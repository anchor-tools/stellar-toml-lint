/**
 * SEP-45 Soroban Web Auth signature verification engine.
 *
 * SEP-10 authenticates a classic `G...` account by verifying signatures on a
 * challenge transaction. SEP-45 extends that to contract accounts — smart
 * wallets and multisig contracts — whose authorization is a Soroban entry that
 * the contract itself verifies on chain, not an ed25519 signature a client can
 * check locally. A challenge that is malformed, that targets the wrong
 * contract, that has already expired, or that reuses a nonce is either
 * unverifiable or replayable, so this engine decodes the challenge, validates
 * its structure and authorization entries against the spec, and can confirm it
 * by simulating the invocation on a Soroban RPC.
 *
 * Every failure is a stable error code from {@link SEP45_ERROR_CODES}, emitted
 * as an ordinary diagnostic so it flows through the same reporters as the rest
 * of the linter.
 */
import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';

/** The function a SEP-45 web auth contract must export. */
export const SEP45_WEB_AUTH_FUNCTION = 'web_auth_verify';

/** Every failure this engine can report, as a stable machine-readable id. */
export const SEP45_ERROR_CODES = {
  /** The XDR is not a transaction envelope at all. */
  MALFORMED_CHALLENGE: 'sep45/malformed-challenge',
  /** The transaction does not carry exactly one invoke operation. */
  NOT_INVOKE_HOST_FUNCTION: 'sep45/not-invoke-host-function',
  /** The host function is not a contract invocation. */
  UNSUPPORTED_HOST_FUNCTION: 'sep45/unsupported-host-function',
  /** The challenge targets a different web auth contract. */
  UNEXPECTED_AUTH_CONTRACT: 'sep45/unexpected-auth-contract',
  /** The invoked function is not `web_auth_verify`. */
  UNEXPECTED_AUTH_FUNCTION: 'sep45/unexpected-auth-function',
  /** The `web_auth_verify` arguments are missing or the wrong shape. */
  MALFORMED_ARGUMENTS: 'sep45/malformed-arguments',
  /** No client authorization entry is present. */
  MISSING_AUTHORIZATION: 'sep45/missing-authorization',
  /** An authorization entry is not a client address-credential invocation. */
  MALFORMED_AUTHORIZATION_ENTRY: 'sep45/malformed-authorization-entry',
  /** A sub-invocation's signature expiration ledger has already passed. */
  EXPIRED_SUB_INVOCATION: 'sep45/expired-sub-invocation',
  /** A client nonce is zero, duplicated, or otherwise out of sequence. */
  INVALID_NONCE_SEQUENCE: 'sep45/invalid-nonce-sequence',
  /** The client signature is not a non-empty byte payload. */
  INVALID_SIGNATURE_STRUCTURE: 'sep45/invalid-signature-structure',
  /** The Soroban RPC rejected the simulated invocation. */
  SIMULATION_FAILED: 'sep45/simulation-failed',
  /** The Soroban RPC could not be reached, so simulation could not run. */
  SIMULATION_UNAVAILABLE: 'sep45/simulation-unavailable',
} as const;

export type Sep45ErrorCode = (typeof SEP45_ERROR_CODES)[keyof typeof SEP45_ERROR_CODES];

/** How long one RPC request may take before the audit gives up on it. */
const RPC_TIMEOUT_MS = 10_000;

/** Bytes a SEP-45 challenge nonce must be: a 32-byte random value. */
const NONCE_BYTES = 32;

/** The default severity of each error code, before rule overrides. */
const DEFAULT_SEVERITIES: Record<Sep45ErrorCode, Severity> = {
  [SEP45_ERROR_CODES.MALFORMED_CHALLENGE]: 'error',
  [SEP45_ERROR_CODES.NOT_INVOKE_HOST_FUNCTION]: 'error',
  [SEP45_ERROR_CODES.UNSUPPORTED_HOST_FUNCTION]: 'error',
  [SEP45_ERROR_CODES.UNEXPECTED_AUTH_CONTRACT]: 'error',
  [SEP45_ERROR_CODES.UNEXPECTED_AUTH_FUNCTION]: 'error',
  [SEP45_ERROR_CODES.MALFORMED_ARGUMENTS]: 'error',
  [SEP45_ERROR_CODES.MISSING_AUTHORIZATION]: 'error',
  [SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY]: 'error',
  [SEP45_ERROR_CODES.EXPIRED_SUB_INVOCATION]: 'error',
  [SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE]: 'error',
  [SEP45_ERROR_CODES.INVALID_SIGNATURE_STRUCTURE]: 'error',
  [SEP45_ERROR_CODES.SIMULATION_FAILED]: 'error',
  [SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]: 'warning',
};

const SEP45_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md';

export interface Sep45AuthOptions {
  /** The web auth contract the challenge is expected to target. */
  webAuthContractId?: string;
  /** The network's current ledger, so expiration ledgers can be judged. */
  latestLedger?: number;
  /** Soroban RPC endpoint; when set, verification simulates the invocation. */
  rpcUrl?: string;
  /** Transport for the RPC call. */
  fetchImpl?: typeof fetch;
  rules?: RuleOverrides;
}

/** The decoded `web_auth_verify` arguments. */
export interface Sep45ChallengeArgs {
  /** The authenticating account: a `G...` address or a `C...` contract. */
  account?: string;
  /** The anchor's home domain. */
  homeDomain?: string;
  /** The anchor's web auth domain. */
  webAuthDomain?: string;
  /** The 32-byte random nonce the server generated. */
  nonce?: Uint8Array;
  /** The optional client domain, for client-domain authentication. */
  clientDomain?: string;
}

/** A decoded SEP-45 challenge transaction. */
export interface Sep45Challenge {
  /** The original XDR, so it can be re-submitted to a simulation. */
  xdr: string;
  /** Number of operations in the transaction. */
  operationCount: number;
  /** The single operation's body type, when there is exactly one. */
  operationType?: string;
  /** The host function's type, when the operation is an invoke. */
  hostFunctionType?: string;
  /** The invoked contract's `C...` id, when it can be read. */
  contractId?: string;
  /** The invoked function name, when it can be read. */
  functionName?: string;
  /** The decoded `web_auth_verify` arguments. */
  args: Sep45ChallengeArgs;
  /** The client authorization entries the operation carries. */
  auth: xdr.SorobanAuthorizationEntry[];
}

export type Sep45ParseResult =
  | { challenge: Sep45Challenge; diagnostic?: undefined }
  | { challenge?: undefined; diagnostic: Diagnostic };

/** The engine's verdict on one challenge. */
export interface Sep45Verification {
  valid: boolean;
  diagnostics: Diagnostic[];
  challenge?: Sep45Challenge;
  /** The raw `simulateTransaction` result, when a simulation ran. */
  simulation?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function severityFor(code: Sep45ErrorCode, rules?: RuleOverrides): Severity | undefined {
  const override = rules?.[code];
  if (override === 'off') return undefined;
  return override ?? DEFAULT_SEVERITIES[code];
}

function finding(
  code: Sep45ErrorCode,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
): Diagnostic[] {
  const severity = severityFor(code, rules);
  if (severity === undefined) return [];
  return [
    {
      rule: code,
      severity,
      category: 'network',
      message,
      helpUri: SEP45_SPEC,
      suggestion,
    },
  ];
}

/** A one-off diagnostic, used before rule overrides can be consulted. */
function parseFailure(message: string, suggestion: string): Diagnostic {
  return {
    rule: SEP45_ERROR_CODES.MALFORMED_CHALLENGE,
    severity: 'error',
    category: 'network',
    message,
    helpUri: SEP45_SPEC,
    suggestion,
  };
}

/**
 * The operations of the transaction an envelope wraps.
 *
 * Fee-bump envelopes are unwrapped to the inner transaction, since the
 * challenge — not its fee sponsor — is what SEP-45 authenticates. An envelope
 * type this build does not know yields no operations, which the validator then
 * reports as a non-invoke challenge.
 */
export function operationsOf(envelope: xdr.TransactionEnvelope): xdr.Operation[] {
  switch (envelope.switch().name) {
    case 'envelopeTypeTx':
      return envelope.v1().tx().operations();
    case 'envelopeTypeTxV0':
      return envelope.v0().tx().operations();
    case 'envelopeTypeTxFeeBump':
      return envelope.feeBump().tx().innerTx().v1().tx().operations();
    default:
      return [];
  }
}

/** The `C...`/`G...` string for an `ScAddress`, or `undefined`. */
function addressOf(address: xdr.ScAddress): string | undefined {
  try {
    return Address.fromScAddress(address).toString();
  } catch {
    return undefined;
  }
}

/** An `ScVal` address as a string, or `undefined` for any other type. */
function scAddressString(val: xdr.ScVal | undefined): string | undefined {
  if (val === undefined || val.switch().name !== 'scvAddress') return undefined;
  return addressOf(val.address());
}

/** An `ScVal` string or symbol as a JS string, or `undefined`. */
function scString(val: xdr.ScVal | undefined): string | undefined {
  if (val === undefined) return undefined;
  if (val.switch().name === 'scvString' || val.switch().name === 'scvSymbol') {
    return val.value()?.toString();
  }
  return undefined;
}

/** An `ScVal` bytes value as a `Uint8Array`, or `undefined`. */
function scBytes(val: xdr.ScVal | undefined): Uint8Array | undefined {
  if (val === undefined || val.switch().name !== 'scvBytes') return undefined;
  return val.bytes();
}

/**
 * Reads the five `web_auth_verify` arguments out of an invocation.
 *
 * Positions are fixed by SEP-45 — account, home domain, web auth domain,
 * nonce, client domain — and an argument of the wrong type simply comes back
 * absent, which {@link validateSep45Challenge} then reports as a malformed
 * argument. Nothing here throws on a surprising shape.
 */
export function decodeSep45Args(values: xdr.ScVal[]): Sep45ChallengeArgs {
  const args: Sep45ChallengeArgs = {};
  const account = scAddressString(values[0]);
  if (account !== undefined) args.account = account;
  const homeDomain = scString(values[1]);
  if (homeDomain !== undefined) args.homeDomain = homeDomain;
  const webAuthDomain = scString(values[2]);
  if (webAuthDomain !== undefined) args.webAuthDomain = webAuthDomain;
  const nonce = scBytes(values[3]);
  if (nonce !== undefined) args.nonce = nonce;
  const clientDomain = scString(values[4]);
  if (clientDomain !== undefined) args.clientDomain = clientDomain;
  return args;
}

/**
 * Parses a base64 (or hex) challenge envelope into its validated-able parts.
 *
 * The parse is deliberately permissive: it decodes whatever envelope it is
 * handed and records the operation and host-function types, so
 * {@link validateSep45Challenge} can report the precise thing that is wrong
 * rather than collapsing every failure into "malformed".
 */
export function parseSep45Challenge(xdrString: string): Sep45ParseResult {
  if (typeof xdrString !== 'string' || xdrString.trim() === '') {
    return {
      diagnostic: parseFailure(
        'SEP-45 challenge is empty',
        'Pass the base64 XDR of the challenge transaction the server returned.',
      ),
    };
  }

  let envelope: xdr.TransactionEnvelope;
  try {
    envelope = xdr.TransactionEnvelope.fromXDR(xdrString.trim(), 'base64');
  } catch (base64Error) {
    try {
      envelope = xdr.TransactionEnvelope.fromXDR(xdrString.trim(), 'hex');
    } catch {
      return {
        diagnostic: parseFailure(
          `SEP-45 challenge is not a valid base64 or hex transaction envelope: ${errorMessage(base64Error)}`,
          'Decode the challenge from the server verbatim; do not trim or re-encode it.',
        ),
      };
    }
  }

  const operations = operationsOf(envelope);
  const challenge: Sep45Challenge = {
    xdr: xdrString.trim(),
    operationCount: operations.length,
    args: {},
    auth: [],
  };

  const operation = operations[0];
  if (operations.length === 1 && operation !== undefined) {
    const body = operation.body();
    challenge.operationType = body.switch().name;

    if (challenge.operationType === 'invokeHostFunction') {
      // The union arm accessor is named after the arm (`invokeHostFunctionOp`),
      // not after the convenience constructor.
      const invoke = body.invokeHostFunctionOp();
      challenge.auth = invoke.auth();
      const hostFunction = invoke.hostFunction();
      challenge.hostFunctionType = hostFunction.switch().name;

      if (challenge.hostFunctionType === 'hostFunctionTypeInvokeContract') {
        const call = hostFunction.invokeContract();
        challenge.functionName = String(call.functionName());
        challenge.contractId = addressOf(call.contractAddress());
        challenge.args = decodeSep45Args(call.args());
      }
    }
  }

  return { challenge };
}

/** True when an `ScVal` holds a non-empty signature payload. */
function isSignatureScVal(val: xdr.ScVal): boolean {
  if (val.switch().name === 'scvBytes') return val.bytes().length > 0;
  if (val.switch().name === 'scvVec') {
    const values = val.vec();
    return (
      values !== null &&
      values.length > 0 &&
      values.every((entry) => entry.switch().name === 'scvBytes' && entry.bytes().length > 0)
    );
  }
  return false;
}

/**
 * Validates a decoded challenge against SEP-45.
 *
 * Checks run outermost-first and stop as soon as a check cannot be answered —
 * there is no point inspecting authorization entries of a transaction that is
 * not an invoke — so a maintainer sees the one thing that is actually wrong.
 */
export function validateSep45Challenge(
  challenge: Sep45Challenge,
  options: Sep45AuthOptions = {},
): Diagnostic[] {
  const rules = options.rules;
  const diagnostics: Diagnostic[] = [];
  const push = (code: Sep45ErrorCode, message: string, suggestion: string): void => {
    diagnostics.push(...finding(code, message, suggestion, rules));
  };

  if (challenge.operationCount !== 1 || challenge.operationType !== 'invokeHostFunction') {
    push(
      SEP45_ERROR_CODES.NOT_INVOKE_HOST_FUNCTION,
      `SEP-45 challenge must contain exactly one invokeHostFunction operation (found ${challenge.operationCount}${
        challenge.operationType === undefined ? '' : `, first is ${challenge.operationType}`
      })`,
      'Build the challenge with a single Operation.invokeHostFunction call.',
    );
    return diagnostics;
  }

  if (challenge.hostFunctionType !== 'hostFunctionTypeInvokeContract') {
    push(
      SEP45_ERROR_CODES.UNSUPPORTED_HOST_FUNCTION,
      `SEP-45 challenge hosts ${challenge.hostFunctionType} rather than a contract invocation`,
      'The challenge must invoke the web auth contract with InvokeContract.',
    );
    return diagnostics;
  }

  if (challenge.functionName !== SEP45_WEB_AUTH_FUNCTION) {
    push(
      SEP45_ERROR_CODES.UNEXPECTED_AUTH_FUNCTION,
      `SEP-45 challenge invokes "${challenge.functionName}", not ${SEP45_WEB_AUTH_FUNCTION}`,
      `Invoke ${SEP45_WEB_AUTH_FUNCTION} on the web auth contract.`,
    );
  }

  if (
    options.webAuthContractId !== undefined &&
    challenge.contractId !== undefined &&
    challenge.contractId !== options.webAuthContractId
  ) {
    push(
      SEP45_ERROR_CODES.UNEXPECTED_AUTH_CONTRACT,
      `SEP-45 challenge targets contract ${challenge.contractId}, not the declared ${options.webAuthContractId}`,
      'Point the challenge at the contract published as WEB_AUTH_CONTRACT_ID.',
    );
  }

  const { args } = challenge;
  if (args.account === undefined) {
    push(
      SEP45_ERROR_CODES.MALFORMED_ARGUMENTS,
      'SEP-45 challenge account argument is missing or is not an address',
      'Pass the authenticating account as the first web_auth_verify argument.',
    );
  }
  if (args.homeDomain === undefined) {
    push(
      SEP45_ERROR_CODES.MALFORMED_ARGUMENTS,
      'SEP-45 challenge home domain argument is missing or is not a string',
      'Pass the anchor home domain as the second web_auth_verify argument.',
    );
  }
  if (args.webAuthDomain === undefined) {
    push(
      SEP45_ERROR_CODES.MALFORMED_ARGUMENTS,
      'SEP-45 challenge web auth domain argument is missing or is not a string',
      'Pass the web auth domain as the third web_auth_verify argument.',
    );
  }
  if (args.nonce === undefined || args.nonce.length !== NONCE_BYTES) {
    push(
      SEP45_ERROR_CODES.MALFORMED_ARGUMENTS,
      `SEP-45 challenge nonce must be ${NONCE_BYTES} random bytes`,
      'Generate the nonce with a cryptographically secure 32-byte random source.',
    );
  }

  if (challenge.auth.length === 0) {
    push(
      SEP45_ERROR_CODES.MISSING_AUTHORIZATION,
      'SEP-45 challenge carries no client authorization entry',
      'Include the client SorobanAuthorizationEntry the server issued for the challenge.',
    );
  }

  const seenNonces = new Set<string>();
  challenge.auth.forEach((entry, index) => {
    const credentials = entry.credentials();
    if (credentials.switch().name !== 'sorobanCredentialsAddress') {
      push(
        SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
        `SEP-45 auth[${index}] uses ${credentials.switch().name} credentials rather than an address credential`,
        'Client authorization entries must carry SorobanCredentialsAddress for the client account.',
      );
      return;
    }

    const address = credentials.address();
    const expiration = address.signatureExpirationLedger();
    if (options.latestLedger !== undefined && expiration <= options.latestLedger) {
      push(
        SEP45_ERROR_CODES.EXPIRED_SUB_INVOCATION,
        `SEP-45 auth[${index}] signature expired at ledger ${expiration}, at or before the latest ledger ${options.latestLedger}`,
        'Request a fresh challenge; the authorization entry can no longer be verified.',
      );
    }

    const nonce = address.nonce().toString();
    if (nonce === '0') {
      push(
        SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE,
        `SEP-45 auth[${index}] nonce is zero, which Soroban hosts reject as a replay risk`,
        'Use the unique non-zero nonce the server generated for this entry.',
      );
    } else if (seenNonces.has(nonce)) {
      push(
        SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE,
        `SEP-45 auth[${index}] repeats nonce ${nonce}, which would make the second invocation replayable`,
        'Give every authorization entry its own nonce.',
      );
    }
    seenNonces.add(nonce);

    if (!isSignatureScVal(address.signature())) {
      push(
        SEP45_ERROR_CODES.INVALID_SIGNATURE_STRUCTURE,
        `SEP-45 auth[${index}] signature is not a non-empty bytes payload`,
        'Sign the challenge payload and submit the signature as ScVal bytes.',
      );
    }

    const root = entry.rootInvocation();
    const fn = root.function();
    if (fn.switch().name !== 'sorobanAuthorizedFunctionTypeContractFn') {
      push(
        SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
        `SEP-45 auth[${index}] root invocation is ${fn.switch().name}, not a contract function`,
        'Authorize a contract function invocation against the web auth contract.',
      );
      return;
    }

    const call = fn.contractFn();
    const invokedFunction = String(call.functionName());
    if (invokedFunction !== SEP45_WEB_AUTH_FUNCTION) {
      push(
        SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
        `SEP-45 auth[${index}] authorizes "${invokedFunction}", not ${SEP45_WEB_AUTH_FUNCTION}`,
        `Authorize ${SEP45_WEB_AUTH_FUNCTION} on the web auth contract.`,
      );
    } else if (
      challenge.contractId !== undefined &&
      addressOf(call.contractAddress()) !== challenge.contractId
    ) {
      push(
        SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
        `SEP-45 auth[${index}] authorizes a different contract than the challenge invokes`,
        'Authorize the same contract the challenge calls.',
      );
    }

    root.subInvocations().forEach((sub, subIndex) => {
      if (sub.function().switch().name !== 'sorobanAuthorizedFunctionTypeContractFn') {
        push(
          SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
          `SEP-45 auth[${index}].subInvocations[${subIndex}] is not a contract function invocation`,
          'A SEP-45 sub-invocation must invoke a contract function the client approved.',
        );
      }
    });
  });

  return diagnostics;
}

/**
 * Confirms a challenge by simulating its invocation against a Soroban RPC.
 *
 * SEP-45's whole point is that the web auth contract — not the linter — decides
 * whether the client's authorization is valid, so the strongest check available
 * is to ask the network to run `web_auth_verify`. A rejected simulation is an
 * error; an unreachable RPC is only a warning, because a network problem is not
 * evidence the challenge is bad.
 */
export async function simulateSep45Challenge(
  challengeXdr: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: Sep45AuthOptions = {},
): Promise<{ diagnostics: Diagnostic[]; result?: unknown }> {
  let response: Response;
  try {
    response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: challengeXdr },
      }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
  } catch (error) {
    return {
      diagnostics: finding(
        SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE,
        `Could not simulate the SEP-45 challenge: ${errorMessage(error)}`,
        'Point --rpc-url at a reachable Soroban RPC for the challenge network.',
        options.rules,
      ),
    };
  }

  if (!response.ok) {
    return {
      diagnostics: finding(
        SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE,
        `Soroban RPC returned HTTP ${response.status} while simulating the SEP-45 challenge`,
        'Confirm the RPC URL serves JSON-RPC and matches the challenge network.',
        options.rules,
      ),
    };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return {
      diagnostics: finding(
        SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE,
        'Soroban RPC returned a body that is not JSON',
        'Confirm the RPC URL serves JSON-RPC and matches the challenge network.',
        options.rules,
      ),
    };
  }

  if (!isRecord(body)) {
    return {
      diagnostics: finding(
        SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE,
        'Soroban RPC returned JSON that is not a JSON-RPC object',
        'Confirm the RPC URL serves JSON-RPC and matches the challenge network.',
        options.rules,
      ),
    };
  }

  const result = body.result;
  // A JSON-RPC level error means the request itself was rejected — a bad
  // method, parameter, or network — before the contract ran.
  if (body.error !== undefined) {
    const detail = isRecord(body.error)
      ? errorMessage(body.error.message ?? body.error)
      : errorMessage(body.error);
    return {
      diagnostics: finding(
        SEP45_ERROR_CODES.SIMULATION_FAILED,
        `Soroban RPC rejected the SEP-45 simulation: ${detail}`,
        'Verify the challenge signature against the web auth contract before submitting it.',
        options.rules,
      ),
      result,
    };
  }

  if (isRecord(result) && result.error !== undefined) {
    return {
      diagnostics: finding(
        SEP45_ERROR_CODES.SIMULATION_FAILED,
        `Soroban RPC rejected the SEP-45 invocation: ${errorMessage(result.error)}`,
        'Verify the challenge signature against the web auth contract before submitting it.',
        options.rules,
      ),
      result,
    };
  }

  return { diagnostics: [], ...(result === undefined ? {} : { result }) };
}

/**
 * Parses, validates, and (when an RPC is configured) simulates a challenge.
 *
 * `valid` is true only when no emitted diagnostic is an error: a warning, like
 * an unreachable RPC, leaves the challenge unproven but not disproven.
 */
export async function verifySep45Challenge(
  challengeXdr: string,
  options: Sep45AuthOptions = {},
): Promise<Sep45Verification> {
  const parsed = parseSep45Challenge(challengeXdr);
  if (parsed.challenge === undefined) {
    return { valid: false, diagnostics: [parsed.diagnostic] };
  }

  const diagnostics = validateSep45Challenge(parsed.challenge, options);

  let simulation: unknown;
  if (options.rpcUrl !== undefined) {
    const simulated = await simulateSep45Challenge(
      parsed.challenge.xdr,
      options.rpcUrl,
      options.fetchImpl ?? fetch,
      options,
    );
    diagnostics.push(...simulated.diagnostics);
    simulation = simulated.result;
  }

  const valid = diagnostics.every((diagnostic) => diagnostic.severity !== 'error');
  return {
    valid,
    diagnostics,
    challenge: parsed.challenge,
    ...(simulation === undefined ? {} : { simulation }),
  };
}

/**
 * The SEP-45 verification engine, bundling the network and contract
 * configuration a caller would otherwise thread through every call.
 */
export class Sep45AuthEngine {
  constructor(private readonly options: Sep45AuthOptions = {}) {}

  parse(challengeXdr: string): Sep45ParseResult {
    return parseSep45Challenge(challengeXdr);
  }

  validate(challenge: Sep45Challenge): Diagnostic[] {
    return validateSep45Challenge(challenge, this.options);
  }

  verify(challengeXdr: string): Promise<Sep45Verification> {
    return verifySep45Challenge(challengeXdr, this.options);
  }

  /** Simulates the challenge when an RPC endpoint is configured, else nothing. */
  async simulate(challengeXdr: string): Promise<Diagnostic[]> {
    if (this.options.rpcUrl === undefined) return [];
    const simulated = await simulateSep45Challenge(
      challengeXdr,
      this.options.rpcUrl,
      this.options.fetchImpl ?? fetch,
      this.options,
    );
    return simulated.diagnostics;
  }
}

/** One-line descriptions, keyed by error code, for `--list-rules`. */
const SEP45_RULE_DESCRIPTIONS: Record<Sep45ErrorCode, string> = {
  [SEP45_ERROR_CODES.MALFORMED_CHALLENGE]:
    'A SEP-45 challenge must be a decodable transaction envelope',
  [SEP45_ERROR_CODES.NOT_INVOKE_HOST_FUNCTION]:
    'A SEP-45 challenge must contain exactly one invoke operation',
  [SEP45_ERROR_CODES.UNSUPPORTED_HOST_FUNCTION]:
    'A SEP-45 challenge must invoke a contract function',
  [SEP45_ERROR_CODES.UNEXPECTED_AUTH_CONTRACT]:
    'A SEP-45 challenge must target the declared web auth contract',
  [SEP45_ERROR_CODES.UNEXPECTED_AUTH_FUNCTION]: 'A SEP-45 challenge must invoke web_auth_verify',
  [SEP45_ERROR_CODES.MALFORMED_ARGUMENTS]:
    'SEP-45 web_auth_verify arguments must have the shape the spec fixes',
  [SEP45_ERROR_CODES.MISSING_AUTHORIZATION]:
    'A SEP-45 challenge must carry the client authorization entry',
  [SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY]:
    'SEP-45 authorization entries must be client contract invocations',
  [SEP45_ERROR_CODES.EXPIRED_SUB_INVOCATION]:
    'A SEP-45 sub-invocation must not outlive its signature expiration ledger',
  [SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE]:
    'SEP-45 authorization nonces must be unique and non-zero',
  [SEP45_ERROR_CODES.INVALID_SIGNATURE_STRUCTURE]:
    'SEP-45 client signatures must be non-empty byte payloads',
  [SEP45_ERROR_CODES.SIMULATION_FAILED]: 'A SEP-45 challenge must simulate successfully on Soroban',
  [SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]:
    'A SEP-45 simulation should be reachable on the configured Soroban RPC',
};

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep45Rules: Rule[] = (Object.values(SEP45_ERROR_CODES) as Sep45ErrorCode[]).map(
  (code) => ({
    id: code,
    category: 'network' as const,
    severity: DEFAULT_SEVERITIES[code],
    description: SEP45_RULE_DESCRIPTIONS[code],
    run() {},
  }),
);

/** Rule ids emitted by this engine. */
export const sep45RuleIds: readonly string[] = sep45Rules.map((rule) => rule.id);
