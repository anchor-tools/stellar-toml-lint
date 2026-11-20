/**
 * Soroban SEP-42 cross-contract authorization call-tree simulator.
 *
 * A Stellar Asset Contract never mints on its own authority: `mint` and
 * `clawback` both run `require_auth`, and under SEP-42 the contract that
 * forwards the call hands the token contract a *delegated* authorization.
 * What comes back from the RPC is an authorization call tree — a
 * `SorobanAuthorizationEntry` whose credentials name the identity that has to
 * sign, and whose root invocation carries the calls that signature covers.
 *
 * A misconfigured tree is how a mint turns into a drain. If the tree also
 * authorizes an unrelated contract, or authorizes an identity the anchor does
 * not control, then the signature the anchor hands to the RPC covers far more
 * than the mint it appears to approve. This module dry-runs the SAC `mint`
 * and `clawback` calls with `simulateTransaction` in recording mode, reads
 * the authorization tree the RPC returns, and reports the trees that widen
 * the authorization beyond the anchor's own key.
 *
 * Nothing is submitted and no fees are spent. The audit runs under the
 * opt-in `--check-network` flag, never throws on an RPC outage, and registers
 * rule objects so `--list-rules` and `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/unauthorized-cross-contract-call` (error)
 * - `soroban/unbounded-auth-grant` (warning)
 */
import {
  Account,
  Address,
  Operation,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';

export const UNAUTHORIZED_CROSS_CONTRACT_RULE = 'soroban/unauthorized-cross-contract-call';
export const UNBOUNDED_AUTH_GRANT_RULE = 'soroban/unbounded-auth-grant';

export const SEP42_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0042.md';

/** Default RPC request timeout in milliseconds. */
export const RPC_TIMEOUT_MS = 10_000;

/** A valid account used as the transaction source when the caller has none. */
export const DEFAULT_SOURCE_ACCOUNT = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/** The token operations the simulator dry-runs. */
export const AUTH_TREE_OPERATIONS = ['mint', 'clawback'] as const;

/** One of the token operations the simulator dry-runs. */
export type AuthTreeOperation = (typeof AUTH_TREE_OPERATIONS)[number];

const NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

/** The amount the simulated `mint`/`clawback` moves. One unit is enough. */
const DEFAULT_SIMULATED_AMOUNT = 1n;

/**
 * The authorization mode the simulation runs in.
 *
 * `record` asks the host to record what the contract asks to be authorized
 * instead of enforcing it, which is the only way the RPC hands back the
 * authorization tree. `enforce`, the default, rejects a transaction whose
 * signatures are not attached.
 */
export const RECORDING_AUTH_MODE = 'record';

/**
 * The function names the host records for an authorization boundary.
 *
 * A `require_auth` boundary is recorded as an invocation of the contract that
 * asked for it, under an internal entry point. Both the internal and the
 * public spelling are accepted because a contract that forwards an
 * authorization explicitly can produce either.
 */
export const AUTH_MARKER_FUNCTIONS: ReadonlySet<string> = new Set([
  'require_auth',
  '__require_auth',
  'require_auth_for_args',
  '__require_auth_for_args',
]);

/**
 * Token functions that move value or change authority.
 *
 * A sub-invocation naming one of these widens the authorization beyond the
 * operation the anchor appears to approve: signing a `mint` that also
 * authorizes a `transfer` is not the same permission.
 */
export const VALUE_MOVING_FUNCTIONS: ReadonlySet<string> = new Set([
  'mint',
  'clawback',
  'burn',
  'burn_from',
  'transfer',
  'transfer_from',
  'set_admin',
  'set_owner',
  'set_authorized',
  'freeze',
  'unfreeze',
  'set_spend_limit',
  'increase_allowance',
  'decrease_allowance',
]);

export interface AuthTreeOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** Network passphrase used to build the invocation envelope. */
  networkPassphrase?: string;
  /** Source account for the simulated envelope. */
  sourceAccount?: string;
  /** Amount passed to `mint`/`clawback` in the simulated call. */
  amount?: bigint;
  /** Operations to simulate. Defaults to `mint`, plus `clawback` when enabled. */
  operations?: readonly AuthTreeOperation[];
  /** Extra addresses that may be authorized at the root of the tree. */
  authorizedIdentities?: readonly string[];
  /** Extra contracts the tree may delegate into. */
  allowedContracts?: readonly string[];
}

/**
 * One node of the authorization call tree.
 *
 * A node is either an authorization boundary (a `require_auth` the contract
 * asked for) or an ordinary contract call.
 */
export interface AuthTreeNode {
  /** Contract the invocation targets, when the node names one. */
  contract?: string;
  /** Function the invocation names, when the node names one. */
  function?: string;
  /** Addresses the boundary asks to be authorized. */
  addresses: string[];
  /** True when the node is an authorization boundary rather than a call. */
  authBoundary: boolean;
  /** Nested invocations. */
  children: AuthTreeNode[];
}

/** One `SorobanAuthorizationEntry`, read as a tree. */
export interface AuthTreeEntry {
  /** Address the credentials name, when they name one. */
  credentialAddress?: string;
  /** True when the transaction source account authorizes the entry. */
  sourceAccount: boolean;
  /** Root invocation of the entry. */
  root: AuthTreeNode;
  /** Every address the tree asks to be authorized. */
  requiredAddresses: string[];
}

/** One problem found in an authorization call tree. */
export interface AuthTreeFinding {
  rule: string;
  severity: 'error' | 'warning';
  message: string;
  suggestion?: string;
}

/** What the analyzer compares the tree against. */
export interface AuthTreeContext {
  /** Addresses the anchor controls and may be authorized at the root. */
  authorizedIdentities: readonly string[];
  /** Contracts the tree may delegate into. */
  allowedContracts: readonly string[];
  /** Account that signed the simulated envelope. */
  sourceAccount?: string;
}

/**
 * The canonical spelling of an address.
 *
 * A muxed account is folded onto the account it wraps, because a Soroban
 * `SCAddress` only ever carries the underlying account. Anything that is not
 * an address returns `undefined` and is simply not recognized.
 */
export function canonicalIdentity(value: string): string | undefined {
  try {
    const rendered = Address.fromString(value).toString();
    if (StrKey.isValidEd25519PublicKey(rendered)) {
      return StrKey.encodeEd25519PublicKey(StrKey.decodeEd25519PublicKey(rendered));
    }
    if (StrKey.isValidMed25519PublicKey(rendered)) {
      return StrKey.encodeEd25519PublicKey(StrKey.decodeMed25519PublicKey(rendered));
    }
    return rendered;
  } catch {
    return undefined;
  }
}

/** The `SCAddress` of an address, or `undefined` when it is not one. */
function scAddressOf(value: string | undefined): xdr.ScAddress | undefined {
  if (value === undefined) return undefined;
  try {
    return new Address(value).toScAddress();
  } catch {
    return undefined;
  }
}

/** The canonical form of an `SCAddress`, or `undefined`. */
function scAddressToString(scAddress: xdr.ScAddress): string | undefined {
  try {
    return Address.fromScAddress(scAddress).toString();
  } catch {
    return undefined;
  }
}

/** Every address argument of a call, in order. */
function scValAddresses(args: xdr.ScVal[]): string[] {
  const found: string[] = [];
  for (const arg of args) {
    if (arg.switch().name !== 'scvAddress') continue;
    const address = scAddressToString(arg.address());
    if (address !== undefined) found.push(address);
  }
  return found;
}

/** Reads one invocation of the tree. */
function parseInvocation(invocation: xdr.SorobanAuthorizedInvocation): AuthTreeNode {
  const fn = invocation.function();
  let contract: string | undefined;
  let fnName: string | undefined;
  let args: xdr.ScVal[] = [];

  if (fn.switch().name === 'sorobanAuthorizedFunctionTypeContractFn') {
    const call = fn.contractFn();
    contract = scAddressToString(call.contractAddress());
    fnName = call.functionName().toString();
    args = call.args();
  }

  const authBoundary = fnName !== undefined && AUTH_MARKER_FUNCTIONS.has(fnName);
  return {
    ...(contract !== undefined ? { contract } : {}),
    ...(fnName !== undefined ? { function: fnName } : {}),
    // Only a boundary names the address it authorizes. A `mint(to, amount)`
    // call carries a recipient, which is not a permission.
    addresses: authBoundary ? scValAddresses(args) : [],
    authBoundary,
    children: invocation.subInvocations().map(parseInvocation),
  };
}

/** Every address the tree asks to be authorized. */
function collectRequiredAddresses(node: AuthTreeNode, into: string[] = []): string[] {
  if (node.authBoundary) into.push(...node.addresses);
  for (const child of node.children) collectRequiredAddresses(child, into);
  return into;
}

/**
 * Reads one `SorobanAuthorizationEntry` as an authorization call tree.
 *
 * The entry's credentials name the identity that has to sign for the root
 * invocation; the root invocation's sub-invocations name everything else the
 * same signature covers.
 */
export function parseAuthEntry(entry: xdr.SorobanAuthorizationEntry): AuthTreeEntry {
  const credentials = entry.credentials();
  const sourceAccount = credentials.switch().name === 'sorobanCredentialsSourceAccount';
  const credentialAddress = sourceAccount
    ? undefined
    : scAddressToString(credentials.address().address());

  const root = parseInvocation(entry.rootInvocation());
  const requiredAddresses = collectRequiredAddresses(root);

  return {
    ...(credentialAddress !== undefined ? { credentialAddress } : {}),
    sourceAccount,
    root,
    requiredAddresses,
  };
}

/**
 * Reads the recorded authorization entries out of a `simulateTransaction`
 * response.
 *
 * Newer RPCs nest them under the host function result (`results[].auth`);
 * older ones put them at the top level of the result (`auth`). Each item is
 * a base64 `SorobanAuthorizationEntry`, and one that cannot be decoded is
 * skipped rather than guessed at.
 */
export function parseAuthEntries(raw: unknown): AuthTreeEntry[] {
  if (!Array.isArray(raw)) return [];
  const entries: AuthTreeEntry[] = [];
  for (const item of raw) {
    if (!isString(item)) continue;
    try {
      entries.push(parseAuthEntry(xdr.SorobanAuthorizationEntry.fromXDR(item, 'base64')));
    } catch {
      // An entry that cannot be decoded says nothing about the tree.
    }
  }
  return entries;
}

/** Where the RPC keeps the recorded authorization entries. */
function authEntriesOf(result: Record<string, unknown>): unknown {
  const results = result.results;
  if (Array.isArray(results)) {
    for (const item of results) {
      if (typeof item !== 'object' || item === null) continue;
      const auth = (item as Record<string, unknown>).auth;
      if (Array.isArray(auth)) return auth;
    }
  }
  return result.auth;
}

/**
 * Builds the base64 `TransactionEnvelope` for an `InvokeHostFunctionOp`
 * calling `operation` on `contractId`.
 *
 * The transaction is never signed or submitted; it exists so
 * `simulateTransaction` can dry-run it and report the authorization tree the
 * contract would demand.
 */
export function buildAuthTreeTransaction(
  contractId: string,
  operation: AuthTreeOperation,
  recipient: string,
  options: AuthTreeOptions = {},
): string {
  const source = options.sourceAccount ?? DEFAULT_SOURCE_ACCOUNT;
  const contract = scAddressOf(contractId);
  const target = scAddressOf(recipient) ?? scAddressOf(source);
  if (contract === undefined || target === undefined) return '';

  const amount = options.amount ?? DEFAULT_SIMULATED_AMOUNT;

  try {
    const hostFunction = xdr.HostFunction.hostFunctionTypeInvokeContract(
      new xdr.InvokeContractArgs({
        contractAddress: contract,
        functionName: operation,
        args: [xdr.ScVal.scvAddress(target), nativeToScVal(amount, { type: 'i128' })],
      }),
    );

    const transaction = new TransactionBuilder(new Account(source, '0'), {
      fee: '100',
      networkPassphrase: options.networkPassphrase ?? NETWORK_PASSPHRASE,
    })
      .addOperation(Operation.invokeHostFunction({ func: hostFunction, auth: [] }))
      .setTimeout(30)
      .build();

    return transaction.toEnvelope().toXDR('base64');
  } catch {
    // An envelope that cannot be built is not a finding; the caller stays
    // silent rather than failing the run.
    return '';
  }
}

/** A readable name for an invocation of the tree. */
function nodeLabel(node: AuthTreeNode): string {
  const fn = node.function ?? 'invocation';
  return node.contract !== undefined ? `${node.contract}.${fn}` : fn;
}

/** The wording used for an identity the anchor does not publish. */
const UNRECOGNIZED_IDENTITY =
  'which is neither the anchor SIGNING_KEY, a designated issuer, nor a contract the file declares';

/** True when the address belongs to the anchor. */
function isRecognized(
  address: string,
  authorized: ReadonlySet<string>,
  allowedContracts: ReadonlySet<string>,
): boolean {
  const canonical = canonicalIdentity(address);
  if (canonical === undefined) return false;
  return authorized.has(canonical) || allowedContracts.has(canonical);
}

/**
 * The invocation the tree actually authorizes.
 *
 * The host records the call that has to be authorized as the root of the
 * tree. Some hosts record the `require_auth` boundary itself as the root
 * instead, with the call underneath it, so the first call that is not a
 * boundary is the one being authorized.
 */
function authorizedCall(root: AuthTreeNode): AuthTreeNode {
  if (!root.authBoundary) return root;
  const queue: AuthTreeNode[] = [...root.children];
  while (queue.length > 0) {
    const node = queue.shift();
    if (node === undefined) break;
    if (!node.authBoundary) return node;
    queue.unshift(...node.children);
  }
  return root;
}

/** Visits every node of the tree, root first. */
function walkNodes(node: AuthTreeNode, visit: (node: AuthTreeNode) => void): void {
  const step = (current: AuthTreeNode): void => {
    visit(current);
    for (const child of current.children) step(child);
  };
  step(node);
}

/**
 * Inspects an authorization call tree.
 *
 * Three things are wrong in a tree that can be exploited:
 *
 * 1. It authorizes an identity the anchor does not control — the identity
 *    behind the root invocation, or an address a `require_auth` boundary
 *    names.
 * 2. It delegates into a contract the operation did not call, or widens the
 *    operation into a second value-moving call on the same contract.
 * 3. It grants authorization without an address boundary, so the grant
 *    covers more than a single account or contract.
 */
export function analyzeAuthTree(
  entries: readonly AuthTreeEntry[],
  context: AuthTreeContext,
): AuthTreeFinding[] {
  const findings: AuthTreeFinding[] = [];
  const authorized = new Set(
    context.authorizedIdentities
      .map(canonicalIdentity)
      .filter((value): value is string => value !== undefined),
  );
  const allowedContracts = new Set(
    context.allowedContracts
      .map(canonicalIdentity)
      .filter((value): value is string => value !== undefined),
  );
  // With nothing to compare against, the tree cannot be judged.
  const canVerifyIdentity = authorized.size > 0 || allowedContracts.size > 0;

  for (const entry of entries) {
    const root = entry.root;
    const call = authorizedCall(root);
    const label = nodeLabel(call);

    // 1. The identity behind the root invocation.
    const rootIdentity =
      entry.credentialAddress ?? (entry.sourceAccount ? context.sourceAccount : undefined);
    if (canVerifyIdentity && rootIdentity !== undefined) {
      if (!isRecognized(rootIdentity, authorized, allowedContracts)) {
        findings.push({
          rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
          severity: 'error',
          message: `The ${label} authorization tree is authorized by ${rootIdentity}, ${UNRECOGNIZED_IDENTITY}`,
          suggestion:
            'Point the token contract at the account the file publishes as SIGNING_KEY, or declare the issuer that is allowed to mint.',
        });
      }
    }

    // 2. Every address a boundary asks to be authorized.
    if (canVerifyIdentity) {
      for (const address of entry.requiredAddresses) {
        if (isRecognized(address, authorized, allowedContracts)) continue;
        findings.push({
          rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
          severity: 'error',
          message: `The ${label} authorization tree requires authorization from ${address}, ${UNRECOGNIZED_IDENTITY}`,
          suggestion:
            'Authorize the account the file publishes as SIGNING_KEY, or the issuer declared for the asset.',
        });
      }
    }

    // 3. The sub-invocations the grant reaches.
    walkNodes(root, (node) => {
      if (node === root) return;

      if (node.authBoundary) {
        if (node.addresses.length === 0) {
          findings.push({
            rule: UNBOUNDED_AUTH_GRANT_RULE,
            severity: 'warning',
            message: `The ${label} authorization tree contains an authorization boundary that names no address, so the grant is not bounded to one account or contract`,
            suggestion:
              'Authorize a specific address with require_auth(address) so the grant cannot be replayed against another one.',
          });
        }
        for (const address of node.addresses) {
          if (node.contract === undefined) continue;
          if (canonicalIdentity(address) !== canonicalIdentity(node.contract)) continue;
          findings.push({
            rule: UNBOUNDED_AUTH_GRANT_RULE,
            severity: 'warning',
            message: `The ${label} authorization tree lets ${node.contract} authorize itself, so the grant covers every entry point of that contract`,
            suggestion:
              'Authorize a dedicated issuer account instead of the token contract itself.',
          });
        }
        if (node.children.some((child) => child.authBoundary)) {
          findings.push({
            rule: UNBOUNDED_AUTH_GRANT_RULE,
            severity: 'warning',
            message: `The ${label} authorization tree re-delegates authorization inside another authorization boundary, so the grant is not bounded to a single address`,
            suggestion: 'Flatten the delegation so one authorization covers one address.',
          });
        }
        return;
      }

      if (node === call) return;

      if (node.contract !== undefined && node.contract !== call.contract) {
        const declared = allowedContracts.has(canonicalIdentity(node.contract) ?? '');
        findings.push({
          rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
          severity: 'error',
          message: `The ${label} authorization tree delegates to ${nodeLabel(node)}${declared ? ', a contract the file declares but the operation did not call' : ', a contract the file does not declare'}`,
          suggestion:
            'Keep the mint or clawback authorization inside the token contract, or declare and approve the contract the call reaches.',
        });
        return;
      }

      if (
        node.function !== undefined &&
        node.function !== call.function &&
        VALUE_MOVING_FUNCTIONS.has(node.function)
      ) {
        findings.push({
          rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
          severity: 'error',
          message: `The ${label} authorization tree also authorizes ${node.function}() on ${node.contract ?? 'the token contract'}, widening the signature beyond the ${call.function ?? 'requested'} operation`,
          suggestion:
            'Sign the mint or clawback authorization on its own, without a second value-moving call inside the same tree.',
        });
      }
    });

    // 4. A contract that authorizes its own mint.
    if (
      entry.credentialAddress !== undefined &&
      call.contract !== undefined &&
      canonicalIdentity(entry.credentialAddress) === canonicalIdentity(call.contract)
    ) {
      findings.push({
        rule: UNBOUNDED_AUTH_GRANT_RULE,
        severity: 'warning',
        message: `The ${label} authorization tree is signed by the token contract itself, so the contract can authorize its own mint and clawback calls`,
        suggestion:
          'Keep the token contract administrator on a dedicated account the file publishes.',
      });
    }
  }

  return findings;
}

/** POSTs one `simulateTransaction`. `undefined` means the RPC could not answer. */
async function simulateAuthEntries(
  rpcUrl: string,
  envelope: string,
  fetchImpl: typeof fetch,
): Promise<AuthTreeEntry[] | undefined> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: envelope, authMode: RECORDING_AUTH_MODE },
      }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) return undefined;

    const body = (await response.json()) as { result?: Record<string, unknown> };
    const result = body.result;
    if (typeof result !== 'object' || result === null) return undefined;
    return parseAuthEntries(authEntriesOf(result));
  } catch {
    return undefined;
  }
}

/** Turns a finding into a diagnostic, honouring the caller's severity overrides. */
function toDiagnostic(finding: AuthTreeFinding, options: AuthTreeOptions): Diagnostic | undefined {
  const severity = severityFor(finding.rule, finding.severity, options.rules);
  if (severity === undefined) return undefined;
  return {
    rule: finding.rule,
    severity,
    category: 'network',
    message: finding.message,
    ...(options.path !== undefined ? { path: options.path } : {}),
    helpUri: SEP42_SPEC_URL,
    ...(finding.suggestion !== undefined ? { suggestion: finding.suggestion } : {}),
  };
}

/**
 * Dry-runs one token operation and reports what its authorization tree
 * authorizes.
 *
 * Silent when the RPC does not answer or the simulation produces no
 * authorization tree: there is nothing to inspect, and an outage is not a
 * finding.
 */
export async function simulateAuthTree(
  contractId: string,
  operation: AuthTreeOperation,
  recipient: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: AuthTreeOptions = {},
): Promise<Diagnostic[]> {
  const envelope = buildAuthTreeTransaction(contractId, operation, recipient, options);
  if (envelope === '') return [];

  const entries = await simulateAuthEntries(rpcUrl, envelope, fetchImpl);
  if (entries === undefined || entries.length === 0) return [];

  const findings = analyzeAuthTree(entries, {
    authorizedIdentities: options.authorizedIdentities ?? [],
    allowedContracts: options.allowedContracts ?? [contractId],
    ...(options.sourceAccount !== undefined ? { sourceAccount: options.sourceAccount } : {}),
  });

  const diagnostics: Diagnostic[] = [];
  for (const finding of findings) {
    const diagnostic = toDiagnostic(finding, options);
    if (diagnostic !== undefined) diagnostics.push(diagnostic);
  }
  return diagnostics;
}

/** The `SIGNING_KEY` the file publishes, when it names one. */
function signingKeyOf(doc: Record<string, unknown>): string | undefined {
  const key = doc.SIGNING_KEY;
  if (!isString(key)) return undefined;
  const trimmed = key.trim();
  return trimmed === '' ? undefined : trimmed;
}

/**
 * The accounts the anchor controls: the key it publishes and the issuer it
 * designates for each asset.
 */
export function authorizedIdentitiesOf(
  doc: Record<string, unknown>,
  options: AuthTreeOptions = {},
): string[] {
  const identities: string[] = [];
  const signingKey = signingKeyOf(doc);
  if (signingKey !== undefined) identities.push(signingKey);

  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    for (const currency of currencies) {
      if (typeof currency !== 'object' || currency === null) continue;
      const issuer = (currency as Record<string, unknown>).issuer;
      if (!isString(issuer)) continue;
      const trimmed = issuer.trim();
      if (trimmed !== '') identities.push(trimmed);
    }
  }

  identities.push(...(options.authorizedIdentities ?? []));
  return identities;
}

/** The contracts the file declares, which the tree may legitimately reach. */
export function allowedContractsOf(
  doc: Record<string, unknown>,
  options: AuthTreeOptions = {},
): string[] {
  const contracts = contractCurrenciesOf(doc).map((currency) => currency.id);
  const webAuth = doc.WEB_AUTH_CONTRACT_ID;
  if (isString(webAuth) && webAuth.trim() !== '') contracts.push(webAuth.trim());
  contracts.push(...(options.allowedContracts ?? []));
  return contracts;
}

/** The operations a currency entry is audited for. */
function operationsOf(entry: Record<string, unknown>): AuthTreeOperation[] {
  const operations: AuthTreeOperation[] = ['mint'];
  if (entry.clawback_enabled === true) operations.push('clawback');
  return operations;
}

/**
 * Simulates the mint and clawback of every contract the file declares under
 * `[[CURRENCIES]]` and reports the authorization trees that widen the
 * permission beyond the anchor's own key.
 */
export async function auditTomlAuthTree(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuthTreeOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const sourceAccount = options.sourceAccount ?? signingKeyOf(doc) ?? DEFAULT_SOURCE_ACCOUNT;
  const authorizedIdentities = authorizedIdentitiesOf(doc, options);
  const allowedContracts = allowedContractsOf(doc, options);

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    const operations = options.operations ?? operationsOf(currency.entry);
    const recipient = authorizedIdentities[0] ?? sourceAccount;
    for (const operation of operations) {
      diagnostics.push(
        ...(await simulateAuthTree(currency.id, operation, recipient, rpcUrl, fetchImpl, {
          ...options,
          authorizedIdentities,
          allowedContracts,
          sourceAccount,
          path: currency.path,
          networkPassphrase: options.networkPassphrase ?? passphrase,
        })),
      );
    }
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const authTreeSimulatorRules: Rule[] = [
  {
    id: UNAUTHORIZED_CROSS_CONTRACT_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban authorization call tree authorizes an identity or a cross-contract call the anchor did not approve (SEP-42)',
    run() {},
  },
  {
    id: UNBOUNDED_AUTH_GRANT_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban authorization call tree grants authorization without an address boundary (SEP-42)',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlAuthTree}. */
export const authTreeSimulatorRuleIds: readonly string[] = authTreeSimulatorRules.map(
  (rule) => rule.id,
);
