/**
 * SEP-10 network passphrase isolation auditor.
 *
 * Runs under `stellar-toml-lint audit-sep10-isolation --domain <domain>`.
 *
 * A SEP-10 challenge is a Stellar transaction, and a transaction is only valid
 * on the network whose passphrase was hashed into its signing hash. An anchor
 * that serves both Testnet and Mainnet must therefore verify the client's
 * signature against the passphrase of the endpoint that issued the challenge.
 * A server that parses the envelope against the wrong passphrase — or accepts
 * whichever passphrase happens to validate the signature — lets an attacker
 * authenticate with a keypair that only ever existed on Testnet.
 *
 * The audit walks the handshake against the live endpoint:
 *   1. GET /auth?account=<client> to fetch the challenge.
 *   2. Verify the challenge commits to the target network by checking the
 *      server's signature against the target passphrase hash.
 *   3. Re-sign the same challenge under the alternate passphrase and POST it
 *      back; a correct server answers 400 with a descriptive error.
 *
 * Secret keys never leave this module: probes and reports carry public keys
 * only, so a CI log cannot leak a signing seed.
 */

import { Keypair, Networks, TransactionBuilder } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { isRecord, severityFor } from './verifierSupport.js';

const CHALLENGE_MALFORMED_RULE = 'sep10/isolation-challenge-malformed';
const CHALLENGE_MISMATCH_RULE = 'sep10/isolation-challenge-network-mismatch';
const SIGNATURE_INVALID_RULE = 'sep10/isolation-challenge-signature-invalid';
const CROSS_NETWORK_ACCEPTED_RULE = 'sep10/isolation-cross-network-accepted';
const CROSS_NETWORK_STATUS_RULE = 'sep10/isolation-cross-network-bad-status';
const MISSING_ERROR_CODE_RULE = 'sep10/isolation-missing-error-code';
const PROBE_FAILED_RULE = 'sep10/isolation-probe-failed';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md';
const CATEGORY: RuleCategory = 'network';

/** Networks the auditor understands, keyed by the CLI's `--network` values. */
export const NETWORK_PASSPHRASES = {
  public: Networks.PUBLIC,
  testnet: Networks.TESTNET,
} as const;

export type StellarNetwork = keyof typeof NETWORK_PASSPHRASES;

/** HTTP status SEP-10 servers must use for an invalid challenge response. */
export const CROSS_NETWORK_REJECTION_STATUS = 400;

/**
 * Passphrase that must never validate a signature a correct server accepts on
 * the target network: the other network's passphrase.
 */
export function alternatePassphraseFor(network: StellarNetwork): string {
  return network === 'public' ? NETWORK_PASSPHRASES.testnet : NETWORK_PASSPHRASES.public;
}

export function passphraseFor(network: StellarNetwork): string {
  return NETWORK_PASSPHRASES[network];
}

/** Infers the target network from a `stellar.toml` NETWORK_PASSPHRASE. */
export function networkFromPassphrase(passphrase: string): StellarNetwork | undefined {
  const value = passphrase.trim();
  if (value === NETWORK_PASSPHRASES.public) return 'public';
  if (value === NETWORK_PASSPHRASES.testnet) return 'testnet';
  return undefined;
}

/** Reads the passphrase advertised by a parsed `stellar.toml`. */
export function networkFromDocument(doc: Record<string, unknown>): StellarNetwork | undefined {
  const value = doc.NETWORK_PASSPHRASE;
  return typeof value === 'string' ? networkFromPassphrase(value) : undefined;
}

export interface Sep10IsolationOptions {
  rules?: RuleOverrides;
  /** Target network; defaults to `public`. */
  network?: StellarNetwork;
  /**
   * Client keypair used to answer the challenge. Defaults to a throwaway random
   * keypair — the audit never needs a funded account, only a valid signer.
   */
  clientKeypair?: Keypair;
  /** SEP-10 endpoint; discovered from `stellar.toml` when omitted. */
  webAuthEndpoint?: string;
  /** Home domain sent with the challenge request. */
  homeDomain?: string;
  timeoutMs?: number;
}

/** What happened when a cross-network challenge was submitted. */
export interface CrossNetworkProbe {
  /** Passphrase the response was signed under. */
  passphrase: string;
  status?: number;
  /** Server-supplied error string / code, when it returned one. */
  error?: string;
  /** True when the server returned a token instead of an error. */
  accepted: boolean;
  /** True when the server rejected with 400 and a descriptive error. */
  rejectedStrictly: boolean;
}

/** Public-only account and challenge details, safe to print. */
export interface IsolationChallenge {
  /** Public key of the mock client account. */
  account: string;
  /** Public key of the server signing key (challenge source account). */
  serverAccount?: string;
  /** Base64 envelope used for the cross-network probe. */
  xdr: string;
  /** True when the server signature validates under the target passphrase. */
  networkBound: boolean;
  /** Passphrase whose hash validates the server signature, if discoverable. */
  observedPassphrase?: string;
}

export interface Sep10IsolationReport {
  domain: string;
  endpoint: string;
  network: StellarNetwork;
  expectedPassphrase: string;
  alternatePassphrase: string;
  challenge?: IsolationChallenge;
  probe?: CrossNetworkProbe;
  /** True only when the challenge is network-bound and the probe was rejected. */
  ok: boolean;
  findings: { code: string; severity: Severity; message: string }[];
}

export interface Sep10IsolationResult {
  report: Sep10IsolationReport;
  diagnostics: Diagnostic[];
}

function diagnostic(
  code: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  path = 'WEB_AUTH_ENDPOINT',
): Diagnostic[] {
  const severity = severityFor(code, fallback, rules);
  if (severity === undefined) return [];
  return [{ rule: code, severity, category: CATEGORY, message, path, helpUri: SPEC, suggestion }];
}

interface ParsedChallenge {
  source: string;
  account?: string;
  hash: Buffer;
  validSignatures: string[];
}

/**
 * Parses a challenge envelope with `passphrase` and reports which signers
 * produced a signature valid for the hash that passphrase implies.
 *
 * Parsing alone proves nothing: `fromXDR` accepts any envelope and simply
 * attaches the passphrase. The hash check below is the real network assertion.
 */
export function inspectChallenge(xdr: string, passphrase: string): ParsedChallenge | undefined {
  let tx: ReturnType<typeof TransactionBuilder.fromXDR>;
  try {
    tx = TransactionBuilder.fromXDR(xdr, passphrase);
  } catch {
    return undefined;
  }
  if ('innerTransaction' in tx) return undefined;

  // A standard transaction always has a hash; fee bumps were rejected above.
  const hash = tx.hash();

  const operations = tx.operations as { type?: string; source?: string }[];
  const account = operations.find(
    (op) => op.type === 'manageData' && typeof op.source === 'string' && op.source !== tx.source,
  )?.source;

  const validSignatures: string[] = [];
  for (const decorated of tx.signatures) {
    const hint = decorated.hint();
    const signature = decorated.signature();
    for (const candidate of [tx.source, ...(account === undefined ? [] : [account])]) {
      if (validSignatures.includes(candidate)) continue;
      // Account ids in a parsed envelope are validated ed25519 public keys.
      const keypair = Keypair.fromPublicKey(candidate);
      if (!keypair.signatureHint().equals(hint)) continue;
      if (keypair.verify(hash, signature)) validSignatures.push(candidate);
    }
  }

  return {
    source: tx.source,
    ...(account === undefined ? {} : { account }),
    hash,
    validSignatures,
  };
}

/** Signs an existing envelope with `keypair` under `passphrase`. */
export function signUnderPassphrase(xdr: string, passphrase: string, keypair: Keypair): string {
  const tx = TransactionBuilder.fromXDR(xdr, passphrase);
  if ('innerTransaction' in tx) throw new Error('fee-bump challenges are not supported');
  tx.sign(keypair);
  return tx.toXDR();
}

async function readError(response: Response): Promise<string | undefined> {
  // Read the body once: a failed `json()` still consumes it, so JSON and plain
  // text replies have to be distinguished after the read, not by retrying.
  let text: string;
  try {
    text = (await response.text()).trim();
  } catch {
    return undefined;
  }
  if (text === '') return undefined;
  try {
    const body: unknown = JSON.parse(text);
    if (!isRecord(body)) return undefined;
    for (const key of ['error', 'code', 'message']) {
      const value = body[key];
      if (typeof value === 'string' && value.trim() !== '') return value;
    }
    return undefined;
  } catch {
    // Plain-text error body, which some SEP-10 servers still send.
    return text.slice(0, 200);
  }
}

/**
 * Audits one anchor for network passphrase isolation.
 *
 * The passed `domain` is only used for reporting; the endpoint comes from
 * `options.webAuthEndpoint` or the supplied `stellar.toml` document.
 */
export class Sep10NetworkIsolationAuditor {
  private readonly fetchImpl: typeof fetch;
  private readonly options: Sep10IsolationOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: Sep10IsolationOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  async audit(doc: Record<string, unknown>, domain: string): Promise<Sep10IsolationResult> {
    const network = this.options.network ?? networkFromDocument(doc) ?? 'public';
    const expectedPassphrase = passphraseFor(network);
    const alternatePassphrase = alternatePassphraseFor(network);
    const endpoint =
      this.options.webAuthEndpoint ??
      (typeof doc.WEB_AUTH_ENDPOINT === 'string' ? doc.WEB_AUTH_ENDPOINT : undefined) ??
      `https://${domain}/auth`;
    const client = this.options.clientKeypair ?? Keypair.random();

    const report: Sep10IsolationReport = {
      domain,
      endpoint,
      network,
      expectedPassphrase,
      alternatePassphrase,
      ok: false,
      findings: [],
    };
    const diagnostics: Diagnostic[] = [];
    const add = (d: Diagnostic[]): void => {
      diagnostics.push(...d);
      for (const item of d) {
        report.findings.push({
          code: item.rule,
          severity: item.severity,
          message: item.message,
        });
      }
    };

    const url = new URL(endpoint);
    url.searchParams.set('account', client.publicKey());
    const homeDomain = this.options.homeDomain ?? domain;
    if (homeDomain !== '') url.searchParams.set('home_domain', homeDomain);

    let challengeXdr: string;
    try {
      const response = await this.fetchImpl(url.toString(), {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 10_000),
      });
      if (!response.ok) {
        add(
          diagnostic(
            PROBE_FAILED_RULE,
            'warning',
            `GET /auth returned HTTP ${response.status}, so network isolation could not be probed`,
            'Confirm WEB_AUTH_ENDPOINT answers SEP-10 challenge requests.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      const body: unknown = await response.json();
      const transaction =
        isRecord(body) && typeof body.transaction === 'string' ? body.transaction : undefined;
      if (transaction === undefined) {
        add(
          diagnostic(
            PROBE_FAILED_RULE,
            'warning',
            'GET /auth response carried no `transaction` envelope',
            'Confirm WEB_AUTH_ENDPOINT answers the SEP-10 challenge schema.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      challengeXdr = transaction;
    } catch (error) {
      add(
        diagnostic(
          PROBE_FAILED_RULE,
          'warning',
          `GET /auth failed: ${error instanceof Error ? error.message : String(error)}`,
          'Confirm WEB_AUTH_ENDPOINT is reachable from the audit host.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const expected = inspectChallenge(challengeXdr, expectedPassphrase);
    if (expected === undefined) {
      add(
        diagnostic(
          CHALLENGE_MALFORMED_RULE,
          'error',
          'The challenge envelope could not be parsed as a Stellar transaction',
          'Return a base64-encoded SEP-10 challenge transaction in `transaction`.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    // Which passphrase does the server's own signature actually commit to?
    const alternate = inspectChallenge(challengeXdr, alternatePassphrase);
    const observedPassphrase = expected.validSignatures.includes(expected.source)
      ? expectedPassphrase
      : alternate?.validSignatures.includes(expected.source)
        ? alternatePassphrase
        : undefined;
    const networkBound = observedPassphrase === expectedPassphrase;

    const challenge: IsolationChallenge = {
      account: client.publicKey(),
      serverAccount: expected.source,
      xdr: challengeXdr,
      networkBound,
      ...(observedPassphrase === undefined ? {} : { observedPassphrase }),
    };
    report.challenge = challenge;

    if (!networkBound && observedPassphrase !== undefined) {
      add(
        diagnostic(
          CHALLENGE_MISMATCH_RULE,
          'error',
          `The challenge is signed for ${observedPassphrase} but the endpoint serves ${expectedPassphrase}`,
          'Verify the endpoint hashes the target network passphrase into the challenge hash.',
          this.options.rules,
        ),
      );
    } else if (expected.validSignatures.length === 0) {
      add(
        diagnostic(
          SIGNATURE_INVALID_RULE,
          'error',
          'No signature on the challenge validates against the target network passphrase',
          'Sign the challenge transaction with the network passphrase this endpoint serves.',
          this.options.rules,
        ),
      );
    }

    // Safe after {@link inspectChallenge}: the envelope parsed as a standard
    // transaction, so re-parsing here under the alternate passphrase cannot
    // hit the fee-bump path that `signUnderPassphrase` rejects.
    const probeXdr = signUnderPassphrase(challengeXdr, alternatePassphrase, client);

    try {
      const response = await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ transaction: probeXdr }),
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 10_000),
      });
      const error = await readError(response);
      const accepted = response.ok;
      const probe: CrossNetworkProbe = {
        passphrase: alternatePassphrase,
        status: response.status,
        ...(error === undefined ? {} : { error }),
        accepted,
        rejectedStrictly:
          response.status === CROSS_NETWORK_REJECTION_STATUS &&
          error !== undefined &&
          error.trim() !== '',
      };
      report.probe = probe;

      if (accepted) {
        add(
          diagnostic(
            CROSS_NETWORK_ACCEPTED_RULE,
            'error',
            `The endpoint accepted a challenge signed for ${alternatePassphrase} on the ${network} network`,
            'Reject signatures that were produced for a different network passphrase.',
            this.options.rules,
          ),
        );
      } else if (response.status !== CROSS_NETWORK_REJECTION_STATUS) {
        add(
          diagnostic(
            CROSS_NETWORK_STATUS_RULE,
            'error',
            `Cross-network challenge was rejected with HTTP ${response.status}, expected 400`,
            'Answer an invalid network passphrase signature with 400 Bad Request.',
            this.options.rules,
          ),
        );
      } else if (error === undefined || error.trim() === '') {
        add(
          diagnostic(
            MISSING_ERROR_CODE_RULE,
            'warning',
            'Cross-network challenge was rejected with 400 but no descriptive error code',
            'Return `{ "error": "<reason>" }` so wallets can diagnose the failure.',
            this.options.rules,
          ),
        );
      }

      report.ok =
        networkBound && expected.validSignatures.length > 0 && probe.rejectedStrictly && !accepted;
    } catch (error) {
      add(
        diagnostic(
          PROBE_FAILED_RULE,
          'warning',
          `POST /auth failed: ${error instanceof Error ? error.message : String(error)}`,
          'Confirm the endpoint accepts SEP-10 challenge responses.',
          this.options.rules,
        ),
      );
    }

    return { report, diagnostics };
  }
}

/** Discovers the endpoint and target network from `stellar.toml`, then audits. */
export async function auditSep10NetworkIsolation(
  doc: Record<string, unknown>,
  domain: string,
  fetchImpl: typeof fetch = fetch,
  options: Sep10IsolationOptions = {},
): Promise<Sep10IsolationResult> {
  return new Sep10NetworkIsolationAuditor(fetchImpl, options).audit(doc, domain);
}

export function renderSep10IsolationReport(report: Sep10IsolationReport): string {
  const lines = [
    'SEP-10 network passphrase isolation',
    `  domain:    ${report.domain}`,
    `  endpoint:  ${report.endpoint}`,
    `  network:   ${report.network}`,
    `  expected:  ${report.expectedPassphrase}`,
    `  alternate: ${report.alternatePassphrase}`,
  ];
  if (report.challenge) {
    lines.push(`  account:   ${report.challenge.account}`);
    lines.push(`  bound:     ${report.challenge.networkBound ? 'yes' : 'no'}`);
  }
  if (report.probe) {
    lines.push(
      `  probe:     HTTP ${report.probe.status ?? 'n/a'}${report.probe.error === undefined ? '' : ` — ${report.probe.error}`}`,
    );
  }
  lines.push(`  result:    ${report.ok ? 'PASS' : 'FAIL'}`);
  for (const finding of report.findings) {
    lines.push(`  [${finding.severity}] ${finding.code}: ${finding.message}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and severity overrides know these ids. */
export const sep10IsolationRules: Rule[] = [
  {
    id: PROBE_FAILED_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'SEP-10 isolation probe could not complete',
    run() {},
  },
  {
    id: CHALLENGE_MALFORMED_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-10 challenge transaction must be parseable',
    run() {},
  },
  {
    id: CHALLENGE_MISMATCH_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-10 challenge must commit to the endpoint network passphrase',
    run() {},
  },
  {
    id: SIGNATURE_INVALID_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-10 challenge must carry a signature valid on the target network',
    run() {},
  },
  {
    id: CROSS_NETWORK_ACCEPTED_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-10 server must not accept cross-network signatures',
    run() {},
  },
  {
    id: CROSS_NETWORK_STATUS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Cross-network challenges must be rejected with HTTP 400',
    run() {},
  },
  {
    id: MISSING_ERROR_CODE_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'Rejected cross-network challenges need a descriptive error code',
    run() {},
  },
];

/** Rule ids emitted by {@link Sep10NetworkIsolationAuditor}. */
export const sep10IsolationRuleIds: readonly string[] = sep10IsolationRules.map((rule) => rule.id);
