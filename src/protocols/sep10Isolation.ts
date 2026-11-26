/**
 * SEP-10 network passphrase isolation auditor.
 *
 * Runs under `stellar-toml-lint audit-sep10-isolation --domain <domain>`.
 *
 * Fetches an unsigned-client challenge and checks the server signature against
 * the configured Stellar network passphrase.
 */

import { Keypair, Networks, TransactionBuilder } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { isRecord, severityFor } from './verifierSupport.js';

const CHALLENGE_MALFORMED_RULE = 'sep10/isolation-challenge-malformed';
const CHALLENGE_MISMATCH_RULE = 'sep10/isolation-challenge-network-mismatch';
const SIGNATURE_INVALID_RULE = 'sep10/isolation-challenge-signature-invalid';
const PROBE_FAILED_RULE = 'sep10/isolation-probe-failed';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md';
const CATEGORY: RuleCategory = 'network';

/** Networks the auditor understands, keyed by the CLI's `--network` values. */
export const NETWORK_PASSPHRASES = {
  public: Networks.PUBLIC,
  testnet: Networks.TESTNET,
} as const;

export type StellarNetwork = keyof typeof NETWORK_PASSPHRASES;

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
  /** Client public key sent in the request. Defaults to an ephemeral public key. */
  clientAccount?: string;
  /** SEP-10 endpoint; discovered from `stellar.toml` when omitted. */
  webAuthEndpoint?: string;
  /** Home domain sent with the challenge request. */
  homeDomain?: string;
  timeoutMs?: number;
}

/** Public-only account and challenge details, safe to print. */
export interface IsolationChallenge {
  /** Public key of the mock client account. */
  account: string;
  /** Public key of the server signing key (challenge source account). */
  serverAccount?: string;
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
  /** True only when the challenge is network-bound. */
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
    const account = this.options.clientAccount ?? Keypair.random().publicKey();

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

    let challengeXdr: string;
    try {
      const url = new URL(endpoint);
      if (url.protocol !== 'https:') throw new Error('WEB_AUTH_ENDPOINT must use HTTPS');
      url.searchParams.set('account', account);
      const homeDomain = this.options.homeDomain ?? domain;
      if (homeDomain !== '') url.searchParams.set('home_domain', homeDomain);
      const response = await this.fetchImpl(url.toString(), {
        method: 'GET',
        redirect: 'error',
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
      account,
      serverAccount: expected.source,
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
    } else if (!networkBound) {
      add(
        diagnostic(
          SIGNATURE_INVALID_RULE,
          'error',
          'The challenge source signature does not validate against the target network passphrase',
          'Sign the challenge transaction with the network passphrase this endpoint serves.',
          this.options.rules,
        ),
      );
    }

    report.ok = networkBound;

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
];

/** Rule ids emitted by {@link Sep10NetworkIsolationAuditor}. */
export const sep10IsolationRuleIds: readonly string[] = sep10IsolationRules.map((rule) => rule.id);
