/**
 * Environmental ESG and carbon offset attestation verifier.
 *
 * Runs under opt-in `--audit-esg-disclosures`; attestation documents are only
 * downloaded and signature-checked with `--check-network`.
 *
 * Anchors claiming green credentials publish `[DOCUMENTATION.ORG_ESG]`. A claim
 * is only worth showing if it names its carbon accounting methodology, backs
 * renewable usage with certificates (RECs), discloses hosting efficiency (PUE),
 * and links an environmental attestation signed by the auditor. SEP-1 defines
 * none of these keys, so every field is optional at the spec level: absence is
 * a warning and the sustainability rating simply scores lower.
 *
 * Fields: CARBON_ACCOUNTING_METHODOLOGY, RENEWABLE_ENERGY_CERTIFICATES,
 * PUE, ATTESTATION_URL, ATTESTATION_SIGNATURE_URL (hex or base64 Ed25519),
 * ATTESTATION_PUBLIC_KEY (64-char hex or a Stellar G... key),
 * ATTESTATION_EXPIRES (YYYY-MM-DD).
 */

import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const MISSING_RULE = 'esg/missing-field';
const INVALID_RULE = 'esg/invalid-field';
const EXPIRED_RULE = 'esg/attestation-expired';
const UNREACHABLE_RULE = 'esg/attestation-unreachable';
const SIGNATURE_RULE = 'esg/attestation-signature-invalid';

const SPEC = 'https://ghgprotocol.org/standards';

const REQUIRED = [
  'CARBON_ACCOUNTING_METHODOLOGY',
  'RENEWABLE_ENERGY_CERTIFICATES',
  'PUE',
  'ATTESTATION_URL',
] as const;

export type EsgRating = 'Platinum' | 'Gold' | 'Silver' | 'Bronze' | 'Unrated';

export interface EsgCriterion {
  name: string;
  points: number;
  max: number;
  detail: string;
}

export interface EsgReport {
  criteria: EsgCriterion[];
  /** 0-100. */
  score: number;
  rating: EsgRating;
}

export interface EsgOptions {
  rules?: RuleOverrides;
  /** Download the attestation and verify its signature. */
  checkAttestation?: boolean;
  /** Overrides today's date, for tests. */
  now?: Date;
  timeoutMs?: number;
}

export interface EsgResult {
  diagnostics: Diagnostic[];
  report: EsgReport;
}

/** Industry-style tiers: PUE <= 1.2 is hyperscale-grade, > 1.6 is the legacy average. */
export function rate(score: number): EsgRating {
  if (score >= 90) return 'Platinum';
  if (score >= 75) return 'Gold';
  if (score >= 50) return 'Silver';
  if (score >= 25) return 'Bronze';
  return 'Unrated';
}

function pueScore(pue: number): number {
  if (pue <= 1.2) return 25;
  if (pue <= 1.4) return 20;
  if (pue <= 1.6) return 12;
  return 5;
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
}

function fromBase64(text: string): Uint8Array | undefined {
  try {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function publicKeyBytes(key: string): Uint8Array | undefined {
  if (/^[0-9a-f]{64}$/i.test(key)) return fromHex(key);
  if (StrKey.isValidEd25519PublicKey(key))
    return new Uint8Array(StrKey.decodeEd25519PublicKey(key));
  return undefined;
}

function signatureBytes(text: string): Uint8Array | undefined {
  const t = text.trim();
  if (/^[0-9a-f]{128}$/i.test(t)) return fromHex(t);
  const b = fromBase64(t);
  return b !== undefined && b.length === 64 ? b : undefined;
}

/** Verifies `signature` over `data` with an Ed25519 key given as hex or a G... address. */
export async function verifyAttestationSignature(
  data: Uint8Array,
  signature: string,
  publicKey: string,
): Promise<boolean> {
  const key = publicKeyBytes(publicKey);
  const sig = signatureBytes(signature);
  if (key === undefined || sig === undefined) return false;
  try {
    // WebCrypto, so the same code runs in Node and in the browser bundle.
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      key as Uint8Array<ArrayBuffer>,
      'Ed25519',
      false,
      ['verify'],
    );
    return await globalThis.crypto.subtle.verify(
      'Ed25519',
      cryptoKey,
      sig as Uint8Array<ArrayBuffer>,
      data as Uint8Array<ArrayBuffer>,
    );
  } catch {
    return false;
  }
}

function lookupEsg(doc: Record<string, unknown>): Record<string, unknown> | undefined {
  const documentation = doc.DOCUMENTATION;
  const esg = isRecord(documentation) ? documentation.ORG_ESG : undefined;
  return isRecord(esg) ? esg : undefined;
}

export class EsgComplianceVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: EsgOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<EsgResult> {
    const diagnostics: Diagnostic[] = [];
    const criteria: EsgCriterion[] = [];
    const push = (
      rule: string,
      fallback: 'error' | 'warning',
      message: string,
      path: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'documentation',
        message,
        path: `DOCUMENTATION.ORG_ESG${path ? `.${path}` : ''}`,
        helpUri: SPEC,
        suggestion,
      });
    };
    const finish = (): EsgResult => {
      const score = criteria.reduce((n, c) => n + c.points, 0);
      return { diagnostics, report: { criteria, score, rating: rate(score) } };
    };

    const esg = lookupEsg(doc);
    if (esg === undefined) {
      // No green claim, nothing to verify: stay silent rather than nag every anchor.
      return finish();
    }

    for (const key of REQUIRED) {
      if (esg[key] === undefined) {
        push(
          MISSING_RULE,
          'warning',
          `${key} is not declared in ORG_ESG`,
          key,
          `Publish ${key} so green claims can be evidenced.`,
        );
      }
    }

    const method = esg.CARBON_ACCOUNTING_METHODOLOGY;
    const methodOk = isString(method) && method.trim() !== '';
    if (method !== undefined && !methodOk) {
      push(
        INVALID_RULE,
        'warning',
        'CARBON_ACCOUNTING_METHODOLOGY must be a non-empty string',
        'CARBON_ACCOUNTING_METHODOLOGY',
        'Name the standard used, e.g. "GHG Protocol Scope 2".',
      );
    }
    criteria.push({
      name: 'Carbon accounting methodology',
      points: methodOk ? 25 : 0,
      max: 25,
      detail: methodOk ? String(method) : 'missing',
    });

    const recs = esg.RENEWABLE_ENERGY_CERTIFICATES;
    const recList = isString(recs) ? [recs] : Array.isArray(recs) ? recs : [];
    const recsOk = recList.length > 0 && recList.every((r) => isString(r) && r.trim() !== '');
    if (recs !== undefined && !recsOk) {
      push(
        INVALID_RULE,
        'warning',
        'RENEWABLE_ENERGY_CERTIFICATES must be a non-empty string or list of certificate ids',
        'RENEWABLE_ENERGY_CERTIFICATES',
        'List the REC serial numbers or registry ids.',
      );
    }
    criteria.push({
      name: 'Renewable energy certificates',
      points: recsOk ? 25 : 0,
      max: 25,
      detail: recsOk ? `${recList.length} certificate(s)` : 'missing',
    });

    const pue = esg.PUE;
    // PUE is total facility energy over IT energy, so it can never be below 1.
    const pueOk = typeof pue === 'number' && Number.isFinite(pue) && pue >= 1 && pue <= 5;
    if (pue !== undefined && !pueOk) {
      push(
        INVALID_RULE,
        'warning',
        `PUE ${String(pue)} is not a plausible power usage effectiveness`,
        'PUE',
        'PUE is a number from 1.0 upwards, e.g. 1.2.',
      );
    }
    criteria.push({
      name: 'Hosting efficiency (PUE)',
      points: pueOk ? pueScore(pue as number) : 0,
      max: 25,
      detail: pueOk ? String(pue) : 'missing',
    });

    let attestationPoints = 0;
    let attestationDetail = 'missing';
    const url = esg.ATTESTATION_URL;
    if (url !== undefined && !(isString(url) && isHttpsUrl(url))) {
      push(
        INVALID_RULE,
        'warning',
        'ATTESTATION_URL must be an https URL',
        'ATTESTATION_URL',
        'Link the auditor-hosted attestation over https.',
      );
      attestationDetail = 'invalid url';
    } else if (isString(url)) {
      attestationDetail = 'declared';
      attestationPoints = 10;
      const expiry = esg.ATTESTATION_EXPIRES;
      if (isString(expiry) && /^\d{4}-\d{2}-\d{2}$/.test(expiry)) {
        if (new Date(`${expiry}T23:59:59Z`) < (this.options.now ?? new Date())) {
          push(
            EXPIRED_RULE,
            'error',
            `Environmental attestation expired on ${expiry}`,
            'ATTESTATION_EXPIRES',
            'Obtain a renewed attestation from the auditor and update ATTESTATION_URL.',
          );
          attestationPoints = 0;
          attestationDetail = `expired ${expiry}`;
        }
      } else if (expiry !== undefined) {
        push(
          INVALID_RULE,
          'warning',
          'ATTESTATION_EXPIRES must be a YYYY-MM-DD date',
          'ATTESTATION_EXPIRES',
          'Use an ISO date such as 2027-06-30.',
        );
      }
      if (attestationPoints > 0 && this.options.checkAttestation) {
        const verified = await this.checkSignature(esg, url, push);
        if (verified) {
          attestationPoints = 25;
          attestationDetail = 'signature verified';
        } else {
          attestationPoints = 0;
          attestationDetail = 'unverified';
        }
      } else if (attestationPoints > 0) {
        attestationDetail = 'declared, not verified (use --check-network)';
      }
    }
    criteria.push({
      name: 'Third-party attestation',
      points: attestationPoints,
      max: 25,
      detail: attestationDetail,
    });
    return finish();
  }

  private async checkSignature(
    esg: Record<string, unknown>,
    url: string,
    push: (r: string, f: 'error' | 'warning', m: string, p: string, s: string) => void,
  ): Promise<boolean> {
    const sigUrl = esg.ATTESTATION_SIGNATURE_URL;
    const pub = esg.ATTESTATION_PUBLIC_KEY;
    if (!isString(sigUrl) || !isHttpsUrl(sigUrl) || !isString(pub)) {
      push(
        MISSING_RULE,
        'warning',
        'ATTESTATION_SIGNATURE_URL and ATTESTATION_PUBLIC_KEY are needed to verify the attestation',
        'ATTESTATION_SIGNATURE_URL',
        'Publish the auditor’s detached Ed25519 signature and public key.',
      );
      return false;
    }
    try {
      const [doc, sig] = await Promise.all([
        fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs),
        fetchWithTimeout(this.fetchImpl, sigUrl, {}, this.options.timeoutMs),
      ]);
      if (!doc.ok || !sig.ok) throw new Error(`HTTP ${doc.ok ? sig.status : doc.status}`);
      const data = new Uint8Array(await doc.arrayBuffer());
      if (await verifyAttestationSignature(data, await sig.text(), pub)) return true;
      push(
        SIGNATURE_RULE,
        'error',
        'Environmental attestation signature does not verify against ATTESTATION_PUBLIC_KEY',
        'ATTESTATION_SIGNATURE_URL',
        'Re-download the attestation and signature from the auditor, or correct the public key.',
      );
    } catch (error) {
      push(
        UNREACHABLE_RULE,
        'warning',
        `Environmental attestation could not be downloaded (${errorMessage(error)})`,
        'ATTESTATION_URL',
        'Host the attestation and its signature at stable https URLs.',
      );
    }
    return false;
  }
}

export async function auditEsgDisclosures(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: EsgOptions = {},
): Promise<EsgResult> {
  return new EsgComplianceVerifier(fetchImpl, options).verify(doc);
}

/** Renders the sustainability rating as a plain-text checklist. */
export function renderEsgReport(report: EsgReport): string {
  const lines = report.criteria.map(
    (c) => `  ${String(c.points).padStart(2)}/${c.max}  ${c.name}: ${c.detail}`,
  );
  return `ESG sustainability rating: ${report.rating} (${report.score}/100)\n${lines.join('\n')}\n`;
}

const def = (id: string, severity: 'error' | 'warning', description: string): Rule => ({
  id,
  category: 'documentation',
  severity,
  description,
  run() {},
});

export const esgRules: Rule[] = [
  def(MISSING_RULE, 'warning', 'ORG_ESG should disclose methodology, RECs, PUE and an attestation'),
  def(INVALID_RULE, 'warning', 'ORG_ESG fields must be well-formed'),
  def(EXPIRED_RULE, 'error', 'Environmental attestations must not be expired'),
  def(UNREACHABLE_RULE, 'warning', 'The environmental attestation must be downloadable'),
  def(SIGNATURE_RULE, 'error', 'The environmental attestation signature must verify'),
];

export const esgRuleIds: readonly string[] = esgRules.map((r) => r.id);
