/**
 * Fiat anchor bank reserve attestation document verifier.
 *
 * Runs under opt-in `--verify-attestations` (also `stellar-toml-lint
 * verify-attestations --domain <domain>`); documents are only downloaded with
 * `--check-network`.
 *
 * Fiat-backed issuers publish third-party (CPA) attestations that bank
 * balances cover the tokens in circulation. A report is only evidence if it is
 * reachable over verified HTTPS, matches a published SHA-256 checksum, names
 * the firm that signed it, and is recent. Sources:
 *
 * - `[[DOCUMENTATION.ATTESTATIONS]]` (or a single table): `url`, `sha256`,
 *   optional `date` (YYYY-MM-DD), `firm`, `reserve_balance`, `issued_supply`.
 * - `CURRENCIES[].attestation_of_reserve` (SEP-1), with an optional
 *   `attestation_of_reserve_sha256`.
 *
 * Downloads go through the platform `fetch`, which rejects invalid or
 * self-signed certificates; that is never disabled here. Corrupted or
 * truncated PDFs are reported as findings, never thrown.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import {
  errorMessage,
  fetchWithTimeout,
  isRecord,
  severityFor,
  toScaled,
} from '../protocols/verifierSupport.js';

const INVALID_URL_RULE = 'attestation/invalid-url';
const MISSING_CHECKSUM_RULE = 'attestation/missing-checksum';
const INVALID_FIELD_RULE = 'attestation/invalid-field';
const EXPIRED_RULE = 'attestation/expired';
const UNDER_RESERVED_RULE = 'attestation/under-reserved';
const UNREACHABLE_RULE = 'attestation/unreachable';
const MISMATCH_RULE = 'attestation/checksum-mismatch';
const CORRUPTED_RULE = 'attestation/corrupted-document';
const MISSING_FIRM_RULE = 'attestation/missing-firm';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';
const DAY_MS = 86_400_000;
const MAX_BYTES = 25 * 1024 * 1024;

export interface AttestationEntry {
  path: string;
  url: unknown;
  sha256: unknown;
  date?: unknown;
  firm?: unknown;
  reserveBalance?: unknown;
  issuedSupply?: unknown;
}

export interface PdfMetadata {
  creationDate?: number;
  author?: string;
  reserveBalance?: string;
}

export interface AttestationOptions {
  rules?: RuleOverrides;
  /** Download each document and check its checksum and metadata. */
  download?: boolean;
  /** Oldest acceptable attestation, in days. Default 90. */
  maxAgeDays?: number;
  /** Reference time in UTC milliseconds. */
  now?: number;
  timeoutMs?: number;
}

export interface AttestationResult {
  diagnostics: Diagnostic[];
  attestations: Array<{ path: string; url: string; verified: boolean }>;
}

/** SHA-256 via Web Crypto, so the verifier also runs in the browser bundle. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Collects every declared attestation from a parsed `stellar.toml`. */
export function collectAttestations(doc: Record<string, unknown>): AttestationEntry[] {
  const out: AttestationEntry[] = [];
  const documentation = isRecord(doc.DOCUMENTATION) ? doc.DOCUMENTATION : {};
  const raw = documentation.ATTESTATIONS;
  const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  list.forEach((a, i) => {
    const path = Array.isArray(raw)
      ? `DOCUMENTATION.ATTESTATIONS[${i}]`
      : 'DOCUMENTATION.ATTESTATIONS';
    const r = isRecord(a) ? a : {};
    out.push({
      path,
      url: r.url,
      sha256: r.sha256,
      date: r.date,
      firm: r.firm,
      reserveBalance: r.reserve_balance,
      issuedSupply: r.issued_supply,
    });
  });
  const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];
  currencies.forEach((c, i) => {
    if (!isRecord(c) || c.attestation_of_reserve === undefined) return;
    out.push({
      path: `CURRENCIES[${i}].attestation_of_reserve`,
      url: c.attestation_of_reserve,
      sha256: c.attestation_of_reserve_sha256,
    });
  });
  return out;
}

/** Parses a PDF date (`D:YYYYMMDDHHmmSSOHH'mm'`) to UTC milliseconds. */
export function parsePdfDate(value: string): number | undefined {
  const m = /^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?/.exec(value);
  if (!m) return undefined;
  const [, y, mo = '01', d = '01', h = '00', mi = '00', s = '00', tz] = m;
  let offset = 0;
  if (tz && tz !== 'Z') {
    const sign = tz.startsWith('-') ? -1 : 1;
    const digits = tz.replace(/\D/g, '');
    offset = sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4))) * 60_000;
  }
  const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  return Number.isNaN(ms) ? undefined : ms - offset;
}

/**
 * Reads the Info dictionary of a PDF without a PDF library: `/CreationDate`,
 * `/Author` (the CPA firm) and an optional `/ReserveBalance`. Returns
 * `undefined` when the bytes are not a complete PDF.
 */
export function readPdfMetadata(bytes: Uint8Array): PdfMetadata | undefined {
  const text = Buffer.from(bytes).toString('latin1');
  if (!text.startsWith('%PDF-') || !text.slice(-1024).includes('%%EOF')) return undefined;
  const field = (name: string): string | undefined =>
    new RegExp(`/${name}\\s*\\(([^)]*)\\)`).exec(text)?.[1];
  const date = field('CreationDate');
  return {
    creationDate: date === undefined ? undefined : parsePdfDate(date),
    author: field('Author')?.trim() || undefined,
    reserveBalance: field('ReserveBalance')?.trim(),
  };
}

export class BankAttestationVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: AttestationOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<AttestationResult> {
    const diagnostics: Diagnostic[] = [];
    const push = (rule: string, fallback: 'error' | 'warning', message: string, path: string) => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule,
          severity,
          category: 'documentation',
          message,
          path,
          helpUri: SPEC,
        });
      }
    };
    const now = this.options.now ?? Date.now();
    const maxAge = this.options.maxAgeDays ?? 90;
    const checkAge = (time: number, path: string, source: string): void => {
      const age = Math.floor((now - time) / DAY_MS);
      if (age > maxAge)
        push(EXPIRED_RULE, 'error', `${source} is ${age} days old (limit ${maxAge})`, path);
    };
    const attestations: AttestationResult['attestations'] = [];

    for (const a of collectAttestations(doc)) {
      if (!isString(a.url) || !isHttpsUrl(a.url)) {
        push(
          INVALID_URL_RULE,
          'error',
          `${a.path} must be an https URL to the attestation`,
          a.path,
        );
        continue;
      }
      const record = { path: a.path, url: a.url, verified: false };
      attestations.push(record);
      let checksum: string | undefined;
      if (a.sha256 === undefined) {
        push(MISSING_CHECKSUM_RULE, 'error', `${a.path} publishes no SHA-256 checksum`, a.path);
      } else if (!isString(a.sha256) || !/^[0-9a-f]{64}$/i.test(a.sha256)) {
        push(INVALID_FIELD_RULE, 'error', `${a.path} sha256 must be 64 hex characters`, a.path);
      } else checksum = a.sha256.toLowerCase();

      if (a.date !== undefined) {
        const time =
          isString(a.date) && /^\d{4}-\d{2}-\d{2}$/.test(a.date)
            ? Date.parse(`${a.date}T00:00:00Z`)
            : NaN;
        if (Number.isNaN(time))
          push(INVALID_FIELD_RULE, 'error', `${a.path} date must be YYYY-MM-DD`, a.path);
        else checkAge(time, a.path, 'Declared attestation date');
      }
      if (a.reserveBalance !== undefined && a.issuedSupply !== undefined) {
        const reserve = isString(a.reserveBalance) ? toScaled(a.reserveBalance) : undefined;
        const supply = isString(a.issuedSupply) ? toScaled(a.issuedSupply) : undefined;
        if (reserve === undefined || supply === undefined) {
          push(INVALID_FIELD_RULE, 'error', `${a.path} balances must be decimal strings`, a.path);
        } else if (reserve < supply) {
          push(
            UNDER_RESERVED_RULE,
            'error',
            `${a.path} reports reserves ${a.reserveBalance} below issued supply ${a.issuedSupply}`,
            a.path,
          );
        }
      }
      if (!this.options.download) continue;

      let bytes: Uint8Array;
      try {
        const res = await fetchWithTimeout(this.fetchImpl, a.url, {}, this.options.timeoutMs);
        if (res.url && !res.url.startsWith('https://')) throw new Error(`redirected to ${res.url}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        bytes = new Uint8Array(await res.arrayBuffer());
        if (bytes.byteLength > MAX_BYTES) throw new Error('document exceeds 25 MiB');
      } catch (error) {
        push(
          UNREACHABLE_RULE,
          'error',
          `${a.url} could not be downloaded securely (${errorMessage(error)})`,
          a.path,
        );
        continue;
      }
      const digest = await sha256Hex(bytes);
      const hashOk = checksum !== undefined && digest === checksum;
      if (checksum !== undefined && !hashOk) {
        push(
          MISMATCH_RULE,
          'error',
          `${a.url} hashes to ${digest}, not the published ${checksum}`,
          a.path,
        );
      }
      const meta = readPdfMetadata(bytes);
      if (meta === undefined) {
        push(CORRUPTED_RULE, 'error', `${a.url} is not a complete PDF document`, a.path);
        continue;
      }
      if (meta.creationDate !== undefined) checkAge(meta.creationDate, a.path, 'Attestation PDF');
      else if (a.date === undefined) {
        push(
          INVALID_FIELD_RULE,
          'error',
          `${a.url} carries no creation date and none is declared`,
          a.path,
        );
      }
      if (meta.author === undefined && !isString(a.firm)) {
        push(MISSING_FIRM_RULE, 'warning', `${a.url} does not name the attesting firm`, a.path);
      }
      const pdfReserve =
        meta.reserveBalance === undefined ? undefined : toScaled(meta.reserveBalance);
      const supply = isString(a.issuedSupply) ? toScaled(a.issuedSupply) : undefined;
      if (pdfReserve !== undefined && supply !== undefined && pdfReserve < supply) {
        push(
          UNDER_RESERVED_RULE,
          'error',
          `${a.url} attests reserves ${meta.reserveBalance} below issued supply ${a.issuedSupply}`,
          a.path,
        );
      }
      const fresh = !diagnostics.some((d) => d.path === a.path && d.rule === EXPIRED_RULE);
      record.verified = hashOk && fresh;
    }
    return { diagnostics, attestations };
  }
}

export async function verifyBankAttestations(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AttestationOptions = {},
): Promise<AttestationResult> {
  return new BankAttestationVerifier(fetchImpl, options).verify(doc);
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'documentation',
  severity: 'error',
  description,
  run() {},
});

export const bankAttestationRules: Rule[] = [
  def(INVALID_URL_RULE, 'Reserve attestations must be linked over https'),
  def(MISSING_CHECKSUM_RULE, 'Reserve attestations must publish a SHA-256 checksum'),
  def(INVALID_FIELD_RULE, 'Attestation checksum, date and balance fields must be well formed'),
  def(EXPIRED_RULE, 'Reserve attestations must not be older than 90 days'),
  def(UNDER_RESERVED_RULE, 'Attested reserves must cover the issued supply'),
  def(UNREACHABLE_RULE, 'Attestation documents must download over verified HTTPS'),
  def(MISMATCH_RULE, 'The downloaded attestation must match its published SHA-256'),
  def(CORRUPTED_RULE, 'Attestation documents must be complete PDF files'),
  def(MISSING_FIRM_RULE, 'Attestations should name the attesting CPA firm'),
];

export const bankAttestationRuleIds: readonly string[] = bankAttestationRules.map((r) => r.id);
