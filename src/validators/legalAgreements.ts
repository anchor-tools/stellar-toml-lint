/**
 * Automated anchor terms of service and legal agreement integrity auditor.
 *
 * SEP-1 and consumer-protection rules expect an anchor to publish its legal
 * disclosures — terms of service and a privacy policy — and to keep them
 * reachable. Anchors routinely update those documents without touching the
 * version or checksum a wallet recorded, so a client that verified the terms
 * last month is now relying on text it never saw. The auditor fetches each
 * declared document over HTTPS, computes its SHA-256, and compares that against
 * any checksum the file publishes, so a silent edit is caught rather than
 * trusted.
 *
 * Runs under opt-in `--verify-legal`. Documents are read from
 * `[DOCUMENTATION]` and its `[DOCUMENTATION.ORG_LEGAL]` sub-table, so both
 * spellings of `ORG_TERMS_OF_SERVICE` and `ORG_PRIVACY_POLICY` are honoured. A
 * document that cannot be fetched, or that fails its checksum, is reported; a
 * document that is fine stays silent.
 */
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString, isUrl } from '../predicates.js';

export const LEGAL_DOCUMENT_UNREACHABLE = 'legal/document-unreachable';
export const LEGAL_DOCUMENT_NOT_HTTPS = 'legal/document-not-https';
export const LEGAL_DOCUMENT_REDIRECTED = 'legal/document-redirected';
export const LEGAL_HASH_MISMATCH = 'legal/hash-mismatch';
export const LEGAL_TIMESTAMP_MISMATCH = 'legal/timestamp-mismatch';
export const LEGAL_MISSING_DECLARATION = 'legal/missing-declaration';

/** How long one legal document may take to answer before the read is abandoned. */
const FETCH_TIMEOUT_MS = 10_000;

/** A published timestamp and a served `Last-Modified` this far apart disagree. */
const TIMESTAMP_TOLERANCE_MS = 86_400_000;

const SPEC_URL = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';

export type LegalDocumentKind = 'terms-of-service' | 'privacy-policy';

/** One legal document the file declares. */
export interface LegalDocumentRef {
  kind: LegalDocumentKind;
  url: string;
  /** Dotted path of the field that declared the document. */
  path: string;
  /** Published SHA-256, if the file carries one. */
  hash?: string;
  /** Published revision timestamp, if the file carries one. */
  updated?: string;
}

/** What the audit concluded for one document. */
export type LegalDocumentStatus =
  | 'verified'
  | 'not-https'
  | 'not-a-url'
  | 'unreachable'
  | 'redirected'
  | 'hash-mismatch'
  | 'timestamp-mismatch';

/** The outcome of auditing one declared document. */
export interface LegalDocumentAudit {
  ref: LegalDocumentRef;
  status: LegalDocumentStatus;
  httpStatus?: number;
  /** The SHA-256 the audit computed over the bytes it read. */
  computedHash?: string;
  /** The checksum the file published, when it carried one. */
  expectedHash?: string;
  /** The `Last-Modified` the server reported, as an ISO string. */
  lastModified?: string;
  /** The redirect target, when the canonical link was not direct. */
  redirectLocation?: string;
  diagnostics: Diagnostic[];
}

/** The audit's full result: findings, plus one report per document. */
export interface LegalAuditResult {
  diagnostics: Diagnostic[];
  documents: LegalDocumentAudit[];
}

export interface LegalAuditOptions {
  rules?: RuleOverrides;
  /** Evaluated once, so every document is judged against the same clock. */
  now?: Date;
}

/** The document fields the auditor understands, and their published companions. */
const DOCUMENT_FIELDS: readonly { kind: LegalDocumentKind; field: string }[] = [
  { kind: 'terms-of-service', field: 'ORG_TERMS_OF_SERVICE' },
  { kind: 'privacy-policy', field: 'ORG_PRIVACY_POLICY' },
];

const HASH_SUFFIXES = ['_HASH', '_CHECKSUM', '_SHA256'] as const;
const UPDATED_SUFFIXES = ['_UPDATED', '_LAST_MODIFIED'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Reads the legal documents a file declares.
 *
 * Both `[DOCUMENTATION]` and its `[DOCUMENTATION.ORG_LEGAL]` sub-table are
 * consulted, so an anchor that groups its legal links under `ORG_LEGAL` is
 * audited the same as one that puts them directly under `DOCUMENTATION`. A
 * checksum or timestamp sits next to its document under the same container.
 */
export function legalDocumentsOf(doc: Record<string, unknown>): LegalDocumentRef[] {
  const documentation = doc.DOCUMENTATION;
  if (!isRecord(documentation)) return [];

  const containers: { table: Record<string, unknown>; prefix: string }[] = [
    { table: documentation, prefix: 'DOCUMENTATION' },
  ];
  const orgLegal = documentation.ORG_LEGAL;
  if (isRecord(orgLegal)) {
    containers.push({ table: orgLegal, prefix: 'DOCUMENTATION.ORG_LEGAL' });
  }

  const documents: LegalDocumentRef[] = [];
  for (const { table, prefix } of containers) {
    for (const { kind, field } of DOCUMENT_FIELDS) {
      const url = table[field];
      if (!isString(url)) continue;

      const hash = findCompanion(table, field, HASH_SUFFIXES);
      const updated = findCompanion(table, field, UPDATED_SUFFIXES);
      documents.push({
        kind,
        url,
        path: `${prefix}.${field}`,
        ...(hash === undefined ? {} : { hash }),
        ...(updated === undefined ? {} : { updated }),
      });
    }
  }
  return documents;
}

function findCompanion(
  table: Record<string, unknown>,
  field: string,
  suffixes: readonly string[],
): string | undefined {
  for (const suffix of suffixes) {
    const value = table[`${field}${suffix}`];
    if (isString(value) && value.trim() !== '') return value.trim();
  }
  return undefined;
}

/**
 * Best-effort normalisation for a checksum comparison over rendered content.
 *
 * Static text documents are served with an HTML comment, a cache-busting
 * timestamp, or a 1×1 tracking pixel that changes on every deploy; hashing the
 * bytes verbatim would report a mismatch on a document nobody edited. This
 * drops those known-dynamic fragments and normalises line endings so a
 * published checksum computed over the rendered text still matches. Binary
 * documents (PDF) are returned untouched.
 */
export function normalizeLegalContent(bytes: Uint8Array, contentType: string): Uint8Array {
  const looksTextual =
    contentType.includes('text') || contentType.includes('html') || contentType.includes('xml');
  if (!looksTextual) return bytes;

  const text = new TextDecoder().decode(bytes);
  const normalized = text
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<img\b[^>]*>/gi, (tag) =>
      /\b(width|height)\s*=\s*["']?1["']?|\bwidth\s*:\s*1px|\bheight\s*:\s*1px/i.test(tag)
        ? ''
        : tag,
    )
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+$/gm, '');
  return new TextEncoder().encode(normalized);
}

/** `sha256:<hex>`, `SHA256 <hex>`, or bare hex, normalised to lowercase hex. */
export function normalizePublishedHash(value: string): string | undefined {
  const candidate = value
    .trim()
    .replace(/^(sha-?256|sha256sum)\s*[:=]?\s*/i, '')
    .replace(/\s+/g, '')
    .toLowerCase();
  return /^[0-9a-f]{64}$/.test(candidate) ? candidate : undefined;
}

export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

function parseDate(value: string | undefined): Date | undefined {
  if (value === undefined) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  path: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    { rule, severity, category: 'documentation', message, path, helpUri: SPEC_URL, suggestion },
  ];
}

/** The URL a redirect Location header points at, resolved against the request. */
function resolveLocation(location: string | null, base: string): string | undefined {
  if (location === null || location === '') return undefined;
  try {
    return new URL(location, base).toString();
  } catch {
    return undefined;
  }
}

async function fetchDocument(
  url: string,
  fetchImpl: typeof fetch,
): Promise<{ response: Response; redirectLocation?: string } | { error: string }> {
  try {
    const response = await fetchImpl(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    // A canonical legal link should not bounce: an anchor that moved its terms
    // behind a redirect is one hop away from serving stale text to a client
    // that cached the location. The document is still read, from the target.
    if (response.status >= 300 && response.status < 400) {
      const location = resolveLocation(response.headers.get('location'), url);
      if (location === undefined) return { error: `redirected without a usable Location header` };
      await response.body?.cancel().catch(() => {});
      const followed = await fetchImpl(location, {
        redirect: 'follow',
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      return { response: followed, redirectLocation: location };
    }

    return { response };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Fetches one declared document and audits its availability, checksum, and
 * timestamp.
 *
 * Never throws: an unreachable host, a non-200 answer, or an unreadable body
 * becomes a report whose status and diagnostics say so.
 */
export async function auditLegalDocument(
  ref: LegalDocumentRef,
  fetchImpl: typeof fetch = fetch,
  options: LegalAuditOptions = {},
): Promise<LegalDocumentAudit> {
  if (!isUrl(ref.url)) {
    return {
      ref,
      status: 'not-a-url',
      diagnostics: finding(
        LEGAL_DOCUMENT_NOT_HTTPS,
        'error',
        `${ref.path} is not a usable URL`,
        ref.path,
        'Point the legal document field at an absolute https:// URL.',
        options.rules,
      ),
    };
  }

  if (!isHttpsUrl(ref.url)) {
    return {
      ref,
      status: 'not-https',
      diagnostics: finding(
        LEGAL_DOCUMENT_NOT_HTTPS,
        'error',
        `${ref.path} is served over plain HTTP; legal documents must use https://`,
        ref.path,
        'Serve the document over TLS so a client can trust the bytes it reads.',
        options.rules,
      ),
    };
  }

  const outcome = await fetchDocument(ref.url, fetchImpl);
  if ('error' in outcome) {
    return {
      ref,
      status: 'unreachable',
      diagnostics: finding(
        LEGAL_DOCUMENT_UNREACHABLE,
        'error',
        `Could not fetch ${ref.path}: ${outcome.error}`,
        ref.path,
        'Confirm the document is published and reachable at the declared URL.',
        options.rules,
      ),
    };
  }

  const { response, redirectLocation } = outcome;
  const diagnostics: Diagnostic[] = [];

  if (redirectLocation !== undefined) {
    diagnostics.push(
      ...finding(
        LEGAL_DOCUMENT_REDIRECTED,
        'warning',
        `${ref.path} redirects to ${redirectLocation} instead of serving the document directly`,
        ref.path,
        'Link the canonical URL so a cached location cannot serve stale terms.',
        options.rules,
      ),
    );
  }

  if (!response.ok) {
    diagnostics.push(
      ...finding(
        LEGAL_DOCUMENT_UNREACHABLE,
        'error',
        `${ref.path} returned HTTP ${response.status}`,
        ref.path,
        'A legal document a client must read cannot answer with an error status.',
        options.rules,
      ),
    );
    return {
      ref,
      status: 'unreachable',
      httpStatus: response.status,
      ...(redirectLocation === undefined ? {} : { redirectLocation }),
      diagnostics,
    };
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  const contentType = response.headers.get('content-type') ?? '';
  const computedHash = sha256Hex(bytes);
  const reported: LegalDocumentAudit = {
    ref,
    status: redirectLocation === undefined ? 'verified' : 'redirected',
    httpStatus: response.status,
    computedHash,
    ...(redirectLocation === undefined ? {} : { redirectLocation }),
    diagnostics,
  };

  const lastModified = parseDate(response.headers.get('last-modified') ?? undefined);
  if (lastModified !== undefined) reported.lastModified = lastModified.toISOString();

  if (ref.hash !== undefined) {
    const expected = normalizePublishedHash(ref.hash);
    reported.expectedHash = ref.hash;
    if (expected === undefined) {
      diagnostics.push(
        ...finding(
          LEGAL_HASH_MISMATCH,
          'error',
          `${ref.path} publishes a checksum that is not a SHA-256 digest`,
          ref.path,
          'Publish the lowercase hex SHA-256 of the document, e.g. a 64-character digest.',
          options.rules,
        ),
      );
    } else {
      const normalizedMatch = sha256Hex(normalizeLegalContent(bytes, contentType)) === expected;
      if (computedHash !== expected && !normalizedMatch) {
        diagnostics.push(
          ...finding(
            LEGAL_HASH_MISMATCH,
            'error',
            `${ref.path} does not match its published SHA-256 (served ${computedHash.slice(0, 12)}…, published ${expected.slice(0, 12)}…)`,
            ref.path,
            'Re-publish the checksum after the edit, or restore the document the checksum was taken from.',
            options.rules,
          ),
        );
        reported.status = 'hash-mismatch';
      }
    }
  }

  const publishedUpdated = parseDate(ref.updated);
  if (publishedUpdated !== undefined && lastModified !== undefined) {
    const drift = Math.abs(lastModified.getTime() - publishedUpdated.getTime());
    if (drift > TIMESTAMP_TOLERANCE_MS) {
      const direction =
        lastModified.getTime() > publishedUpdated.getTime()
          ? 'newer than the published revision'
          : 'older than the published revision';
      diagnostics.push(
        ...finding(
          LEGAL_TIMESTAMP_MISMATCH,
          'warning',
          `${ref.path} Last-Modified (${lastModified.toISOString().slice(0, 10)}) is ${direction} (${publishedUpdated.toISOString().slice(0, 10)})`,
          ref.path,
          'Update the published revision timestamp whenever the document changes.',
          options.rules,
        ),
      );
      if (reported.status === 'verified' || reported.status === 'redirected') {
        reported.status = 'timestamp-mismatch';
      }
    }
  }

  return reported;
}

/**
 * Audits every legal document the file declares.
 *
 * When the file carries a `[DOCUMENTATION]` table but neither a terms of
 * service nor a privacy policy, that absence is itself a finding — a wallet has
 * no legal text to show a user. With no `[DOCUMENTATION]` at all the offline
 * `documentation/present` rule already speaks, so the audit stays quiet to
 * avoid a second diagnostic for one problem.
 */
export async function checkLegalAgreements(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: LegalAuditOptions = {},
): Promise<LegalAuditResult> {
  const documents = legalDocumentsOf(doc);

  if (documents.length === 0) {
    const documentation = doc.DOCUMENTATION;
    if (!isRecord(documentation)) return { diagnostics: [], documents: [] };

    return {
      diagnostics: finding(
        LEGAL_MISSING_DECLARATION,
        'warning',
        'DOCUMENTATION declares neither ORG_TERMS_OF_SERVICE nor ORG_PRIVACY_POLICY',
        'DOCUMENTATION',
        'Publish links to your terms of service and privacy policy so clients can show them.',
        options.rules,
      ),
      documents: [],
    };
  }

  const audits: LegalDocumentAudit[] = [];
  for (const ref of documents) {
    audits.push(await auditLegalDocument(ref, fetchImpl, options));
  }

  return {
    diagnostics: audits.flatMap((audit) => audit.diagnostics),
    documents: audits,
  };
}

/** A one-line, human-readable label for a document kind. */
function labelFor(kind: LegalDocumentKind): string {
  return kind === 'terms-of-service' ? 'Terms of service' : 'Privacy policy';
}

/** The glyphs the reporter uses; the text form is ASCII-only. */
const STATUS_MARKS: Record<LegalDocumentStatus, string> = {
  verified: 'ok',
  'not-https': 'insecure',
  'not-a-url': 'invalid',
  unreachable: 'unreachable',
  redirected: 'redirected',
  'hash-mismatch': 'hash mismatch',
  'timestamp-mismatch': 'stale timestamp',
};

/**
 * Renders the per-document audit summary.
 *
 * `markdown` produces a table for a GitHub step summary; otherwise a compact
 * ASCII block is returned for the console. Both name the document, the URL it
 * was read from, and the status, so the summary is usable without the full
 * diagnostic list.
 */
export function formatLegalAuditReport(
  audits: readonly LegalDocumentAudit[],
  options: { markdown?: boolean } = {},
): string {
  if (audits.length === 0) return '';

  if (options.markdown === true) {
    const lines = [
      '### Legal document audit',
      '',
      '| Document | URL | Status | SHA-256 |',
      '| --- | --- | --- | --- |',
    ];
    for (const audit of audits) {
      lines.push(
        `| ${labelFor(audit.ref.kind)} | ${audit.ref.url} | ${STATUS_MARKS[audit.status]} | ${
          audit.computedHash === undefined ? '—' : `${audit.computedHash.slice(0, 12)}…`
        } |`,
      );
    }
    return `${lines.join('\n')}\n`;
  }

  const lines = ['Legal document audit'];
  for (const audit of audits) {
    lines.push(`  ${labelFor(audit.ref.kind)}: ${STATUS_MARKS[audit.status]} (${audit.ref.url})`);
    if (audit.computedHash !== undefined) lines.push(`    sha256 ${audit.computedHash}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const legalAgreementRules: Rule[] = [
  {
    id: LEGAL_DOCUMENT_UNREACHABLE,
    category: 'documentation',
    severity: 'error',
    description: 'A declared legal document must be reachable over HTTPS',
    run() {},
  },
  {
    id: LEGAL_DOCUMENT_NOT_HTTPS,
    category: 'documentation',
    severity: 'error',
    description: 'Legal document links must be absolute https:// URLs',
    run() {},
  },
  {
    id: LEGAL_DOCUMENT_REDIRECTED,
    category: 'documentation',
    severity: 'warning',
    description: 'Legal document links should serve the document directly, without redirecting',
    run() {},
  },
  {
    id: LEGAL_HASH_MISMATCH,
    category: 'documentation',
    severity: 'error',
    description: 'A legal document must match the SHA-256 checksum the file publishes',
    run() {},
  },
  {
    id: LEGAL_TIMESTAMP_MISMATCH,
    category: 'documentation',
    severity: 'warning',
    description: 'A legal document revision timestamp must agree with the served Last-Modified',
    run() {},
  },
  {
    id: LEGAL_MISSING_DECLARATION,
    category: 'documentation',
    severity: 'warning',
    description: 'DOCUMENTATION should declare a terms of service and privacy policy',
    run() {},
  },
];

/** Rule ids emitted by {@link checkLegalAgreements}. */
export const legalAgreementRuleIds: readonly string[] = legalAgreementRules.map((rule) => rule.id);
