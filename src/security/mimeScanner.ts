/**
 * MIME type confusion and script execution vector scanner.
 *
 * Wallets embed what `stellar.toml` links to: `ORG_LOGO` and
 * `[[CURRENCIES]].image` go into `<img>` tags, reserve attestations into
 * `<iframe>`s and new tabs. A host that answers those links with an ambiguous
 * `Content-Type`, or without `X-Content-Type-Options: nosniff`, lets the client
 * guess — and a guessed `text/html` is executed. An SVG is the same trap in
 * plain sight: it is a vector image format that can carry `<script>`, an
 * `onload=` handler, or a `javascript:` href.
 *
 * The scanner fetches each declared asset, reads its headers, and — only for
 * text-bearing payloads — reads a bounded prefix of the body and looks for
 * active content. Binary image bodies are never buffered, so a multi-gigabyte
 * or endless response cannot exhaust the linter's memory.
 *
 * The SVG check is a token scan of the raw markup, not a parsed document: XML
 * entities are never expanded, so `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
 * is reported rather than dereferenced, and a billion-laughs payload costs the
 * same as any other file.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout } from '../protocols/verifierSupport.js';

const UNREACHABLE_RULE = 'mime/asset-unreachable';
const NOSNIFF_RULE = 'mime/missing-nosniff';
const ACTIVE_TYPE_RULE = 'mime/active-content-type';
const MISMATCH_RULE = 'mime/content-type-mismatch';
const SCRIPT_RULE = 'svg/embedded-script';
const ENTITY_RULE = 'svg/entity-declaration';

const MDN_NOSNIFF_URL =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options';
const MDN_SVG_SCRIPT_URL = 'https://developer.mozilla.org/en-US/docs/Web/SVG/Element/script';

/** Bytes of a text payload the scanner will look at before giving up on it. */
export const MAX_SCAN_BYTES = 256 * 1024;

/** Response types a browser may execute, or sniff into something executable. */
const ACTIVE_TYPE_PATTERNS: readonly RegExp[] = [
  /^text\/html/i,
  /^application\/xhtml/i,
  /^image\/svg\+xml/i,
  /^text\/xml/i,
  /^application\/xml/i,
  /javascript/i,
  /^text\/ecmascript/i,
];

/** The MIME type each file extension actually promises. */
const EXTENSION_TYPES: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  pdf: 'application/pdf',
};

export type AssetKind = 'image' | 'svg' | 'document' | 'toml' | 'other';

interface AssetTarget {
  /** Dotted SEP-1 field the URL came from; reported as the diagnostic path. */
  field: string;
  url: string;
  kind: AssetKind;
}

export interface AssetObservation {
  field: string;
  url: string;
  kind: AssetKind;
  status?: number;
  contentType: string | null;
  nosniff: boolean;
  /** Active markup found in the payload, when one was scanned. */
  vectors: SvgVector[];
  /** True when the payload was cut short at {@link MAX_SCAN_BYTES}. */
  truncated: boolean;
  scanned: boolean;
  error?: string;
}

export type SvgVector =
  | 'script-element'
  | 'event-handler'
  | 'javascript-uri'
  | 'foreign-object'
  | 'embedded-document'
  | 'entity-declaration';

export interface MimeFinding {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  field: string;
  url: string;
  suggestion: string;
}

export interface MimeScanReport {
  ok: boolean;
  observations: AssetObservation[];
  findings: MimeFinding[];
}

export interface MimeScanOptions {
  rules?: RuleOverrides;
  timeoutMs?: number;
  /** Overrides {@link MAX_SCAN_BYTES}; tests and memory-tight runners use it. */
  maxScanBytes?: number;
}

/** Resolves the effective severity for a rule, or `undefined` when it is turned off. */
function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/** Lowercase file extension of a URL path, without the dot, or `undefined`. */
function extensionOf(url: string): string | undefined {
  try {
    const last = new URL(url).pathname.split('/').pop() ?? '';
    const dot = last.lastIndexOf('.');
    if (dot <= 0 || dot === last.length - 1) return undefined;
    return last.slice(dot + 1).toLowerCase();
  } catch {
    return undefined;
  }
}

function kindOf(extension: string | undefined): AssetKind {
  if (extension === 'svg') return 'svg';
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp', 'ico'].includes(extension ?? '')) {
    return 'image';
  }
  if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'].includes(extension ?? '')) return 'document';
  if (extension === 'toml') return 'toml';
  return 'other';
}

/** True when the media type can carry executable content into a client. */
export function isActiveContentType(contentType: string): boolean {
  return ACTIVE_TYPE_PATTERNS.some((pattern) => pattern.test(contentType));
}

/**
 * Finds the vectors that make markup executable.
 *
 * Comments are removed first because a parser ignores them, so a `<script>`
 * sitting in a comment is inert and must not be reported. Everything else is
 * matched against the raw text: no entity is expanded and no external DTD is
 * fetched.
 */
export function findSvgScriptVectors(markup: string): SvgVector[] {
  const stripped = markup.replace(/<!--(?:[^-]|-(?!>))*-->/gis, '');
  // Attribute values reach the URL parser with tabs and newlines removed, and
  // `&#x3a;` reaches it as a colon, so both are folded away before matching.
  const normalised = stripped
    .replace(/&#x0*9;|&#0*9;|&Tab;|&NewLine;|&#x0*a;|&#0*10;/gi, '')
    .replace(/&#x0*3a;|&#0*58;|&colon;/gi, ':')
    .replace(/[\t\n\r\f]/g, '');

  const checks: [SvgVector, RegExp][] = [
    ['script-element', /<\s*(?:[a-z][\w.-]*:)?script\b/i],
    ['event-handler', /\son[a-z]{3,20}\s*=\s*(?:"[^"]*[^\s"]|'[^']*[^\s']|[^\s">])/i],
    ['javascript-uri', /\b(?:xlink:|xml:)?href\s*=\s*["']?\s*javascript\s*:/i],
    ['foreign-object', /<\s*(?:[a-z][\w.-]*:)?foreignobject\b/i],
    ['embedded-document', /<\s*(?:[a-z][\w.-]*:)?(?:iframe|frame|embed|object)\b/i],
    ['entity-declaration', /<!\s*(?:DOCTYPE|ENTITY)/i],
  ];

  const found: SvgVector[] = [];
  for (const [vector, pattern] of checks) {
    if (pattern.test(normalised)) found.push(vector);
  }
  return found;
}

/** Reads at most `maxBytes` of a response body, then releases the stream. */
async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const reader = response.body?.getReader?.();
  if (reader === undefined) {
    // A transport without a readable stream (a recorded fixture, say) has
    // already buffered the body, so the slice is the only bound left.
    const buffered = new Uint8Array(await response.arrayBuffer());
    return decoder.decode(buffered.subarray(0, maxBytes));
  }

  const chunks: Uint8Array[] = [];
  let received = 0;
  let closed = false;
  try {
    while (received < maxBytes) {
      const next = await reader.read();
      if (next.done === true) {
        closed = true;
        break;
      }
      const value = next.value;
      if (value === undefined) continue;
      const room = maxBytes - received;
      if (value.byteLength > room) {
        chunks.push(value.subarray(0, room));
        received += room;
        break;
      }
      chunks.push(value);
      received += value.byteLength;
    }
  } finally {
    if (!closed) await reader.cancel().catch(() => undefined);
    else reader.releaseLock();
  }

  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return decoder.decode(merged);
}

/** Every URL in the document that a client is likely to load or embed. */
export function assetTargets(doc: Record<string, unknown>): AssetTarget[] {
  const targets: AssetTarget[] = [];
  const push = (field: string, value: unknown): void => {
    if (!isString(value) || !isHttpsUrl(value)) return;
    targets.push({ field, url: value, kind: kindOf(extensionOf(value)) });
  };

  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    const table = documentation as Record<string, unknown>;
    push('DOCUMENTATION.ORG_LOGO', table.ORG_LOGO);
    push('DOCUMENTATION.ORG_PHYSICAL_ADDRESS_ATTESTATION', table.ORG_PHYSICAL_ADDRESS_ATTESTATION);
    push('DOCUMENTATION.ORG_PHONE_NUMBER_ATTESTATION', table.ORG_PHONE_NUMBER_ATTESTATION);
  }

  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      const currency = entry as Record<string, unknown>;
      push(`CURRENCIES[${index}].image`, currency.image);
      push(`CURRENCIES[${index}].attestation_of_reserve`, currency.attestation_of_reserve);
      push(`CURRENCIES[${index}].toml`, currency.toml);
    });
  }

  return targets;
}

export class MimeSecurityScanner {
  private readonly fetchImpl: typeof fetch;
  private readonly options: MimeScanOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: MimeScanOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  /** Requests every declared asset and inspects its headers and, where text, its body. */
  async audit(doc: Record<string, unknown>): Promise<MimeScanReport> {
    const maxBytes = this.options.maxScanBytes ?? MAX_SCAN_BYTES;
    const findings: MimeFinding[] = [];
    const observations: AssetObservation[] = [];

    for (const target of assetTargets(doc)) {
      const observation = await this.probe(target, maxBytes);
      observations.push(observation);
      findings.push(...this.inspect(target, observation, maxBytes));
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      observations,
      findings,
    };
  }

  private async probe(target: AssetTarget, maxBytes: number): Promise<AssetObservation> {
    const base: AssetObservation = {
      field: target.field,
      url: target.url,
      kind: target.kind,
      contentType: null,
      nosniff: false,
      vectors: [],
      truncated: false,
      scanned: false,
    };

    let response: Response;
    try {
      response = await fetchWithTimeout(this.fetchImpl, target.url, {}, this.options.timeoutMs);
    } catch (error) {
      return { ...base, error: errorMessage(error) };
    }

    const contentType = response.headers.get('content-type');
    const observed: AssetObservation = {
      ...base,
      status: response.status,
      contentType,
      nosniff: /\bnosniff\b/i.test(response.headers.get('x-content-type-options') ?? ''),
    };

    // Binary payloads are classified from their headers alone: buffering a
    // multi-gigabyte icon to look for a `<script>` tag would be the bug.
    const scannable =
      target.kind === 'svg' ||
      (observed.contentType !== null &&
        (isActiveContentType(observed.contentType) || /^text\//i.test(observed.contentType)));
    if (response.status >= 400 || !scannable) return observed;

    const markup = await readBoundedText(response, maxBytes);
    return {
      ...observed,
      scanned: true,
      truncated: markup.length >= maxBytes,
      vectors: findSvgScriptVectors(markup),
    };
  }

  private inspect(
    target: AssetTarget,
    observation: AssetObservation,
    maxBytes: number,
  ): MimeFinding[] {
    const findings: MimeFinding[] = [];
    const emit = (
      code: string,
      fallback: 'error' | 'warning',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(code, fallback, this.options.rules);
      if (severity === undefined) return;
      findings.push({ code, severity, message, field: target.field, url: target.url, suggestion });
    };

    if (observation.error !== undefined) {
      emit(
        UNREACHABLE_RULE,
        'warning',
        `${target.field} could not be fetched: ${observation.error}`,
        'Serve the asset over https from a host you control so wallets can load it.',
      );
      return findings;
    }

    if (observation.status !== undefined && observation.status >= 400) {
      emit(
        UNREACHABLE_RULE,
        'warning',
        `${target.field} answered HTTP ${observation.status}`,
        'A missing asset shows as a broken icon or an empty attestation in every wallet that lists you.',
      );
      return findings;
    }

    const contentType = observation.contentType ?? '';
    if (!observation.nosniff) {
      emit(
        NOSNIFF_RULE,
        'warning',
        `${target.field} is served without X-Content-Type-Options: nosniff`,
        'Add the nosniff header so a client never guesses a content type from the payload.',
      );
    }

    const expected = EXTENSION_TYPES[extensionOf(target.url) ?? ''];
    const served = contentType.toLowerCase();

    // An `.svg` link served as `image/svg+xml` is not type confusion: that is
    // the only correct way to serve it, and the script scan below is what
    // decides whether the markup is safe. Anything else executable is.
    if (isActiveContentType(served) && served !== expected) {
      emit(
        ACTIVE_TYPE_RULE,
        'error',
        `${target.field} is served as ${contentType}, a type a client may execute`,
        'Serve images as their own image type and documents as application/pdf, never as HTML, XML or script.',
      );
    }

    if (expected !== undefined && served.length > 0 && !served.startsWith(expected)) {
      emit(
        MISMATCH_RULE,
        'warning',
        `${target.field} is named like a ${expected} but served as ${contentType || '(no Content-Type)'}`,
        'Match the Content-Type to the file, or drop the extension from the URL if the host rewrites it.',
      );
    }

    const active = observation.vectors.filter((vector) => vector !== 'entity-declaration');
    if (active.length > 0) {
      emit(
        SCRIPT_RULE,
        'error',
        `${target.field} carries executable markup: ${active.join(', ')}${
          observation.truncated ? ` (first ${maxBytes} bytes scanned)` : ''
        }`,
        'Strip scripts, event handlers, foreignObject and javascript: URLs from SVGs before publishing them.',
      );
    }

    if (observation.vectors.includes('entity-declaration')) {
      emit(
        ENTITY_RULE,
        'warning',
        `${target.field} declares an XML DOCTYPE or ENTITY, the payload for entity-expansion and XXE attacks`,
        'Publish SVGs with no DOCTYPE or internal entity definitions; this scanner reads them without expanding them.',
      );
    }

    return findings;
  }
}

/** Diagnostics for the lint pipeline, so `--audit-asset-security` reports normally. */
export async function auditAssetSecurity(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: MimeScanOptions = {},
): Promise<{ diagnostics: Diagnostic[]; report: MimeScanReport }> {
  const report = await new MimeSecurityScanner(fetchImpl, options).audit(doc);
  const diagnostics: Diagnostic[] = report.findings.map((finding) => ({
    rule: finding.code,
    severity: finding.severity,
    category: 'network',
    message: finding.message,
    path: finding.field,
    helpUri:
      finding.code === SCRIPT_RULE || finding.code === ENTITY_RULE
        ? MDN_SVG_SCRIPT_URL
        : finding.code === NOSNIFF_RULE
          ? MDN_NOSNIFF_URL
          : undefined,
    suggestion: finding.suggestion,
  }));
  return { diagnostics, report };
}

export function renderMimeReport(report: MimeScanReport): string {
  const lines: string[] = [];
  lines.push(`Asset MIME and script scan: ${report.ok ? 'clean' : 'issues found'}`);
  lines.push(`  assets: ${report.observations.length}`);
  for (const observation of report.observations) {
    const state =
      observation.error !== undefined
        ? `unreachable: ${observation.error}`
        : `Content-Type=${observation.contentType ?? '(absent)'} status=${
            observation.status ?? '-'
          } nosniff=${observation.nosniff ? 'yes' : 'no'}${
            observation.scanned ? ` vectors=${observation.vectors.join(',') || 'none'}` : ''
          }`;
    lines.push(`  ${observation.field} (${observation.kind})  ${state}`);
  }
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.findings.length === 0) {
    lines.push('  Every linked asset was typed, sniffed and scanned without a finding.');
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules`, completions and `--off`/`--warn`/`--error` know these ids. */
export const mimeSecurityRules: Rule[] = [
  {
    id: UNREACHABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Assets linked from stellar.toml must be reachable over https',
    run() {},
  },
  {
    id: NOSNIFF_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Linked assets should be served with X-Content-Type-Options: nosniff',
    run() {},
  },
  {
    id: ACTIVE_TYPE_RULE,
    category: 'network',
    severity: 'error',
    description: 'Image and document assets must not be served with an executable content type',
    run() {},
  },
  {
    id: MISMATCH_RULE,
    category: 'network',
    severity: 'warning',
    description: 'The served Content-Type must match the type the asset URL names',
    run() {},
  },
  {
    id: SCRIPT_RULE,
    category: 'network',
    severity: 'error',
    description: 'SVG assets must not carry scripts, event handlers or javascript: URLs',
    run() {},
  },
  {
    id: ENTITY_RULE,
    category: 'network',
    severity: 'warning',
    description: 'SVG assets should not declare DOCTYPE or ENTITY definitions',
    run() {},
  },
];

export const mimeSecurityRuleIds: readonly string[] = mimeSecurityRules.map((rule) => rule.id);
