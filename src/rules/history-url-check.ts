import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';

/**
 * SEP-20 validators publish a history archive, declaring its root in
 * `[[VALIDATORS]].HISTORY`. stellar-core substitutes the `{0}` template
 * parameter when it walks the archive, and every standard archive serves a
 * `.well-known/stellar-history.json` describing its version.
 *
 * The format half of this rule is offline, so it runs on every lint. The
 * reachability half only makes sense against a live archive, so `--check-network`
 * drives it through {@link checkHistoryArchive}.
 */

const INVALID_URL_RULE = 'validators/invalid-history-url';
const UNREACHABLE_RULE = 'validators/stellar-history-json-unreachable';

const METADATA_PATH = '.well-known/stellar-history.json';
const TEMPLATE = /\{[^}]*\}/g;

const SUGGESTION =
  'Point at the archive root, e.g. "https://history.example.com/prd/core-live/core_live_001/".';

/** Reads `[[VALIDATORS]]` as a list of tables, ignoring malformed entries. */
function validatorsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = doc.VALIDATORS;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

/** Applies a `--off`/`--warn`/`--error` override to a network rule's severity. */
function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

/**
 * Returns why a `HISTORY` value is not a usable archive URL, or `undefined` when
 * it is acceptable.
 *
 * `{0}` is the only template parameter stellar-core understands, it belongs to
 * the path rather than the host, and its braces must be balanced. Any absolute
 * URI with a host is accepted — archives are commonly published to S3 or GCS
 * buckets, not only web servers.
 */
function historyUrlProblem(raw: string): string | undefined {
  for (const token of raw.match(TEMPLATE) ?? []) {
    if (token !== '{0}') return `uses the template ${token}, but only {0} is supported`;
  }

  // Any brace left once the well-formed placeholders are removed is a typo.
  if (/[{}]/.test(raw.replace(TEMPLATE, ''))) {
    return 'has unbalanced {0} template braces';
  }

  const schemeEnd = raw.indexOf('://');
  if (schemeEnd !== -1) {
    const authority = raw.slice(schemeEnd + 3).split(/[/?#]/)[0] ?? '';
    if (authority.includes('{')) return 'must not use a template parameter in the host';
  }

  let url: URL;
  try {
    url = new URL(raw.replace(TEMPLATE, '0'));
  } catch {
    return 'is not an absolute URL';
  }
  if (!/^[a-z][a-z0-9+.-]*:$/i.test(url.protocol)) return 'has no URI scheme';
  if (url.hostname === '') return 'has no host';
  return undefined;
}

/**
 * Resolves the archive root described by `HISTORY` to its metadata URL.
 *
 * The `{0}` template names the archive's own path, which is not fixed, so it is
 * dropped and the metadata is looked for at the server root — the location the
 * issue specifies as `/.well-known/stellar-history.json`.
 */
function metadataUrlFor(history: string): string | undefined {
  let base: URL;
  try {
    base = new URL(history.replace(TEMPLATE, ''));
  } catch {
    return undefined;
  }
  base.search = '';
  base.hash = '';
  base.pathname = `${base.pathname.replace(/\/+$/, '')}/`;
  try {
    return new URL(METADATA_PATH, base).toString();
  } catch {
    return undefined;
  }
}

/** Fetches and reads the archive metadata, returning why it is unusable. */
async function readArchiveMetadata(
  metadataUrl: string,
  fetchImpl: typeof fetch,
): Promise<string | undefined> {
  try {
    const response = await fetchImpl(metadataUrl);
    if (!response.ok) return `it returned HTTP ${response.status}`;
    const body: unknown = await response.json();
    const version =
      typeof body === 'object' && body !== null
        ? (body as { version?: unknown }).version
        : undefined;
    return version === 1 ? undefined : 'the metadata does not declare "version": 1';
  } catch {
    return 'it could not be read';
  }
}

/**
 * Verifies each validator's history archive by fetching its root metadata.
 *
 * A network failure is reported rather than thrown, so one unreachable archive
 * never takes down the rest of the run. The rule can be switched off like any
 * other.
 */
export async function checkHistoryArchive(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: { rules?: RuleOverrides } = {},
): Promise<Diagnostic[]> {
  const severity = severityFor(UNREACHABLE_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  for (const [index, entry] of validatorsOf(doc).entries()) {
    // A value the format rule already rejected is not worth a request.
    const history = entry.HISTORY;
    if (typeof history !== 'string') continue;

    const metadataUrl = metadataUrlFor(history);
    if (metadataUrl === undefined) continue;

    const problem = await readArchiveMetadata(metadataUrl, fetchImpl);
    if (problem === undefined) continue;

    const path = `VALIDATORS[${index}].HISTORY`;
    diagnostics.push({
      rule: UNREACHABLE_RULE,
      severity,
      category: 'validators',
      message: `${path} does not serve ${METADATA_PATH}: ${problem}`,
      path,
      helpUri: specUrl('validator-information'),
      suggestion: 'Publish the archive metadata at the archive root, or remove the HISTORY entry.',
    });
  }

  return diagnostics;
}

/** Rules covering the `[[VALIDATORS]].HISTORY` archive URL (SEP-20). */
export const historyUrlRules: Rule[] = [
  {
    id: INVALID_URL_RULE,
    category: 'validators',
    severity: 'error',
    description: 'HISTORY must be a well-formed archive URL with a valid {0} template',
    run(ctx) {
      validatorsOf(ctx.doc).forEach((entry, index) => {
        const history = entry.HISTORY;
        if (history === undefined) return;

        const path = `VALIDATORS[${index}].HISTORY`;
        if (typeof history !== 'string') {
          ctx.report({
            rule: INVALID_URL_RULE,
            category: 'validators',
            message: `${path} must be a string`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('validator-information'),
            suggestion: SUGGESTION,
          });
          return;
        }

        const problem = historyUrlProblem(history);
        if (problem === undefined) return;
        ctx.report({
          rule: INVALID_URL_RULE,
          category: 'validators',
          message: `${path} ${problem}`,
          path,
          position: ctx.locate(path),
          helpUri: specUrl('validator-information'),
          suggestion: SUGGESTION,
        });
      });
    },
  },
  {
    id: UNREACHABLE_RULE,
    category: 'validators',
    severity: 'error',
    description: 'History archives must serve .well-known/stellar-history.json with "version": 1',
    // Async by nature: `--check-network` runs `checkHistoryArchive`, which emits
    // this diagnostic. Registering it keeps `--off`, `--list-rules`, and SARIF
    // aware of it.
    run() {},
  },
];
