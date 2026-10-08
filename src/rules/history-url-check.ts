import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';
import { verifyHistoryArchive } from '../validators/history.js';

const INVALID_URL_RULE = 'validators/invalid-history-url';
const UNREACHABLE_RULE = 'validators/history-archive-unreachable';
const MALFORMED_RULE = 'validators/history-archive-malformed';
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

/** Returns why a HISTORY value is malformed, or undefined when it is usable. */
function historyUrlProblem(raw: string): string | undefined {
  for (const token of raw.match(TEMPLATE) ?? []) {
    if (token !== '{0}') return `uses the template ${token}, but only {0} is supported`;
  }
  if (/[{}]/.test(raw.replace(TEMPLATE, ''))) return 'has unbalanced {0} template braces';

  const schemeEnd = raw.indexOf('://');
  if (schemeEnd !== -1) {
    const authority = raw.slice(schemeEnd + 3).split(/[/?#]/)[0] ?? '';
    if (authority.includes('{')) return 'must not use a template parameter in the host';
  }

  try {
    const url = new URL(raw.replace(TEMPLATE, '0'));
    if (!/^[a-z][a-z0-9+.-]*:$/i.test(url.protocol)) return 'has no URI scheme';
    if (!url.hostname) return 'has no host';
  } catch {
    return 'is not an absolute URL';
  }
  return undefined;
}

/** Verify every declared history archive and return stable diagnostics. */
export async function checkHistoryArchive(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: { rules?: RuleOverrides } = {},
): Promise<Diagnostic[]> {
  const unreachableSeverity = severityFor(UNREACHABLE_RULE, 'error', options.rules);
  const malformedSeverity = severityFor(MALFORMED_RULE, 'error', options.rules);
  if (unreachableSeverity === undefined && malformedSeverity === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  for (const [index, entry] of validatorsOf(doc).entries()) {
    const history = entry.HISTORY;
    if (typeof history !== 'string' || historyUrlProblem(history) !== undefined) continue;

    const result = await verifyHistoryArchive(history, fetchImpl);
    if (result.status === 'valid') continue;
    const rule = result.status === 'unreachable' ? UNREACHABLE_RULE : MALFORMED_RULE;
    const severity = result.status === 'unreachable' ? unreachableSeverity : malformedSeverity;
    if (severity === undefined) continue;

    const path = `VALIDATORS[${index}].HISTORY`;
    diagnostics.push({
      rule,
      severity,
      category: 'validators',
      message: `${path} does not publish a valid History Archive State file: ${result.message}`,
      path,
      helpUri: specUrl('validator-information'),
      suggestion:
        'Publish a valid stellar-history.json at the archive root, or remove the HISTORY entry.',
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
    description: 'History archives must serve their HAS file with HTTP 200',
    run() {},
  },
  {
    id: MALFORMED_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'History Archive State JSON must include a valid version, server, and currentLedger',
    run() {},
  },
];
