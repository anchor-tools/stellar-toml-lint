import type { Rule } from '../types.js';
import { specUrl } from '../spec.js';
import { documentationOf } from './documentation.js';

/**
 * SEP-1's `ORG_TWITTER` names the organization's official Twitter/X account as
 * a bare handle. Operators paste `@stellarorg` or a whole profile URL
 * (`https://x.com/stellarorg`) just as often, and clients that concatenate
 * `https://twitter.com/` + the field's value then resolve to a 404 — so the
 * shape is validated and both pasted forms are normalized to the handle.
 *
 * The rule owns its field outright, the way `general/invalid-github-handle`
 * owns `ORG_GITHUB`: `documentation/social-handles` deliberately no longer
 * reports `ORG_TWITTER`, so one problem produces exactly one diagnostic.
 *
 * The handle grammar is Twitter/X's own: 1 to 15 characters drawn from
 * letters, digits, and underscores (`^[A-Za-z0-9_]{1,15}$`).
 */

const MAX_HANDLE_LENGTH = 15;

/** Profile hosts a value may legitimately wrap. */
const TWITTER_HOST_PATTERN = /^(www\.|mobile\.)?(twitter|x)\.com$/i;

const HANDLE_EXAMPLE = 'Use the bare handle, e.g. "exampleanchor".';

/**
 * Returns why `handle` is not a valid Twitter/X handle, or `undefined` when it
 * is. Expects the bare handle, with any `@` or profile URL already unwrapped.
 */
function handleProblem(handle: string): string | undefined {
  if (handle.length === 0) return 'is empty';
  if (handle.length > MAX_HANDLE_LENGTH) {
    return `is longer than Twitter/X's ${MAX_HANDLE_LENGTH}-character limit`;
  }
  if (!/^[A-Za-z0-9_]+$/.test(handle)) {
    return 'contains characters Twitter/X does not allow';
  }
  return undefined;
}

/**
 * Unwraps a `@handle` or `https://twitter.com/<handle>` /
 * `https://x.com/<handle>` profile URL to its bare handle, or reports why the
 * value cannot be read as one. A value already bare comes back unchanged.
 */
function normalize(value: string): { handle: string } | { problem: string } {
  if (value.startsWith('@')) {
    const handle = value.slice(1);
    return handle === '' ? { problem: 'is empty' } : { handle };
  }

  if (!value.includes('/')) return { handle: value };

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { problem: 'is not a valid Twitter/X handle or profile URL' };
  }
  if (url.protocol !== 'https:' || !TWITTER_HOST_PATTERN.test(url.hostname)) {
    return {
      problem: 'must be a https://twitter.com/<handle> or https://x.com/<handle> profile URL',
    };
  }
  if (url.search !== '' || url.hash !== '') {
    return { problem: 'must be a plain profile URL, without a query or fragment' };
  }

  const handle = url.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (handle === '' || handle.includes('/')) {
    return { problem: 'is not a valid Twitter/X handle or profile URL' };
  }
  return { handle };
}

interface Verdict {
  problem: string;
  suggestion: string;
  /** The corrected value, present only when it would pass this rule itself. */
  fix?: string;
}

/** How a value that wrapped the handle in `@` or a URL should read instead. */
function formVerdict(value: string): Verdict {
  const normalized = normalize(value);
  if ('problem' in normalized) {
    return { problem: normalized.problem, suggestion: HANDLE_EXAMPLE };
  }

  const problem = value.startsWith('@')
    ? 'must not include a leading @'
    : 'must be a bare handle, not a URL';
  const suggestion = `Use the bare handle, e.g. "${normalized.handle}".`;

  // The fix is offered only when the unwrapped handle is itself valid, so an
  // applied fix can never leave a value this rule would flag again.
  if (handleProblem(normalized.handle) === undefined) {
    return { problem, suggestion, fix: normalized.handle };
  }
  return { problem, suggestion };
}

/** The verdict for one `ORG_TWITTER` value, or `undefined` when it is fine. */
function verdictOf(value: string): Verdict | undefined {
  const trimmed = value.trim();
  if (trimmed === '') {
    return { problem: 'is empty', suggestion: HANDLE_EXAMPLE };
  }

  if (trimmed.startsWith('@') || trimmed.includes('/')) {
    return formVerdict(trimmed);
  }

  const problem = handleProblem(trimmed);
  if (problem === undefined) return undefined;

  return {
    problem,
    suggestion:
      problem === 'contains characters Twitter/X does not allow'
        ? 'Use letters, digits, and underscores only, e.g. "exampleanchor".'
        : `Twitter/X handles are at most ${MAX_HANDLE_LENGTH} characters — shorten it or pick another handle.`,
  };
}

/**
 * Returns why `ORG_TWITTER` is not a usable value, or `undefined` when it is.
 *
 * Accepts the bare handle (`stellarorg`); `@handle` and profile URLs are
 * reported with the handle to use instead.
 */
export function twitterHandleProblem(value: string): string | undefined {
  return verdictOf(value)?.problem;
}

/** Rules covering `[DOCUMENTATION].ORG_TWITTER`. */
export const twitterHandleRules: Rule[] = [
  {
    id: 'general/invalid-twitter-handle',
    category: 'general',
    severity: 'warning',
    description: 'ORG_TWITTER must be a bare Twitter/X handle, without @ or a URL',
    run(ctx) {
      const value = documentationOf(ctx.doc)?.ORG_TWITTER;
      if (value === undefined || typeof value !== 'string') return;

      const verdict = verdictOf(value);
      if (verdict === undefined) return;

      ctx.report({
        rule: 'general/invalid-twitter-handle',
        category: 'general',
        message: `DOCUMENTATION.ORG_TWITTER ${verdict.problem}`,
        path: 'DOCUMENTATION.ORG_TWITTER',
        position: ctx.locate('DOCUMENTATION.ORG_TWITTER'),
        helpUri: specUrl('organization-documentation'),
        suggestion: verdict.suggestion,
        ...(verdict.fix !== undefined ? { fix: { value: verdict.fix } } : {}),
      });
    },
  },
];
