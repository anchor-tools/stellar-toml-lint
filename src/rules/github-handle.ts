import type { Rule } from '../types.js';
import { specUrl } from '../spec.js';
import { documentationOf } from './documentation.js';

/**
 * SEP-1's `ORG_GITHUB` names the organization's GitHub account. Operators
 * frequently paste a full profile URL and just as frequently mistype the handle
 * — a leading or trailing hyphen, doubled hyphens, or characters GitHub does
 * not permit — so validate the shape and normalize both accepted forms.
 *
 * The GitHub username rules enforced here are the ones GitHub documents:
 * alphanumeric characters or single hyphens, no leading or trailing hyphen,
 * at most 39 characters.
 */

const MAX_USERNAME_LENGTH = 39;

/**
 * Returns why `username` is not a valid GitHub username, or `undefined` when it
 * is. Expects the bare handle, with any profile URL already unwrapped.
 */
function usernameProblem(username: string): string | undefined {
  if (username.length === 0) return 'is empty';
  if (username.length > MAX_USERNAME_LENGTH) {
    return `is longer than GitHub's ${MAX_USERNAME_LENGTH}-character limit`;
  }
  if (!/^[a-zA-Z0-9-]+$/.test(username)) {
    return 'contains characters GitHub does not allow';
  }
  if (username.startsWith('-') || username.endsWith('-')) {
    return 'must not start or end with a hyphen';
  }
  if (username.includes('--')) return 'must not contain consecutive hyphens';
  return undefined;
}

/**
 * Unwraps a `https://github.com/<username>` profile URL to its bare handle, or
 * returns the value unchanged when it is already a bare handle.
 *
 * A value that looks like a URL but is not a plain github.com profile URL gets a
 * problem string rather than being treated as a (nonsensical) handle.
 */
function handleOf(value: string): { handle: string } | { problem: string } {
  if (!value.includes('/')) return { handle: value };

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { problem: 'is not a valid GitHub username or profile URL' };
  }
  if (url.protocol !== 'https:' || !/^(www\.)?github\.com$/i.test(url.hostname)) {
    return { problem: 'must be a https://github.com/<username> profile URL' };
  }
  if (url.search !== '' || url.hash !== '') {
    return { problem: 'must be a plain github.com profile URL, without a query or fragment' };
  }

  const handle = url.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (handle.includes('/'))
    return { problem: 'must be a github.com profile URL, not a repository' };
  return { handle };
}

/**
 * Returns why `ORG_GITHUB` is not a usable value, or `undefined` when it is.
 *
 * Accepts both forms SEP-1 permits in practice: the bare handle (`stellar`) and
 * the canonical profile URL (`https://github.com/stellar`).
 */
export function githubHandleProblem(value: string): string | undefined {
  const unwrapped = handleOf(value.trim());
  if ('problem' in unwrapped) return unwrapped.problem;
  return usernameProblem(unwrapped.handle);
}

/** Rules covering `[DOCUMENTATION].ORG_GITHUB`. */
export const githubHandleRules: Rule[] = [
  {
    id: 'general/invalid-github-handle',
    category: 'general',
    severity: 'warning',
    description: 'ORG_GITHUB must be a valid GitHub username or profile URL',
    run(ctx) {
      const value = documentationOf(ctx.doc)?.ORG_GITHUB;
      if (value === undefined || typeof value !== 'string') return;

      const problem = githubHandleProblem(value);
      if (problem === undefined) return;

      ctx.report({
        rule: 'general/invalid-github-handle',
        category: 'general',
        message: `DOCUMENTATION.ORG_GITHUB ${problem}`,
        path: 'DOCUMENTATION.ORG_GITHUB',
        position: ctx.locate('DOCUMENTATION.ORG_GITHUB'),
        helpUri: specUrl('organization-documentation'),
        suggestion:
          'Use the GitHub account name, e.g. "stellar", or its profile URL, e.g. "https://github.com/stellar".',
      });
    },
  },
];
