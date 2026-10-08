import type { Rule } from '../types.js';
import { specUrl } from '../spec.js';
import { documentationOf } from './documentation.js';

/**
 * SEP-1's `ORG_TELEGRAM` names the organization's Telegram community handle or link.
 * Valid Telegram usernames consist of 5–32 alphanumeric characters and underscores.
 * Accepts bare handle (e.g. `example_anchor`), leading `@` (`@example_anchor`),
 * or Telegram URLs (`https://t.me/example_anchor`, `t.me/example_anchor`).
 */

const MIN_HANDLE_LENGTH = 5;
const MAX_HANDLE_LENGTH = 32;

/**
 * Unwraps `@handle` or `https://t.me/<handle>` profile URL to its bare handle.
 */
function normalize(value: string): { handle: string } | { problem: string } {
  let val = value.trim();
  if (val.startsWith('@')) {
    val = val.slice(1);
    return val === '' ? { problem: 'is empty' } : { handle: val };
  }

  if (!val.includes('/')) return { handle: val };

  let rawUrl = val;
  if (!/^https?:\/\//i.test(rawUrl)) {
    rawUrl = `https://${rawUrl}`;
  }

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { problem: 'is not a valid Telegram handle or profile URL' };
  }

  const host = url.hostname.toLowerCase().replace(/^www\./, '');
  if (host !== 't.me' && host !== 'telegram.me') {
    return { problem: 'must be a https://t.me/<handle> profile URL or Telegram handle' };
  }

  if (url.search !== '' || url.hash !== '') {
    return { problem: 'must be a plain Telegram profile URL, without a query or fragment' };
  }

  const handle = url.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (handle === '' || handle.includes('/')) {
    return { problem: 'is not a valid Telegram handle or profile URL' };
  }

  return { handle: handle.startsWith('@') ? handle.slice(1) : handle };
}

function handleProblem(handle: string): string | undefined {
  if (handle.length === 0) return 'is empty';
  if (handle.length < MIN_HANDLE_LENGTH) {
    return `is shorter than Telegram's ${MIN_HANDLE_LENGTH}-character limit`;
  }
  if (handle.length > MAX_HANDLE_LENGTH) {
    return `is longer than Telegram's ${MAX_HANDLE_LENGTH}-character limit`;
  }
  if (!/^[A-Za-z0-9_]+$/.test(handle)) {
    return 'contains characters Telegram does not allow';
  }
  return undefined;
}

/**
 * Returns why `ORG_TELEGRAM` is not a usable value, or `undefined` when it is fine.
 */
export function telegramHandleProblem(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed === '') return 'is empty';

  const normalized = normalize(trimmed);
  if ('problem' in normalized) return normalized.problem;

  return handleProblem(normalized.handle);
}

/** Rules covering `[DOCUMENTATION].ORG_TELEGRAM`. */
export const telegramHandleRules: Rule[] = [
  {
    id: 'general/invalid-telegram-handle',
    category: 'general',
    severity: 'warning',
    description: 'ORG_TELEGRAM must be a valid Telegram handle or profile URL',
    run(ctx) {
      const value = documentationOf(ctx.doc)?.ORG_TELEGRAM;
      if (value === undefined || typeof value !== 'string') return;

      const problem = telegramHandleProblem(value);
      if (problem === undefined) return;

      ctx.report({
        rule: 'general/invalid-telegram-handle',
        category: 'general',
        message: `DOCUMENTATION.ORG_TELEGRAM ${problem}`,
        path: 'DOCUMENTATION.ORG_TELEGRAM',
        position: ctx.locate('DOCUMENTATION.ORG_TELEGRAM'),
        helpUri: specUrl('organization-documentation'),
        suggestion:
          'Use a Telegram handle (5–32 alphanumeric characters / underscores), e.g. "example_anchor" or "https://t.me/example_anchor".',
      });
    },
  },
];
