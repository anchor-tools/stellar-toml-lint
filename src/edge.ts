/**
 * Edge runtime entry point — `@anchor-tools/stellar-toml-lint/edge`.
 *
 * Zero Node.js built-ins: no `node:fs`, `node:crypto`, `node:http`, nothing.
 * Network transport is the runtime's `fetch` (the same `fetch` the linter
 * core already uses), and hashing is the Web Cryptography API
 * (`crypto.subtle`). This loads in Cloudflare Workers, Vercel Edge, Fastly
 * Compute@Edge, Deno, and any other WinterCG-compatible runtime.
 *
 * ```ts
 * import { lintEdge } from 'stellar-toml-lint/edge';
 *
 * const result = await lintEdge(tomlContent, {
 *   domain: 'example.com',
 *   strict: true,
 *   expectedContentDigest: 'sha256-hex-...',
 * });
 * if (!result.ok) console.error(result.diagnostics);
 * ```
 */

import { lint } from './lint.js';
import type { LintOptions, LintResult, RuleOverrides } from './types.js';

export interface EdgeOptions {
  /** Serving domain, enabling same-origin checks (`ORG_URL`, etc.). */
  domain?: string;
  /** Treat warnings as errors. */
  strict?: boolean;
  /** Per-rule severity overrides. */
  rules?: RuleOverrides;
  /**
   * Expected SHA-256 (hex) of `tomlContent`. When set, the run is aborted
   * with an `edge/content-digest-mismatch` diagnostic unless the content's
   * digest matches — an integrity gate for deployed configuration, computed
   * with `crypto.subtle` instead of `node:crypto`.
   */
  expectedContentDigest?: string;
}

/**
 * Lints a `stellar.toml` string using only Web-interoperable APIs.
 *
 * Resolves with a {@link LintResult} like every other entry point. When
 * `expectedContentDigest` is set and does not match the content, the result
 * carries a single `edge/content-digest-mismatch` error and nothing else is
 * linted.
 */
export async function lintEdge(
  tomlContent: string,
  options: EdgeOptions = {},
): Promise<LintResult> {
  if (options.expectedContentDigest !== undefined) {
    const actual = await sha256Hex(tomlContent);
    if (actual !== options.expectedContentDigest) {
      return {
        diagnostics: [
          {
            rule: 'edge/content-digest-mismatch',
            severity: 'error',
            category: 'file',
            message: `stellar.toml content digest (${actual}) does not match the expected digest (${options.expectedContentDigest}).`,
          },
        ],
        ok: false,
        counts: { error: 1, warning: 0, info: 0 },
      };
    }
  }

  const lintOptions: LintOptions = {
    domain: options.domain,
    strict: options.strict,
    rules: options.rules,
  };
  return lint(tomlContent, lintOptions);
}

/** SHA-256 of `input` as lowercase hex, via the Web Cryptography API. */
async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}
