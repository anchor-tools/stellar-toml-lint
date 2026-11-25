/**
 * Browser entry point — `stellar-toml-lint/browser`.
 *
 * The linter core was already free of Node built-ins except for the CLI
 * (`node:fs/promises`, `node:path`, `node:process`) and the TLS audit
 * (`node:tls`, now imported lazily). This entry point replaces the two Node
 * dependencies a browser cannot have:
 *
 * | Capability        | In the browser                                                   |
 * | ----------------- | ---------------------------------------------------------------- |
 * | Parsing, rules    | unchanged — the same {@link lint} the CLI calls                   |
 * | Filesystem        | a virtual, in-memory one ({@link createVirtualFileSystem})        |
 * | Network           | `globalThis.fetch`, so CORS rules report what a wallet would hit  |
 * | TLS session audit | impossible — the probe reports an unknown session, never a guess  |
 *
 * The TLS point is worth stating plainly rather than hiding: a page cannot see
 * the negotiated protocol or cipher suite, so `security/*` goes quiet instead of
 * inventing a finding. `--check-network`'s account lookups still work, because
 * they are ordinary `fetch` calls.
 */

import { lint, lintDomain } from './lint.js';
import { UNKNOWN_TLS_SESSION } from './tls.js';
import type { LintOptions, LintResult } from './types.js';

/** What this entry point can and cannot do, for callers that branch on it. */
export const browserCapabilities = {
  filesystem: 'virtual',
  network: true,
  tlsAudit: false,
} as const;

/** An in-memory file store, standing in for `node:fs`. */
export interface VirtualFileSystem {
  read(path: string): string | undefined;
  has(path: string): boolean;
  list(): string[];
}

/** Builds a {@link VirtualFileSystem} from a plain path → content map. */
export function createVirtualFileSystem(files: Record<string, string>): VirtualFileSystem {
  // Copied so later edits to the caller's object cannot change a lint run
  // halfway through it.
  const entries = new Map(Object.entries(files));

  return {
    read: (path) => entries.get(path),
    has: (path) => entries.has(path),
    list: () => [...entries.keys()],
  };
}

export interface BrowserLintOptions extends Omit<LintOptions, 'tls'> {
  /** Virtual files for the path-based helpers. */
  files?: VirtualFileSystem;
  /** Injected for tests and workers; defaults to the page's `fetch`. */
  fetchImpl?: typeof fetch;
}

/** A file with no content to lint is a bug in the caller, not a diagnostic. */
function requireFile(path: string, files: VirtualFileSystem | undefined): string {
  const content = files?.read(path);
  if (content === undefined) {
    const known = files?.list() ?? [];
    const suffix =
      known.length > 0 ? ` Known files: ${known.join(', ')}.` : ' The file system is empty.';
    throw new Error(`No content for "${path}" in the virtual file system.${suffix}`);
  }
  return content;
}

/**
 * Strips the browser-only keys so the rest can be handed to the core linter.
 *
 * Written as a copy-then-delete rather than an allow-list so a future option
 * added to `LintOptions` is forwarded automatically instead of being silently
 * dropped — the caller's own object is never touched.
 */
function lintOptionsOf(options: BrowserLintOptions): LintOptions {
  const lintOptions: LintOptions = { ...options };
  delete (lintOptions as Partial<BrowserLintOptions>).files;
  delete (lintOptions as Partial<BrowserLintOptions>).fetchImpl;
  return lintOptions;
}

/**
 * Lints a `stellar.toml` held in memory. Asynchronous to match the rest of this
 * entry point, so callers can await a single shape whether the source came from
 * a textarea, a `fetch`, or a virtual file.
 */
export async function lintBrowser(
  content: string,
  options: BrowserLintOptions = {},
): Promise<LintResult> {
  return lint(content, lintOptionsOf(options));
}

/** Lints a file from the virtual filesystem; throws when the path is unknown. */
export async function lintBrowserFile(
  path: string,
  options: BrowserLintOptions = {},
): Promise<LintResult> {
  return lintBrowser(requireFile(path, options.files), options);
}

/**
 * Lints several virtual files as one run, in the order asked for — the shape the
 * CLI's reporters already accept, so a browser UI can reuse them.
 */
export async function lintBrowserRun(
  paths: string[],
  options: BrowserLintOptions = {},
): Promise<{ name: string; result: LintResult }[]> {
  const run: { name: string; result: LintResult }[] = [];
  for (const path of paths) {
    run.push({ name: path, result: await lintBrowserFile(path, options) });
  }
  return run;
}

/**
 * Fetches `https://<domain>/.well-known/stellar.toml` with the page's own
 * `fetch` and lints it, keeping the CORS, content-type and ORG_URL checks.
 *
 * CORS applies to this request exactly as it would to a wallet, so a host that
 * does not send `Access-Control-Allow-Origin: *` produces the same
 * `network/cors` finding here as it would in the browser it is meant for.
 */
export async function lintBrowserDomain(
  domain: string,
  options: BrowserLintOptions = {},
): Promise<LintResult> {
  const send = options.fetchImpl ?? globalThis.fetch;

  return lintDomain(
    domain,
    lintOptionsOf(options),
    send,
    // A browser cannot open a socket, so the TLS audit is reported as not
    // observed: the security rules stay silent rather than inventing a session.
    async () => UNKNOWN_TLS_SESSION,
  );
}
