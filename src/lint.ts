import { parse, TomlError } from 'smol-toml';
import type {
  Diagnostic,
  LintOptions,
  LintResult,
  Position,
  RuleContext,
  RuleOverrides,
  Severity,
  TlsSession,
} from './types.js';
import { allRules } from './rules/index.js';
import { securityRuleIds } from './rules/security.js';
import { SourceIndex } from './source-index.js';
import { MAX_FILE_BYTES, isString } from './predicates.js';
import { specUrl } from './spec.js';
import { probeTls, type TlsProbe } from './tls.js';
import { checkOrgUrl } from './rules/org-url-check.js';

/** Severity ordering used for sorting and for `--max-warnings` style counts. */
const SEVERITY_RANK: Record<Severity, number> = { error: 0, warning: 1, info: 2 };

/**
 * The real transport, captured so {@link lintDomain} can tell whether the
 * caller replaced it. The parameter of the same name shadows the global.
 */
const globalFetch: typeof fetch = fetch;

/**
 * Lints a `stellar.toml` source string against SEP-1.
 *
 * A syntax error short-circuits the run: with no parsed document there is
 * nothing for the semantic rules to inspect, and cascading errors from a
 * half-parsed file would bury the one diagnostic that matters.
 */
export function lint(source: string, options: LintOptions = {}): LintResult {
  const diagnostics: Diagnostic[] = [];

  // A byte order mark makes some TOML parsers and HTTP clients choke, and it is
  // invisible in an editor — worth calling out explicitly.
  if (source.charCodeAt(0) === 0xfeff) {
    diagnostics.push({
      rule: 'file/encoding',
      severity: 'error',
      category: 'file',
      message: 'File starts with a UTF-8 byte order mark, which some TOML parsers reject',
      position: { line: 1, column: 1 },
      helpUri: specUrl('specification'),
      suggestion: 'Re-save the file as UTF-8 without a BOM.',
    });
    source = source.slice(1);
  }

  let parsed: Record<string, unknown> | undefined;
  try {
    const result = parse(source);
    parsed = result as Record<string, unknown>;
  } catch (error) {
    diagnostics.push(parseDiagnostic(error, source));
    return finalize(diagnostics, options, undefined);
  }

  const index = new SourceIndex(source);
  const overrides = options.rules ?? {};

  for (const rule of allRules) {
    if (overrides[rule.id] === 'off') continue;

    const ctx: RuleContext = {
      doc: parsed,
      source,
      options,
      locate: (path: string): Position | undefined => index.get(path),
      report: (d) => {
        const override = overrides[d.rule];
        const severity: Severity =
          override && override !== 'off' ? override : (d.severity ?? rule.severity);
        diagnostics.push({ ...d, severity });
      },
    };

    try {
      rule.run(ctx);
    } catch (error) {
      // A crashing rule must not take down the whole run — report it and move
      // on, so the remaining rules still produce useful output.
      diagnostics.push({
        rule: 'internal/rule-error',
        severity: 'warning',
        category: 'file',
        message: `Rule ${rule.id} failed to run: ${errorMessage(error)}`,
        helpUri: 'https://github.com/anchor-tools/stellar-toml-lint/issues',
        suggestion: 'Please report this file (with secrets removed) as a bug.',
      });
    }
  }

  return finalize(diagnostics, options, parsed);
}

/**
 * Lints the file served at `https://<domain>/.well-known/stellar.toml`,
 * additionally checking the HTTP-level requirements SEP-1 imposes: CORS,
 * content type, size, and the security of the TLS session itself.
 *
 * `tlsProbe` is only consulted for the default transport. Once a caller injects
 * its own `fetchImpl` the transport is theirs to describe, and a probe aimed at
 * the same host would say nothing about the connection they made — so tests and
 * embedders inject a probe when they want the audit, and otherwise it is
 * skipped rather than guessed at.
 */
export async function lintDomain(
  domain: string,
  options: LintOptions = {},
  fetchImpl: typeof fetch = globalFetch,
  tlsProbe?: TlsProbe,
): Promise<LintResult> {
  const host = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const url = `https://${host}/.well-known/stellar.toml`;
  const diagnostics: Diagnostic[] = [];

  let response: Response;
  try {
    // Send an Origin header so the request looks like the browser-based wallet
    // this check exists to protect. Many servers (and CDNs) only emit
    // Access-Control-Allow-Origin when Origin is present, so probing without
    // one reports a CORS failure on correctly-configured hosts.
    response = await fetchImpl(url, {
      redirect: 'follow',
      headers: { Origin: 'https://stellar-toml-lint.invalid' },
    });
  } catch (error) {
    return finalize(
      [
        {
          rule: 'network/unreachable',
          severity: 'error',
          category: 'network',
          message: `Could not fetch ${url}: ${errorMessage(error)}`,
          helpUri: specUrl('specification'),
          suggestion: 'Confirm the file is published and that DNS and TLS resolve correctly.',
        },
      ],
      options,
      undefined,
    );
  }

  if (!response.ok) {
    const failed: Diagnostic[] = [
      {
        rule: 'network/unreachable',
        severity: 'error',
        category: 'network',
        message: `${url} returned HTTP ${response.status}`,
        helpUri: specUrl('specification'),
        suggestion: 'SEP-1 requires the file at exactly /.well-known/stellar.toml.',
      },
    ];

    // A 404 is often a deploy mistake rather than a missing file: the anchor
    // published stellar.toml at the site root. One bounded probe of that path
    // turns a dead-end status code into a fix the maintainer can act on.
    if (response.status === 404) {
      const rootUrl = `https://${host}/stellar.toml`;
      try {
        const root = await fetchImpl(rootUrl, {
          redirect: 'follow',
          headers: { Origin: 'https://stellar-toml-lint.invalid' },
        });
        if (root.ok) {
          failed.push({
            rule: 'network/wrong-path',
            severity: 'error',
            category: 'network',
            message: `Found stellar.toml at ${rootUrl}, but SEP-1 requires /.well-known/stellar.toml`,
            helpUri: specUrl('specification'),
            suggestion:
              'Move the file to /.well-known/stellar.toml — wallets only discover it there.',
          });
        }
      } catch {
        // The root probe is a hint, not a requirement: a transport failure
        // here leaves today's network/unreachable behaviour unchanged.
      }
    }

    return finalize(failed, options, undefined);
  }

  // Anchors sign SEP-10 challenges over this same host, so deprecated protocol
  // versions and weak cipher suites matter even when the file is flawless.
  const tls = await observeTls(url, fetchImpl, tlsProbe, options.rules);

  // CORS is the single most common deployment failure: the file is valid, but
  // browser-based wallets cannot read it.
  const cors = response.headers.get('access-control-allow-origin');
  if (cors !== '*') {
    diagnostics.push({
      rule: 'network/cors',
      severity: 'error',
      category: 'network',
      message: cors
        ? `Access-Control-Allow-Origin is "${cors}", but SEP-1 requires "*"`
        : 'Access-Control-Allow-Origin header is missing, so browser clients cannot read the file',
      helpUri: specUrl('specification'),
      suggestion: 'Set `Access-Control-Allow-Origin: *` on /.well-known/stellar.toml.',
    });
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('text/plain')) {
    diagnostics.push({
      rule: 'network/content-type',
      severity: 'warning',
      category: 'network',
      message: contentType
        ? `Content-Type is "${contentType}"; SEP-1 recommends "text/plain"`
        : 'Content-Type header is missing; SEP-1 recommends "text/plain"',
      helpUri: specUrl('specification'),
      suggestion: 'Serving text/plain lets browsers render the file instead of downloading it.',
    });
  }

  const source = await response.text();
  if (Buffer.byteLength(source, 'utf8') > MAX_FILE_BYTES) {
    diagnostics.push({
      rule: 'file/max-size',
      severity: 'error',
      category: 'file',
      message: 'Served file exceeds the 100KB maximum',
      helpUri: specUrl('specification'),
    });
  }

  const fileResult = lint(source, {
    ...options,
    domain: options.domain ?? host,
    ...(tls ? { tls } : {}),
  });

  // The identity anchor itself must also be alive: probe ORG_URL so a dead
  // endpoint is caught here rather than by the next wallet that vetts the
  // anchor. Same transport as the file fetch, so tests can stub both.
  let orgUrlDiagnostics: Diagnostic[] = [];
  if (fileResult.parsed) {
    orgUrlDiagnostics = await checkOrgUrl(fileResult.parsed, fetchImpl, {
      rules: options.rules,
    });
  }

  return finalize(
    [...diagnostics, ...fileResult.diagnostics, ...orgUrlDiagnostics],
    options,
    fileResult.parsed,
  );
}

/**
 * Measures the TLS session the host negotiates, or `undefined` when there is
 * nothing to measure.
 *
 * Nothing is measured when every rule that consumes the session is switched off
 * (so `--off security/...` costs no extra connection), or when the caller
 * supplied a transport this function did not open.
 */
async function observeTls(
  url: string,
  fetchImpl: typeof fetch,
  tlsProbe: TlsProbe | undefined,
  overrides: RuleOverrides | undefined,
): Promise<TlsSession | undefined> {
  if (securityRuleIds.every((id) => overrides?.[id] === 'off')) return undefined;

  const probe = tlsProbe ?? (fetchImpl === globalFetch ? probeTls : undefined);
  if (!probe) return undefined;

  try {
    const target = new URL(url);
    const port = target.port ? Number(target.port) : 443;
    return await probe(target.hostname, port);
  } catch {
    // The audit is advisory: a probe that cannot complete is not a finding.
    return undefined;
  }
}

/** Converts a `smol-toml` parse failure into a positioned diagnostic. */
function parseDiagnostic(error: unknown, source: string): Diagnostic {
  const position =
    error instanceof TomlError
      ? { line: error.line, column: error.column }
      : positionFromMessage(error, source);

  return {
    rule: 'file/parse',
    severity: 'error',
    category: 'file',
    message: `Invalid TOML: ${cleanParseMessage(error)}`,
    position,
    helpUri: 'https://toml.io/en/v1.0.0',
    suggestion: 'Fix the syntax error — no other checks can run until the file parses.',
  };
}

/**
 * `smol-toml` throws a plain `Error` in some builds, but still attaches `line`
 * and `column`. Read them defensively rather than losing the position.
 */
function positionFromMessage(error: unknown, source: string): Position | undefined {
  if (typeof error === 'object' && error !== null) {
    const candidate = error as { line?: unknown; column?: unknown };
    if (typeof candidate.line === 'number' && typeof candidate.column === 'number') {
      return { line: candidate.line, column: candidate.column };
    }
  }
  return source.length > 0 ? { line: 1, column: 1 } : undefined;
}

/** Strips the code frame that `smol-toml` appends to its message. */
function cleanParseMessage(error: unknown): string {
  const message = errorMessage(error);
  return (
    message
      .split('\n')[0]
      ?.replace(/^Invalid TOML document:\s*/i, '')
      .trim() || 'could not parse the file'
  );
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return isString(error) ? error : String(error);
}

export function finalize(
  diagnostics: Diagnostic[],
  options: LintOptions,
  parsed: Record<string, unknown> | undefined,
): LintResult {
  const sorted = [...diagnostics].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    const lineA = a.position?.line ?? Number.MAX_SAFE_INTEGER;
    const lineB = b.position?.line ?? Number.MAX_SAFE_INTEGER;
    if (lineA !== lineB) return lineA - lineB;
    const colA = a.position?.column ?? 0;
    const colB = b.position?.column ?? 0;
    if (colA !== colB) return colA - colB;
    return a.rule.localeCompare(b.rule);
  });

  const counts: Record<Severity, number> = { error: 0, warning: 0, info: 0 };
  for (const d of sorted) counts[d.severity]++;

  const ok = options.strict ? counts.error === 0 && counts.warning === 0 : counts.error === 0;

  return { diagnostics: sorted, ok, counts, parsed };
}
