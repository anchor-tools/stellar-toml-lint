/**
 * Core types for stellar-toml-lint.
 *
 * A lint run turns a `stellar.toml` source string into a flat list of
 * {@link Diagnostic}s. Everything else in this package is either a rule that
 * produces diagnostics or a reporter that formats them.
 */

/** How much a violation matters. Only `error` affects the default exit code. */
export type Severity = 'error' | 'warning' | 'info';

/** Which part of SEP-1 a rule covers. Used for grouping in reports. */
export type RuleCategory =
  'file' | 'general' | 'documentation' | 'principals' | 'currencies' | 'validators' | 'network';

/** A 1-based position in the source file. */
export interface Position {
  line: number;
  column: number;
}

/** One rule violation at one place in the file. */
export interface Diagnostic {
  /** Stable machine-readable id, e.g. `currencies/issuance-exclusive`. */
  rule: string;
  severity: Severity;
  category: RuleCategory;
  /** Human-readable, single sentence, no trailing period. */
  message: string;
  /** Dotted path to the offending value, e.g. `CURRENCIES[1].issuer`. */
  path?: string;
  /** Omitted when the rule is about an absent key. */
  position?: Position;
  /** Link to the relevant part of the spec. */
  helpUri?: string;
  /** Concrete next step for the maintainer. */
  suggestion?: string;
  /**
   * Replacement text for the value at {@link Diagnostic.path}, when the rule
   * can correct itself mechanically. The value is the raw TOML string content
   * (no surrounding quotes), so `fix.value` is ready to drop into a text edit.
   */
  fix?: Fix;
}

/** A mechanically safe replacement for a diagnostic's offending value. */
export interface Fix {
  /** Corrected value content, without TOML quoting. */
  value: string;
}

/** Per-rule severity overrides. `'off'` disables the rule entirely. */
export type RuleOverrides = Record<string, Severity | 'off'>;

/**
 * The TLS parameters a host negotiated, as observed on a live connection.
 *
 * Wallets and exchanges hand anchors their signing keys over these sessions, so
 * a host still speaking TLS 1.0 or offering CBC/RC4 suites is a real risk even
 * when the file itself is perfect.
 */
export interface TlsSession {
  /** Negotiated protocol version, e.g. `TLSv1.3`. `null` when unknown. */
  protocol: string | null;
  /** Cipher suite as the runtime names it, e.g. `AES128-SHA256`. `null` when unknown. */
  cipher: string | null;
  /**
   * IANA name for the same suite, e.g. `TLS_RSA_WITH_AES_128_CBC_SHA256`.
   *
   * Node reports the OpenSSL name, which omits the mode — `AES128-SHA256` is a
   * CBC suite without saying so — so weak-cipher detection has to consult both.
   */
  cipherStandard?: string | null;
}

export interface LintOptions {
  /**
   * The domain the file is (or will be) served from, without scheme.
   * Enables same-domain checks that SEP-1 requires but that cannot be
   * verified from the file alone, e.g. `ORG_URL` matching the host domain.
   */
  domain?: string;
  /** Severity overrides, keyed by rule id. */
  rules?: RuleOverrides;
  /** Treat warnings as errors when computing {@link LintResult.ok}. */
  strict?: boolean;
  /** Verify network-dependent account and currency metadata checks. */
  checkNetwork?: boolean;
  /**
   * TLS session observed while fetching the file.
   *
   * Set by {@link lintDomain} only, so offline runs leave it undefined and the
   * `security/*` rules stay silent. Exposed on the options so the audit can be
   * exercised without opening a socket.
   */
  tls?: TlsSession;
}

export interface LintResult {
  diagnostics: Diagnostic[];
  /** `false` when any error is present (or any warning, in strict mode). */
  ok: boolean;
  counts: Record<Severity, number>;
  /** Parsed document, or `undefined` when the file could not be parsed. */
  parsed?: Record<string, unknown>;
}

/** Everything a rule needs to inspect a document. */
export interface RuleContext {
  /** The parsed TOML document. */
  doc: Record<string, unknown>;
  /** Raw source, for rules that care about bytes or formatting. */
  source: string;
  options: LintOptions;
  /** Resolve a dotted path to a source position, when one can be found. */
  locate(path: string): Position | undefined;
  /** Record a violation. Severity may be overridden by config. */
  report(d: Omit<Diagnostic, 'severity'> & { severity?: Severity }): void;
}

/** A single check. Rules are pure with respect to everything but `report`. */
export interface Rule {
  id: string;
  category: RuleCategory;
  /** Severity used when the user has not overridden it. */
  severity: Severity;
  /** One-line description, surfaced by `--list-rules`. */
  description: string;
  run(ctx: RuleContext): void;
}
