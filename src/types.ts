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
  | 'file'
  | 'general'
  | 'documentation'
  | 'principals'
  | 'currencies'
  | 'validators'
  | 'network'
  | 'policy'
  | 'sep12';

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
   * Fetch and lint the `toml` pointers referenced by `CURRENCIES` entries.
   *
   * Consumes the caller's transport, so a stubbed `fetchImpl` keeps the linked
   * documents hermetic. Only honoured by `lintDomain`; offline `lint` runs have
   * no transport to follow a pointer with.
   */
  followLinks?: boolean;
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
  parsed?: StellarToml;
}

export interface StellarToml {
  VERSION?: string;
  NETWORK_PASSPHRASE?: string;
  HORIZON_URL?: string;
  ACCOUNTS?: string[];
  WEB_AUTH_CONTRACT_ID?: string;
  SIGNING_KEY?: string;
  URI_REQUEST_SIGNING_KEY?: string;
  FEDERATION_SERVER?: string;
  AUTH_SERVER?: string;
  TRANSFER_SERVER?: string;
  TRANSFER_SERVER_SEP0024?: string;
  KYC_SERVER?: string;
  WEB_AUTH_ENDPOINT?: string;
  WEB_AUTH_FOR_CONTRACTS_ENDPOINT?: string;
  DIRECT_PAYMENT_SERVER?: string;
  ANCHOR_QUOTE_SERVER?: string;
  DOCUMENTATION?: {
    ORG_NAME?: string;
    ORG_DBA?: string;
    ORG_URL?: string;
    ORG_LOGO?: string;
    ORG_DESCRIPTION?: string;
    ORG_PHYSICAL_ADDRESS?: string;
    ORG_PHYSICAL_ADDRESS_ATTESTATION?: string;
    ORG_PHONE_NUMBER?: string;
    ORG_PHONE_NUMBER_ATTESTATION?: string;
    ORG_KEYBASE?: string;
    ORG_TWITTER?: string;
    ORG_GITHUB?: string;
    ORG_OFFICIAL_EMAIL?: string;
    ORG_SUPPORT_EMAIL?: string;
    ORG_LICENSING_AUTHORITY?: string;
    ORG_LICENSE_TYPE?: string;
    ORG_LICENSE_NUMBER?: string;
  };
  PRINCIPALS?: Array<{
    name?: string;
    email?: string;
    keybase?: string;
    telegram?: string;
    twitter?: string;
    github?: string;
    id_photo_hash?: string;
    verification_photo_hash?: string;
  }>;
  CURRENCIES?: Array<{
    code?: string;
    issuer?: string;
    contract?: string;
    code_template?: string;
    status?: string;
    display_decimals?: number;
    name?: string;
    desc?: string;
    conditions?: string;
    image?: string;
    fixed_number?: string;
    max_number?: string;
    is_unlimited?: boolean;
    is_asset_anchored?: boolean;
    anchor_asset_type?: string;
    anchor_asset?: string;
    attestation_of_reserve?: string;
    redemption_instructions?: string;
    collateral_addresses?: string[];
    collateral_address_messages?: string[];
    collateral_address_signatures?: string[];
    regulated?: boolean;
    approval_server?: string;
    approval_criteria?: string;
    toml?: string;
  }>;
  VALIDATORS?: Array<{
    ALIAS?: string;
    DISPLAY_NAME?: string;
    PUBLIC_KEY?: string;
    HOST?: string;
    HISTORY?: string;
  }>;
  SERVERS?: Array<{
    WEB_AUTH_ENDPOINT?: string;
    TRANSFER_SERVER?: string;
    TRANSFER_SERVER_SEP0024?: string;
    KYC_SERVER?: string;
    ANCHOR_QUOTE_SERVER?: string;
    DIRECT_PAYMENT_SERVER?: string;
    WEB_AUTH_CONTRACT_ID?: string;
    TLS_CERT?: string;
  }>;
  [key: string]: unknown;
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
