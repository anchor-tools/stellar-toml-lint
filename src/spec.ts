/**
 * SEP-1 field tables, transcribed as data.
 *
 * Keeping the spec's shape here (rather than inlining it across rules) means
 * adding a newly-standardised field is a one-line change, and it gives the
 * `unknown-field` rules something authoritative to check against.
 *
 * Source: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md
 */

export const SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';

/** Anchor a diagnostic to a named section of the spec. */
export function specUrl(anchor?: string): string {
  return anchor ? `${SPEC_URL}#${anchor}` : SPEC_URL;
}

/** Global endpoint fields that SEP-1 requires to use `https://`. */
export const HTTPS_ENDPOINT_FIELDS = [
  'FEDERATION_SERVER',
  'AUTH_SERVER',
  'TRANSFER_SERVER',
  'TRANSFER_SERVER_SEP0024',
  'KYC_SERVER',
  'WEB_AUTH_ENDPOINT',
  'WEB_AUTH_FOR_CONTRACTS_ENDPOINT',
  'DIRECT_PAYMENT_SERVER',
  'ANCHOR_QUOTE_SERVER',
] as const;

/** Global fields holding a `G...` account ID. */
export const ACCOUNT_ID_FIELDS = ['SIGNING_KEY', 'URI_REQUEST_SIGNING_KEY'] as const;

export interface DeprecatedField {
  message: string;
  suggestion: string;
}

export const DEPRECATED_FIELDS: Record<string, DeprecatedField> = {
  AUTH_SERVER: {
    message: 'the SEP-3 Compliance Protocol is deprecated',
    suggestion:
      'Replace AUTH_SERVER with WEB_AUTH_ENDPOINT for SEP-10 authentication and KYC_SERVER for SEP-12 customer data.',
  },
  DEPOSIT_SERVER: {
    message: 'the legacy SEP-6 deposit server field was replaced',
    suggestion:
      'Replace DEPOSIT_SERVER with TRANSFER_SERVER for SEP-6 or TRANSFER_SERVER_SEP0024 for SEP-24.',
  },
};

/** Every field SEP-1 defines at the top level of the document. */
export const KNOWN_GLOBAL_FIELDS = new Set<string>([
  'VERSION',
  'NETWORK_PASSPHRASE',
  'HORIZON_URL',
  'ACCOUNTS',
  'WEB_AUTH_CONTRACT_ID',
  ...HTTPS_ENDPOINT_FIELDS,
  ...ACCOUNT_ID_FIELDS,
  ...Object.keys(DEPRECATED_FIELDS),
  // Tables, handled by their own rule sets.
  'DOCUMENTATION',
  'PRINCIPALS',
  'CURRENCIES',
  'VALIDATORS',
]);

/** Every field SEP-1 defines in `[DOCUMENTATION]`. */
export const KNOWN_DOCUMENTATION_FIELDS = new Set<string>([
  'ORG_NAME',
  'ORG_DBA',
  'ORG_URL',
  'ORG_LOGO',
  'ORG_DESCRIPTION',
  'ORG_PHYSICAL_ADDRESS',
  'ORG_PHYSICAL_ADDRESS_ATTESTATION',
  'ORG_PHONE_NUMBER',
  'ORG_PHONE_NUMBER_ATTESTATION',
  'ORG_KEYBASE',
  'ORG_TWITTER',
  'ORG_GITHUB',
  'ORG_OFFICIAL_EMAIL',
  'ORG_SUPPORT_EMAIL',
  'ORG_LICENSING_AUTHORITY',
  'ORG_LICENSE_TYPE',
  'ORG_LICENSE_NUMBER',
]);

/** Every field SEP-1 defines in a `[[PRINCIPALS]]` entry. */
export const KNOWN_PRINCIPAL_FIELDS = new Set<string>([
  'name',
  'email',
  'keybase',
  'telegram',
  'twitter',
  'github',
  'id_photo_hash',
  'verification_photo_hash',
]);

/** Every field SEP-1 defines in a `[[CURRENCIES]]` entry. */
export const KNOWN_CURRENCY_FIELDS = new Set<string>([
  'code',
  'issuer',
  'contract',
  'code_template',
  'status',
  'display_decimals',
  'name',
  'desc',
  'conditions',
  'image',
  'fixed_number',
  'max_number',
  'is_unlimited',
  'is_asset_anchored',
  'anchor_asset_type',
  'anchor_asset',
  'attestation_of_reserve',
  'redemption_instructions',
  'collateral_addresses',
  'collateral_address_messages',
  'collateral_address_signatures',
  'regulated',
  'approval_server',
  'approval_criteria',
  'toml',
]);

/** Every field SEP-1 defines in a `[[VALIDATORS]]` entry. */
export const KNOWN_VALIDATOR_FIELDS = new Set<string>([
  'ALIAS',
  'DISPLAY_NAME',
  'PUBLIC_KEY',
  'HOST',
  'HISTORY',
]);

/**
 * stellar-core config keywords that cannot be reused as a `[[VALIDATORS]]` alias.
 *
 * Other operators import a validator's ALIAS into the quorum slices of their own
 * stellar-core.cfg. Names like `self` or `quorum` are parsed as stellar-core
 * directives rather than as node names, so an alias colliding with one of these
 * breaks or surprises other operators' configs. Matched case-insensitively.
 */
export const RESERVED_VALIDATOR_ALIASES = new Set<string>([
  'self',
  'all',
  'default',
  'none',
  'quorum',
  'peers',
  'manual',
  'auto',
]);

/**
 * TLS protocol versions that are no longer considered secure.
 *
 * TLS 1.0 and 1.1 were deprecated by RFC 8996; SSLv2/SSLv3 were broken long
 * before that. SEP-1 itself is silent on TLS versions — it only requires
 * `https://` — so these are flagged as warnings rather than errors.
 */
export const DEPRECATED_TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'] as const;

/**
 * Markers that identify a weak cipher suite.
 *
 * Matched as whole tokens against both the runtime and IANA names, so that a
 * strong suite is never flagged for merely containing a substring ("DES" in a
 * hypothetical name, say) while `DES-CBC3-SHA` is still caught.
 */
export const WEAK_CIPHER_MARKERS = ['3DES', 'DES', 'RC4', 'CBC', 'NULL', 'EXPORT'] as const;

/** Where to read up on the TLS configuration these rules care about. */
export const TLS_SECURITY_DOC_URL =
  'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html';

/** Permitted values of `[[CURRENCIES]].status`. */
export const CURRENCY_STATUSES = ['live', 'dead', 'test', 'private'] as const;

/** Permitted values of `[[CURRENCIES]].anchor_asset_type`. */
export const ANCHOR_ASSET_TYPES = [
  'fiat',
  'crypto',
  'stock',
  'bond',
  'commodity',
  'real_estate',
  'other',
] as const;

/**
 * Mutually exclusive issuance policies. SEP-1: "Include exactly one of
 * those fields."
 */
export const ISSUANCE_FIELDS = ['fixed_number', 'max_number', 'is_unlimited'] as const;

/**
 * Fields wallets and exchanges weigh when deciding whether to list an asset.
 * SEP-1 calls out that listing decisions are made "based on the completeness of
 * their Account Information and Documentation sections".
 */
export const RECOMMENDED_DOCUMENTATION_FIELDS = [
  'ORG_NAME',
  'ORG_URL',
  'ORG_DESCRIPTION',
  'ORG_LOGO',
  'ORG_OFFICIAL_EMAIL',
] as const;

/* ── Hover documentation ──────────────────────────────────────────────────────
 *
 * The LSP hover handler (src/lsp/hover.ts) turns these entries into the
 * tooltip an editor shows over a key or a table header. `description` and
 * `type` are quoted from the field tables of SEP-1, and `values` is the set
 * the linter itself enforces, so a tooltip never promises a value the linter
 * would then reject.
 *
 * Every entry sits under a section: `''` is the document root, where SEP-1's
 * General Information fields live. A coverage test asserts that these docs and
 * the KNOWN_* sets above never drift apart.
 */

/** Sections SEP-1 declares as array-of-tables (`[[...]]`) rather than tables. */
export const ARRAY_SECTIONS = new Set(['PRINCIPALS', 'CURRENCIES', 'VALIDATORS']);

/** Label of the link into SEP-1, for each section anchor. */
export const ANCHOR_TITLES: Record<string, string> = {
  'general-information': 'General Information',
  'organization-documentation': 'Organization Documentation',
  'point-of-contact-documentation': 'Point of Contact Documentation',
  'currency-documentation': 'Currency Documentation',
  'validator-information': 'Validator Information',
};

/** Everything an editor needs to describe one SEP-1 field under the cursor. */
export interface FieldDoc {
  /** Section the field lives in; `''` is the document root. */
  section: string;
  /** Key as written in the file, or the table name for a section header. */
  name: string;
  /** The "Requirements" column of the SEP-1 field table. */
  type: string;
  /** The "Description" column of the SEP-1 field table, quoted. */
  description: string;
  /** The accepted values, for the fields SEP-1 enumerates. */
  values?: readonly string[];
  /** Anchor of the SEP-1 section that documents this field. */
  anchor: string;
}

/** Every SEP-1 field and table header this linter knows how to explain. */
export const FIELD_DOCS: readonly FieldDoc[] = [
  // ── General Information (document root) ──
  {
    section: '',
    name: 'VERSION',
    type: 'string',
    description:
      'The version of SEP-1 your stellar.toml adheres to. This helps parsers know which fields to expect.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'NETWORK_PASSPHRASE',
    type: 'string',
    description: 'The passphrase for the specific Stellar network this infrastructure operates on.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'FEDERATION_SERVER',
    type: 'url (`https://`)',
    description:
      'The endpoint for clients to resolve stellar addresses for users on your domain via SEP-2 Federation Protocol.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'AUTH_SERVER',
    type: 'url (`https://`)',
    description:
      '(deprecated) The endpoint used for SEP-3 Compliance Protocol; SEP-10 and SEP-12 replace it.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'DEPOSIT_SERVER',
    type: 'url (`https://`)',
    description:
      '(deprecated) The legacy SEP-6 deposit server field; use TRANSFER_SERVER for SEP-6 or TRANSFER_SERVER_SEP0024 for SEP-24.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'TRANSFER_SERVER',
    type: 'url (`https://`)',
    description: 'The server used for SEP-6 Anchor/Client interoperability.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'TRANSFER_SERVER_SEP0024',
    type: 'url (`https://`)',
    description: 'The server used for SEP-24 Anchor/Client interoperability.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'KYC_SERVER',
    type: 'url (`https://`)',
    description: 'The server used for SEP-12 Anchor/Client customer info transfer.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'WEB_AUTH_ENDPOINT',
    type: 'url (`https://`)',
    description: 'The endpoint used for SEP-10 Web Authentication.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'WEB_AUTH_FOR_CONTRACTS_ENDPOINT',
    type: 'url (`https://`)',
    description: 'The endpoint used for SEP-45 Web Authentication.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'WEB_AUTH_CONTRACT_ID',
    type: 'contract ID (`C...`)',
    description: 'The web authentication contract ID for SEP-45 Web Authentication.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'SIGNING_KEY',
    type: 'account ID (`G...`)',
    description:
      'The signing key is used for SEP-3 Compliance Protocol (deprecated) and the SEP-10 and SEP-45 Authentication Protocols. It must be a Stellar account ID: a `G...` public key with a valid checksum.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'HORIZON_URL',
    type: 'url',
    description: 'Location of a public-facing Horizon instance (if you offer one).',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'ACCOUNTS',
    type: 'list of `G...` strings',
    description: 'A list of Stellar accounts that are controlled by this domain.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'URI_REQUEST_SIGNING_KEY',
    type: 'account ID (`G...`)',
    description: 'The signing key is used for SEP-7 delegated signing.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'DIRECT_PAYMENT_SERVER',
    type: 'url (`https://`)',
    description:
      'The server used for receiving SEP-31 direct fiat-to-fiat payments. Requires SEP-12 and hence a KYC_SERVER attribute.',
    anchor: 'general-information',
  },
  {
    section: '',
    name: 'ANCHOR_QUOTE_SERVER',
    type: 'url (`https://`)',
    description: 'The server used for receiving SEP-38 requests.',
    anchor: 'general-information',
  },

  // ── Section headers ──
  {
    section: '',
    name: 'DOCUMENTATION',
    type: 'table',
    description:
      'These fields go in the stellar.toml [DOCUMENTATION] table: the legal identity, contact details, address, and licensing information that wallets and exchanges weigh before listing an organization.',
    anchor: 'organization-documentation',
  },
  {
    section: '',
    name: 'PRINCIPALS',
    type: 'array of tables',
    description:
      'These fields go in the stellar.toml [[PRINCIPALS]] list: identifying information for the primary point of contact or principal(s) of the organization.',
    anchor: 'point-of-contact-documentation',
  },
  {
    section: '',
    name: 'CURRENCIES',
    type: 'array of tables',
    description:
      'These fields go in the stellar.toml [[CURRENCIES]] list, one set of fields for each currency supported. Complete all applicable fields, and exclude any that do not apply.',
    anchor: 'currency-documentation',
  },
  {
    section: '',
    name: 'VALIDATORS',
    type: 'array of tables',
    description:
      'These fields go in the stellar.toml [[VALIDATORS]] list, one set of fields for each node your organization runs, letting others know the location of any public archives you maintain.',
    anchor: 'validator-information',
  },

  // ── [DOCUMENTATION] ──
  {
    section: 'DOCUMENTATION',
    name: 'ORG_NAME',
    type: 'string',
    description: 'Legal name of your organization.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_DBA',
    type: 'string',
    description: '(may not apply) DBA ("doing business as") name of your organization.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_URL',
    type: 'url (`https://`)',
    description:
      "Your organization's official URL. Your stellar.toml must be hosted on the same domain.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_LOGO',
    type: 'url',
    description: "A PNG image of your organization's logo on a transparent background.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_DESCRIPTION',
    type: 'string',
    description: 'Short description of your organization.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_PHYSICAL_ADDRESS',
    type: 'string',
    description: 'Physical address for your organization.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_PHYSICAL_ADDRESS_ATTESTATION',
    type: 'url (`https://`)',
    description:
      'URL on the same domain as your ORG_URL that contains an image or PDF of an official document attesting to your physical address, listing your ORG_NAME or ORG_DBA as the party at the address. Only documents from an official third party are acceptable, e.g. a utility bill, mail from a financial institution, or a business license.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_PHONE_NUMBER',
    type: 'string (E.164)',
    description: "Your organization's phone number in E.164 format, e.g. +14155552671.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_PHONE_NUMBER_ATTESTATION',
    type: 'url (`https://`)',
    description:
      "URL on the same domain as your ORG_URL that contains an image or PDF of a phone bill showing both the phone number and your organization's name.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_KEYBASE',
    type: 'string',
    description:
      "A Keybase account name for your organization. Should contain proof of ownership of any public online accounts you list here, including your organization's domain.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_TWITTER',
    type: 'string',
    description: "Your organization's Twitter account.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_GITHUB',
    type: 'string',
    description: "Your organization's Github account.",
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_OFFICIAL_EMAIL',
    type: 'email address',
    description:
      'An email that business partners such as wallets, exchanges, or anchors can use to contact your organization. Must be hosted at your ORG_URL domain.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_SUPPORT_EMAIL',
    type: 'email address',
    description:
      'An email that users can use to request support regarding your Stellar assets or applications.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_LICENSING_AUTHORITY',
    type: 'string',
    description:
      'Name of the authority or agency that issued a license, registration, or authorization to your organization, if applicable.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_LICENSE_TYPE',
    type: 'string',
    description:
      'Type of financial or other license, registration, or authorization your organization holds, if applicable.',
    anchor: 'organization-documentation',
  },
  {
    section: 'DOCUMENTATION',
    name: 'ORG_LICENSE_NUMBER',
    type: 'string',
    description:
      'Official license, registration, or authorization number of your organization, if applicable.',
    anchor: 'organization-documentation',
  },

  // ── [[PRINCIPALS]] ──
  {
    section: 'PRINCIPALS',
    name: 'name',
    type: 'string',
    description: 'Full legal name.',
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'email',
    type: 'email address',
    description: 'Business email address for the principal.',
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'keybase',
    type: 'string',
    description:
      "Personal Keybase account. Should include proof of ownership for other online accounts, as well as the organization's domain.",
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'telegram',
    type: 'string',
    description: 'Personal Telegram account.',
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'twitter',
    type: 'string',
    description: 'Personal Twitter account.',
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'github',
    type: 'string',
    description: 'Personal Github account.',
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'id_photo_hash',
    type: 'hex string (SHA-256)',
    description: "SHA-256 hash of a photo of the principal's government-issued photo ID.",
    anchor: 'point-of-contact-documentation',
  },
  {
    section: 'PRINCIPALS',
    name: 'verification_photo_hash',
    type: 'hex string (SHA-256)',
    description:
      'SHA-256 hash of a verification photo of the principal. Should be well-lit and contain the principal holding their ID card and a signed, dated, hand-written message stating: I, $NAME, am a principal of $ORG_NAME, a Stellar token issuer with address $ISSUER_ADDRESS.',
    anchor: 'point-of-contact-documentation',
  },

  // ── [[CURRENCIES]] ──
  {
    section: 'CURRENCIES',
    name: 'code',
    type: 'string (<= 12 characters)',
    description: 'Token code. Required.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'issuer',
    type: 'account ID (`G...`)',
    description:
      'Stellar public key of the issuing account. Required for tokens that are Stellar Assets. Omitted if the token is not a Stellar asset.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'contract',
    type: 'contract ID (`C...`)',
    description:
      'Contract ID of the token contract, which must implement the SEP-41 Token Interface. Required for tokens that are not Stellar Assets. Omitted if the token is a Stellar Asset.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'code_template',
    type: 'string (<= 12 characters)',
    description:
      'A pattern with ? as a single character wildcard. Allows a [[CURRENCIES]] entry to apply to multiple assets that share the same info, e.g. CORN???????? matches CORN20180604.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'status',
    type: 'string',
    description:
      'Status of the token. Allows the issuer to mark whether the token is dead, for testing, for private use, or live and should be listed on live exchanges.',
    values: CURRENCY_STATUSES,
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'display_decimals',
    type: 'integer (0-7)',
    description:
      'Preference for number of decimals to show when a client displays currency balance.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'name',
    type: 'string (<= 20 characters)',
    description: 'A short name for the token.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'desc',
    type: 'string',
    description: 'Description of token and what it represents.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'conditions',
    type: 'string',
    description: 'Conditions on token.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'image',
    type: 'url',
    description: 'URL to a PNG image on a transparent background representing the token.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'fixed_number',
    type: 'integer',
    description:
      'Fixed number of tokens, if the number of tokens issued will never change. Mutually exclusive with max_number and is_unlimited: include exactly one of those three fields.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'max_number',
    type: 'integer',
    description:
      'Max number of tokens, if there will never be more than max_number tokens. Mutually exclusive with fixed_number and is_unlimited: include exactly one of those three fields.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'is_unlimited',
    type: 'boolean',
    description:
      "The number of tokens is dilutable at the issuer's discretion. Mutually exclusive with fixed_number and max_number: include exactly one of those three fields.",
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'is_asset_anchored',
    type: 'boolean',
    description: 'True if the token can be redeemed for the underlying asset, otherwise false.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'anchor_asset_type',
    type: 'string',
    description: 'Type of asset anchored: the class of the underlying asset this token represents.',
    values: ANCHOR_ASSET_TYPES,
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'anchor_asset',
    type: 'string',
    description:
      'If an anchored token, the code or symbol for the asset that the token is anchored to, e.g. USD, BTC, SBUX, or the address of a real-estate investment property.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'attestation_of_reserve',
    type: 'url',
    description:
      'URL to attestation or other proof, evidence, or verification of reserves, such as third-party audits.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'redemption_instructions',
    type: 'string',
    description: 'If an anchored token, instructions to redeem the underlying asset from tokens.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'collateral_addresses',
    type: 'list of crypto address strings',
    description:
      'If this is an anchored crypto token, a list of one or more public addresses that hold the assets for which you are issuing tokens.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'collateral_address_messages',
    type: 'list of message strings',
    description:
      'Messages stating that funds in the collateral_addresses list are reserved to back the issued asset.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'collateral_address_signatures',
    type: 'list of signature strings',
    description:
      "Prove you control the collateral_addresses: for each address, sign the entry in collateral_address_messages with the address's private key and add the resulting base64-encoded raw signature to this list.",
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'regulated',
    type: 'boolean',
    description: 'Indicates whether this is a SEP-8 regulated asset. If missing, false is assumed.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'approval_server',
    type: 'url',
    description: 'URL of a SEP-8 compliant approval service that signs validated transactions.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'approval_criteria',
    type: 'string',
    description:
      'A human readable string that explains the issuer’s requirements for approving transactions.',
    anchor: 'currency-documentation',
  },
  {
    section: 'CURRENCIES',
    name: 'toml',
    type: 'url',
    description:
      'Links out to a separate TOML file for the currency: stellar.toml can specify toml="https://DOMAIN/.well-known/CURRENCY.toml" as the currency’s only field.',
    anchor: 'currency-documentation',
  },

  // ── [[VALIDATORS]] ──
  {
    section: 'VALIDATORS',
    name: 'ALIAS',
    type: 'string',
    description: 'A name for display in stellar-core configs that conforms to ^[a-z0-9-]{2,16}$.',
    anchor: 'validator-information',
  },
  {
    section: 'VALIDATORS',
    name: 'DISPLAY_NAME',
    type: 'string',
    description: 'A human-readable name for display in quorum explorers and other interfaces.',
    anchor: 'validator-information',
  },
  {
    section: 'VALIDATORS',
    name: 'PUBLIC_KEY',
    type: 'account ID (`G...`)',
    description: 'The Stellar account associated with the node.',
    anchor: 'validator-information',
  },
  {
    section: 'VALIDATORS',
    name: 'HOST',
    type: 'string',
    description: 'The IP:port or domain:port peers can use to connect to the node.',
    anchor: 'validator-information',
  },
  {
    section: 'VALIDATORS',
    name: 'HISTORY',
    type: 'url',
    description: 'The location of the history archive published by this validator.',
    anchor: 'validator-information',
  },
];

const FIELD_DOCS_BY_PATH = new Map<string, FieldDoc>(
  FIELD_DOCS.map((doc) => [`${doc.section}/${doc.name}`, doc]),
);

/** SEP-1 documentation for `name` inside `section`, or `undefined`. */
export function fieldDoc(section: string, name: string): FieldDoc | undefined {
  return FIELD_DOCS_BY_PATH.get(`${section}/${name}`);
}

/** How the field is written out: `SIGNING_KEY`, `[DOCUMENTATION].ORG_NAME`. */
export function qualifiedFieldName(section: string, name: string): string {
  if (section === '') return name;
  const header = ARRAY_SECTIONS.has(section) ? `[[${section}]]` : `[${section}]`;
  return `${header}.${name}`;
}
