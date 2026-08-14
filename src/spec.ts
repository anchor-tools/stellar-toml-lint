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

/** Fields SEP-1 marks deprecated, with the SEP that replaced them. */
export const DEPRECATED_FIELDS: Record<string, string> = {
  AUTH_SERVER: 'SEP-3 (Compliance Protocol) is deprecated; SEP-10/SEP-12 replace it',
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

/** Permitted values of `[[CURRENCIES]].status`. */
export const CURRENCY_STATUSES = ['live', 'dead', 'test', 'private'] as const;

/** Permitted values of `[[CURRENCIES]].anchor_asset_type`. */
export const ANCHOR_ASSET_TYPES = [
  'fiat',
  'crypto',
  'nft',
  'stock',
  'bond',
  'commodity',
  'realestate',
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
