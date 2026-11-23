import { CURRENCY_STATUSES, ANCHOR_ASSET_TYPES } from './spec.js';

/**
 * Static JSON Schema (Draft 2020-12) describing a SEP-1 stellar.toml file.
 *
 * Editors that support JSON Schema associations for TOML (VS Code with Even
 * Better TOML, IntelliJ, …) can use this for autocompletion and structural
 * validation without running the linter or an LSP daemon. The shape mirrors
 * the field tables in `spec.ts`, so a newly-standardised field is a one-line
 * addition there and one here.
 */

type JsonSchema = Record<string, unknown>;

/** A non-empty string field. */
function stringField(description: string): JsonSchema {
  return { type: 'string', minLength: 1, description };
}

/** A string field that must look like an https:// URL. */
function httpsUrlField(description: string): JsonSchema {
  return {
    type: 'string',
    minLength: 1,
    pattern: '^https://',
    description,
  };
}

/** A string field that must look like an account ID (`G…`, 56 base32 chars). */
function accountIdField(description: string): JsonSchema {
  return {
    type: 'string',
    pattern: '^G[A-Z2-7]{55}$',
    description,
  };
}

const documentationSchema: JsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ORG_NAME: stringField('Legal name of the organization.'),
    ORG_DBA: stringField('DBA of the organization if it operates under a different name.'),
    ORG_URL: httpsUrlField(
      'Canonical URL of the organization. Must be an HTTPS URL serving the same domain.',
    ),
    ORG_LOGO: httpsUrlField('URL of an image (PNG/JPG) to be used as a logo.'),
    ORG_DESCRIPTION: stringField('Short description of the organization.'),
    ORG_PHYSICAL_ADDRESS: stringField('Physical address of the organization.'),
    ORG_PHYSICAL_ADDRESS_ATTESTATION: httpsUrlField(
      'URL to a photo or PDF of an official document attesting the physical address.',
    ),
    ORG_PHONE_NUMBER: stringField('Phone number of the organization.'),
    ORG_PHONE_NUMBER_ATTESTATION: httpsUrlField(
      'URL to a photo of a phone bill or similar attesting the phone number.',
    ),
    ORG_KEYBASE: stringField('Keybase account name for the organization.'),
    ORG_TWITTER: stringField('Twitter/X account name of the organization.'),
    ORG_GITHUB: stringField('GitHub account or organization for the organization.'),
    ORG_OFFICIAL_EMAIL: stringField('Official email for organization inquiries.'),
    ORG_SUPPORT_EMAIL: stringField('Support email for client support inquiries.'),
    ORG_LICENSING_AUTHORITY: stringField('Name of the authority that licensed the organization.'),
    ORG_LICENSE_TYPE: stringField('Type of license the organization holds.'),
    ORG_LICENSE_NUMBER: stringField('Official license number.'),
  },
};

const principalSchema: JsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    name: stringField('Full name of the principal.'),
    email: stringField('Email address of the principal.'),
    keybase: stringField('Keybase account name of the principal.'),
    telegram: stringField('Telegram account name of the principal.'),
    twitter: stringField('Twitter/X account name of the principal.'),
    github: stringField('GitHub account of the principal.'),
    id_photo_hash: stringField('SHA-256 hash of the photo of the principal, lowercase hex.'),
    verification_photo_hash: stringField(
      'SHA-256 hash of the verification photo of the principal, lowercase hex.',
    ),
  },
  required: ['name', 'email'],
};

const currencySchema: JsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    code: stringField('Asset code as registered on the Stellar network.'),
    issuer: {
      oneOf: [accountIdField('Stellar account ID that issued the asset.'), { type: 'null' }],
    },
    contract: stringField('Soroban contract ID of the token (required for SAC tokens).'),
    code_template: stringField(
      'Template for asset codes, using `?` as a wildcard (required for shared assets).',
    ),
    status: {
      enum: [...CURRENCY_STATUSES],
      description: 'Live status of the asset: live, dead, test, or private.',
    },
    display_decimals: {
      type: 'integer',
      minimum: 0,
      maximum: 7,
      description: 'Preferred number of decimal places to show to users.',
    },
    name: stringField('Short name of the asset.'),
    desc: stringField('Description of the asset and its issuance policy.'),
    conditions: stringField('Conditions of issuance.'),
    image: httpsUrlField('URL of an image representing the asset.'),
    fixed_number: { type: 'integer', minimum: 0, description: 'Fixed number of tokens issued.' },
    max_number: { type: 'integer', minimum: 0, description: 'Maximum number of tokens issued.' },
    is_unlimited: {
      type: 'boolean',
      description: 'Whether the token can have unlimited issuance.',
    },
    is_asset_anchored: {
      type: 'boolean',
      description: 'Whether the asset is anchored to an asset outside the Stellar network.',
    },
    anchor_asset_type: {
      enum: [...ANCHOR_ASSET_TYPES],
      description:
        'Type of asset anchored: fiat, crypto, stock, bond, commodity, real_estate, or other.',
    },
    anchor_asset: stringField('Symbol of the asset that backs this one.'),
    attestation_of_reserve: httpsUrlField('URL attesting the reserve backing the asset.'),
    redemption_instructions: stringField('Instructions to redeem the asset.'),
    collateral_addresses: {
      type: 'array',
      items: { type: 'string' },
      description: 'Addresses holding reserves for the asset.',
    },
    collateral_address_messages: {
      type: 'array',
      items: { type: 'string' },
      description: 'Messages attesting the collateral addresses.',
    },
    collateral_address_signatures: {
      type: 'array',
      items: { type: 'string' },
      description: 'Signatures attesting the collateral addresses.',
    },
    regulated: {
      type: 'boolean',
      description: 'Whether the asset is regulated (SEP-8).',
    },
    approval_server: httpsUrlField('SEP-8 approval service endpoint for the asset.'),
    approval_criteria: stringField('SEP-8 criteria the asset must meet for approval.'),
    toml: httpsUrlField('URL of the stellar.toml for a shared asset.'),
  },
  // `code` and `issuer` are the classic pairing; `code_template` and
  // `contract` are alternatives, so only `code` is required outright.
  required: ['code'],
};

const validatorSchema: JsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ALIAS: stringField('A name to uniquely identify the validator.'),
    DISPLAY_NAME: stringField('A human-readable name for display purposes.'),
    PUBLIC_KEY: accountIdField('The Stellar account associated with the validator.'),
    HOST: stringField('Fully qualified domain name plus port of the validator.'),
    HISTORY: httpsUrlField('URL of the history archive for the validator.'),
  },
  required: ['ALIAS', 'PUBLIC_KEY', 'HOST'],
};

/**
 * Builds the schema. Returns a fresh object each call so callers (tests,
 * generators) can mutate their copy without cross-contamination.
 */
export function getTomlJsonSchema(): Record<string, unknown> {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://raw.githubusercontent.com/anchor-tools/stellar-toml-lint/main/schema/stellar-toml.schema.json',
    title: 'SEP-1 stellar.toml',
    description:
      'The Stellar Info File (stellar.toml) published at /.well-known/stellar.toml, as specified by SEP-1.',
    type: 'object',
    additionalProperties: false,
    properties: {
      VERSION: stringField('The version of the stellar.toml schema the file adheres to.'),
      NETWORK_PASSPHRASE: stringField('Passphrase of the Stellar network the file targets.'),
      HORIZON_URL: httpsUrlField('URL of a Horizon instance to use with this anchor.'),
      ACCOUNTS: {
        type: 'string',
        description: 'Stellar account IDs or channels that indicate the accounts this anchor uses.',
      },
      URI_REQUEST_SIGNING_KEY: accountIdField(
        'Stellar account used to sign URI request tokens (SEP-7).',
      ),
      WEB_AUTH_ENDPOINT: httpsUrlField('SEP-10 web authentication endpoint.'),
      WEB_AUTH_FOR_CONTRACTS_ENDPOINT: httpsUrlField(
        'SEP-45 web authentication for contracts endpoint.',
      ),
      WEB_AUTH_CONTRACT_ID: stringField('Soroban contract ID used for SEP-45 web auth.'),
      FEDERATION_SERVER: httpsUrlField('SEP-2 federation endpoint.'),
      AUTH_SERVER: httpsUrlField('Deprecated SEP-3 compliance endpoint.'),
      TRANSFER_SERVER: httpsUrlField('SEP-6 transfer server endpoint.'),
      TRANSFER_SERVER_SEP0024: httpsUrlField('SEP-24 transfer server endpoint.'),
      KYC_SERVER: httpsUrlField('SEP-12 KYC endpoint.'),
      DIRECT_PAYMENT_SERVER: httpsUrlField('SEP-31 direct payment server endpoint.'),
      ANCHOR_QUOTE_SERVER: httpsUrlField('SEP-38 anchor quote server endpoint.'),
      SIGNING_KEY: accountIdField('Stellar account used for SEP-10 challenge signatures.'),
      DOCUMENTATION: documentationSchema,
      PRINCIPALS: {
        type: 'array',
        items: principalSchema,
        description: 'Primary contact persons for the organization.',
      },
      CURRENCIES: {
        type: 'array',
        items: currencySchema,
        description: 'Assets issued by this anchor.',
      },
      VALIDATORS: {
        type: 'array',
        items: validatorSchema,
        description: 'Validator nodes run by this organization.',
      },
    },
  };
}
