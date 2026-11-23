import {
  KNOWN_GLOBAL_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_CURRENCY_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  CURRENCY_STATUSES,
  ANCHOR_ASSET_TYPES,
} from '../src/spec.js';

interface JsonSchema {
  $schema: string;
  $id: string;
  title: string;
  description: string;
  type: string;
  properties: Record<string, SchemaProperty>;
  additionalProperties: boolean;
}

interface SchemaProperty {
  type?: string | string[];
  description?: string;
  items?: Record<string, unknown>;
  properties?: Record<string, SchemaProperty>;
  enum?: readonly string[];
  pattern?: string;
  format?: string;
  additionalProperties?: boolean;
}

const STELLAR_KEY_PATTERN = '^G[A-Z2-7]{55}$';
const CONTRACT_PATTERN = '^C[A-Z2-7]{55}$';
const HTTPS_PATTERN = '^https://';

function stringProp(description: string, extra: Partial<SchemaProperty> = {}): SchemaProperty {
  return { type: 'string', description, ...extra };
}

function urlProp(description: string): SchemaProperty {
  return stringProp(description, { pattern: HTTPS_PATTERN });
}

function buildGlobalProperties(): Record<string, SchemaProperty> {
  const props: Record<string, SchemaProperty> = {};

  for (const field of KNOWN_GLOBAL_FIELDS) {
    switch (field) {
      case 'VERSION':
        props[field] = stringProp('SEP-1 version');
        break;
      case 'NETWORK_PASSPHRASE':
        props[field] = stringProp('Stellar network passphrase');
        break;
      case 'ACCOUNTS':
        props[field] = {
          type: 'array',
          description: 'List of Stellar account IDs operated by this anchor',
          items: { type: 'string', pattern: STELLAR_KEY_PATTERN },
        };
        break;
      case 'SIGNING_KEY':
      case 'URI_REQUEST_SIGNING_KEY':
        props[field] = stringProp(`${field}`, { pattern: STELLAR_KEY_PATTERN });
        break;
      case 'WEB_AUTH_CONTRACT_ID':
        props[field] = stringProp('SEP-10 web auth contract ID', { pattern: CONTRACT_PATTERN });
        break;
      case 'HORIZON_URL':
        props[field] = urlProp('Horizon server URL');
        break;
      case 'DOCUMENTATION':
      case 'PRINCIPALS':
      case 'CURRENCIES':
      case 'VALIDATORS':
        break;
      default:
        props[field] = urlProp(`${field} endpoint`);
    }
  }

  props['DOCUMENTATION'] = {
    type: 'object',
    description: 'Organization documentation',
    properties: buildDocumentationProperties(),
    additionalProperties: false,
  };

  props['PRINCIPALS'] = {
    type: 'array',
    description: 'Key personnel',
    items: {
      type: 'object',
      properties: buildPrincipalProperties(),
      additionalProperties: false,
    },
  };

  props['CURRENCIES'] = {
    type: 'array',
    description: 'Supported currencies/assets',
    items: {
      type: 'object',
      properties: buildCurrencyProperties(),
      additionalProperties: false,
    },
  };

  props['VALIDATORS'] = {
    type: 'array',
    description: 'Stellar validators operated by this organization',
    items: {
      type: 'object',
      properties: buildValidatorProperties(),
      additionalProperties: false,
    },
  };

  return props;
}

function buildDocumentationProperties(): Record<string, SchemaProperty> {
  const props: Record<string, SchemaProperty> = {};
  for (const field of KNOWN_DOCUMENTATION_FIELDS) {
    if (field.includes('URL') || field.includes('LOGO') || field.includes('ATTESTATION')) {
      props[field] = urlProp(field);
    } else if (field.includes('EMAIL')) {
      props[field] = stringProp(field, { format: 'email' });
    } else {
      props[field] = stringProp(field);
    }
  }
  return props;
}

function buildPrincipalProperties(): Record<string, SchemaProperty> {
  const props: Record<string, SchemaProperty> = {};
  for (const field of KNOWN_PRINCIPAL_FIELDS) {
    if (field.includes('email')) {
      props[field] = stringProp(field, { format: 'email' });
    } else {
      props[field] = stringProp(field);
    }
  }
  return props;
}

function buildCurrencyProperties(): Record<string, SchemaProperty> {
  const props: Record<string, SchemaProperty> = {};
  for (const field of KNOWN_CURRENCY_FIELDS) {
    switch (field) {
      case 'display_decimals':
      case 'fixed_number':
      case 'max_number':
        props[field] = { type: 'number', description: field };
        break;
      case 'is_unlimited':
      case 'is_asset_anchored':
      case 'regulated':
        props[field] = { type: 'boolean', description: field };
        break;
      case 'status':
        props[field] = { type: 'string', description: field, enum: CURRENCY_STATUSES };
        break;
      case 'anchor_asset_type':
        props[field] = { type: 'string', description: field, enum: ANCHOR_ASSET_TYPES };
        break;
      case 'issuer':
        props[field] = stringProp(field, { pattern: STELLAR_KEY_PATTERN });
        break;
      case 'contract':
        props[field] = stringProp(field, { pattern: CONTRACT_PATTERN });
        break;
      case 'collateral_addresses':
      case 'collateral_address_messages':
      case 'collateral_address_signatures':
        props[field] = { type: 'array', description: field, items: { type: 'string' } };
        break;
      case 'image':
      case 'attestation_of_reserve':
      case 'approval_server':
      case 'toml':
        props[field] = urlProp(field);
        break;
      default:
        props[field] = stringProp(field);
    }
  }
  return props;
}

function buildValidatorProperties(): Record<string, SchemaProperty> {
  const props: Record<string, SchemaProperty> = {};
  for (const field of KNOWN_VALIDATOR_FIELDS) {
    switch (field) {
      case 'PUBLIC_KEY':
        props[field] = stringProp(field, { pattern: STELLAR_KEY_PATTERN });
        break;
      case 'HISTORY':
        props[field] = urlProp(field);
        break;
      default:
        props[field] = stringProp(field);
    }
  }
  return props;
}

export function generateJsonSchema(draft: '07' | '2020-12' = '07'): JsonSchema {
  const schemaUri =
    draft === '07'
      ? 'http://json-schema.org/draft-07/schema#'
      : 'https://json-schema.org/draft/2020-12/schema';

  return {
    $schema: schemaUri,
    $id: 'https://raw.githubusercontent.com/anchor-tools/stellar-toml-lint/main/schema/stellar-toml.json',
    title: 'Stellar Info File (stellar.toml)',
    description: 'JSON Schema for SEP-1 stellar.toml configuration files',
    type: 'object',
    properties: buildGlobalProperties(),
    additionalProperties: true,
  };
}

export function generateCatalogEntry(): Record<string, unknown> {
  return {
    name: 'stellar.toml',
    description: 'Stellar Info File (SEP-1)',
    fileMatch: ['stellar.toml', '*/.well-known/stellar.toml'],
    url: 'https://raw.githubusercontent.com/anchor-tools/stellar-toml-lint/main/schema/stellar-toml.json',
  };
}
