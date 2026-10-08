import { describe, expect, it } from 'vitest';
import { getTomlJsonSchema } from '../src/schema.js';
import { CURRENCY_STATUSES, ANCHOR_ASSET_TYPES } from '../src/spec.js';

const schema = getTomlJsonSchema() as Record<string, unknown>;
const properties = schema.properties as Record<string, Record<string, unknown>>;

describe('getTomlJsonSchema', () => {
  it('is valid JSON and a JSON Schema object', () => {
    // Round-trip proves it serialises (no cycles, no undefined, no BigInt).
    const roundTripped = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
    expect(roundTripped).toEqual(schema);
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.type).toBe('object');
  });

  it('exposes every standard top-level section and field', () => {
    for (const key of [
      'VERSION',
      'NETWORK_PASSPHRASE',
      'HORIZON_URL',
      'ACCOUNTS',
      'SIGNING_KEY',
      'URI_REQUEST_SIGNING_KEY',
      'WEB_AUTH_ENDPOINT',
      'WEB_AUTH_FOR_CONTRACTS_ENDPOINT',
      'WEB_AUTH_CONTRACT_ID',
      'FEDERATION_SERVER',
      'AUTH_SERVER',
      'TRANSFER_SERVER',
      'TRANSFER_SERVER_SEP0024',
      'KYC_SERVER',
      'DIRECT_PAYMENT_SERVER',
      'ANCHOR_QUOTE_SERVER',
      'DOCUMENTATION',
      'PRINCIPALS',
      'CURRENCIES',
      'VALIDATORS',
    ]) {
      expect(properties[key], `missing top-level ${key}`).toBeDefined();
    }
  });

  it('models the table sections as arrays of objects', () => {
    expect(properties.PRINCIPALS?.type).toBe('array');
    expect(properties.CURRENCIES?.type).toBe('array');
    expect(properties.VALIDATORS?.type).toBe('array');
    for (const key of ['PRINCIPALS', 'CURRENCIES', 'VALIDATORS']) {
      const items = (properties[key]?.items ?? {}) as Record<string, unknown>;
      expect(items.type, `${key} items must be objects`).toBe('object');
    }
  });

  it('constrains DOCUMENTATION.ORG_URL to https', () => {
    const documentation = properties.DOCUMENTATION as Record<string, unknown>;
    const docProps = documentation.properties as Record<string, Record<string, unknown>>;
    expect(docProps.ORG_URL?.pattern).toBe('^https://');
    expect(docProps.ORG_NAME).toBeDefined();
    expect(docProps.ORG_DESCRIPTION).toBeDefined();
  });

  it('carries the currency status and anchor_asset_type enums', () => {
    const currencies = properties.CURRENCIES as Record<string, unknown>;
    const items = currencies.items as Record<string, unknown>;
    const currencyProps = items.properties as Record<string, Record<string, unknown>>;
    expect(currencyProps.status?.enum).toEqual([...CURRENCY_STATUSES]);
    expect(currencyProps.anchor_asset_type?.enum).toEqual([...ANCHOR_ASSET_TYPES]);
  });

  it('validates account IDs as G... base32 strings', () => {
    expect(properties.SIGNING_KEY?.pattern).toBe('^G[A-Z2-7]{55}$');
    const validators = properties.VALIDATORS as Record<string, unknown>;
    const items = validators.items as Record<string, unknown>;
    const validatorProps = items.properties as Record<string, Record<string, unknown>>;
    expect(validatorProps.PUBLIC_KEY?.pattern).toBe('^G[A-Z2-7]{55}$');
  });

  it('rejects unknown top-level fields', () => {
    expect(schema.additionalProperties).toBe(false);
  });

  it('returns a fresh object on each call', () => {
    const a = getTomlJsonSchema();
    const b = getTomlJsonSchema();
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });
});
