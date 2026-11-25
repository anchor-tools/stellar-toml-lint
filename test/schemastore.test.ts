import { describe, expect, it } from 'vitest';
import { generateJsonSchema, generateCatalogEntry } from '../scripts/sync-schemastore.js';

describe('SchemaStore JSON Schema generator', () => {
  describe('draft-07', () => {
    const schema = generateJsonSchema('07');

    it('uses draft-07 $schema', () => {
      expect(schema.$schema).toBe('http://json-schema.org/draft-07/schema#');
    });

    it('has required top-level fields', () => {
      expect(schema.title).toContain('stellar.toml');
      expect(schema.type).toBe('object');
      expect(schema.properties).toBeDefined();
    });

    it('includes VERSION property', () => {
      const prop = schema.properties['VERSION'];
      expect(prop).toBeDefined();
      expect(prop!.type).toBe('string');
    });

    it('includes ACCOUNTS as array', () => {
      const prop = schema.properties['ACCOUNTS'];
      expect(prop).toBeDefined();
      expect(prop!.type).toBe('array');
    });

    it('includes DOCUMENTATION as object', () => {
      const prop = schema.properties['DOCUMENTATION'];
      expect(prop).toBeDefined();
      expect(prop!.type).toBe('object');
      expect(prop!.properties).toBeDefined();
    });

    it('includes CURRENCIES as array of objects', () => {
      const prop = schema.properties['CURRENCIES'];
      expect(prop).toBeDefined();
      expect(prop!.type).toBe('array');
    });

    it('includes VALIDATORS as array of objects', () => {
      const prop = schema.properties['VALIDATORS'];
      expect(prop).toBeDefined();
      expect(prop!.type).toBe('array');
    });

    it('enforces Stellar key pattern on SIGNING_KEY', () => {
      const prop = schema.properties['SIGNING_KEY'];
      expect(prop).toBeDefined();
      expect(prop?.pattern).toMatch(/\^G/);
    });
  });

  describe('draft-2020-12', () => {
    const schema = generateJsonSchema('2020-12');

    it('uses draft-2020-12 $schema', () => {
      expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    });
  });

  describe('catalog entry', () => {
    const entry = generateCatalogEntry();

    it('has name and fileMatch', () => {
      expect(entry.name).toBe('stellar.toml');
      expect(entry.fileMatch).toContain('stellar.toml');
    });

    it('points to the schema URL', () => {
      expect(entry.url).toContain('stellar-toml.json');
    });
  });
});
