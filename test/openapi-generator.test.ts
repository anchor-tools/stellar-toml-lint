import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse } from 'smol-toml';
import { generateOpenApiSpec } from '../src/generators/openapi.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, 'fixtures', name), 'utf8');

describe('OpenAPI 3.1 generator', () => {
  const doc = parse(fixture('valid.toml')) as Record<string, unknown>;
  const spec = generateOpenApiSpec(doc);

  it('produces a valid OpenAPI 3.1 document', () => {
    expect(spec.openapi).toBe('3.1.0');
    expect(spec.info.title).toBe('Stellar Anchor API');
    expect(spec.info.version).toBe('1.0.0');
  });

  it('includes servers from declared endpoints', () => {
    expect(spec.servers.length).toBeGreaterThan(0);
    expect(spec.servers.some((s) => s.url.includes('example.com'))).toBe(true);
  });

  it('generates paths for declared SEP endpoints', () => {
    const pathKeys = Object.keys(spec.paths);
    expect(pathKeys.length).toBeGreaterThan(0);
  });

  it('includes SEP-6 paths when TRANSFER_SERVER is declared', () => {
    expect(spec.paths['/deposit']).toBeDefined();
    expect(spec.paths['/withdraw']).toBeDefined();
    expect(spec.paths['/info']).toBeDefined();
  });

  it('includes SEP-24 paths when TRANSFER_SERVER_SEP0024 is declared', () => {
    expect(spec.paths['/transactions/deposit/interactive']).toBeDefined();
  });

  it('includes SEP-38 paths when ANCHOR_QUOTE_SERVER is declared', () => {
    expect(spec.paths['/prices']).toBeDefined();
    expect(spec.paths['/quote']).toBeDefined();
  });

  it('links declared currencies in the description', () => {
    expect(spec.info.description).toContain('USDX');
    expect(spec.info.description).toContain('EXPL');
  });

  it('adds asset_code parameter to deposit/withdraw endpoints', () => {
    const depositOp = spec.paths['/deposit']?.['get'];
    expect(depositOp?.parameters).toBeDefined();
    expect(depositOp?.parameters?.some((p) => p.name === 'asset_code')).toBe(true);
  });
});
