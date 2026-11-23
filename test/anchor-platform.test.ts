import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse } from 'smol-toml';
import {
  generateAnchorPlatformConfig,
  formatAnchorPlatformYaml,
} from '../src/generators/anchor-platform.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, 'fixtures', name), 'utf8');

describe('anchor platform config generator', () => {
  const doc = parse(fixture('valid.toml')) as Record<string, unknown>;
  const config = generateAnchorPlatformConfig(doc);

  it('maps currencies to assets', () => {
    expect(config.assets.length).toBeGreaterThan(0);
    expect(config.assets[0]?.code).toBe('USDX');
  });

  it('includes issuer in asset schema', () => {
    const usdx = config.assets.find((a) => a.code === 'USDX');
    expect(usdx?.issuer).toBeDefined();
    expect(usdx?.schema).toContain('stellar:USDX:');
  });

  it('maps SEP-10 settings', () => {
    expect(config.sep10?.web_auth_endpoint).toBe('https://api.example.com/auth');
    expect(config.sep10?.signing_key).toBeDefined();
  });

  it('maps SEP-24 settings', () => {
    expect(config.sep24?.interactive_url).toBe('https://api.example.com/sep24');
  });

  it('maps SEP-38 settings', () => {
    expect(config.sep38?.quote_server).toBe('https://api.example.com/sep38');
  });

  it('formats valid YAML output', () => {
    const yaml = formatAnchorPlatformYaml(config);
    expect(yaml).toContain('assets:');
    expect(yaml).toContain('code: "USDX"');
    expect(yaml).toContain('sep10:');
  });

  it('enables deposit/withdraw for assets when SEP-24 is declared', () => {
    const usdx = config.assets.find((a) => a.code === 'USDX');
    expect(usdx?.deposit?.enabled).toBe(true);
    expect(usdx?.withdraw?.enabled).toBe(true);
  });
});
