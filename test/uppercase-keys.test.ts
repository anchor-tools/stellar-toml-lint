import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { LintResult } from '../src/types.js';

const ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

function find(result: LintResult, rule: string) {
  return result.diagnostics.filter((d) => d.rule === rule);
}

/** Wraps a body so rules that need a minimal valid document stay quiet. */
function withValidBase(body: string): string {
  return [
    'VERSION="2.7.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    '',
    body,
  ].join('\n');
}

describe('general/lowercase-public-key', () => {
  it('passes on an uppercase SIGNING_KEY', () => {
    const result = lint(`SIGNING_KEY="${ACCOUNT}"`);
    expect(find(result, 'general/lowercase-public-key')).toEqual([]);
  });

  it('passes on an uppercase currency issuer', () => {
    const result = lint(
      withValidBase(`[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT}"\nis_unlimited=true`),
    );
    expect(find(result, 'general/lowercase-public-key')).toEqual([]);
  });

  it('passes on an uppercase validator PUBLIC_KEY', () => {
    const result = lint(
      withValidBase(
        `[[VALIDATORS]]\nALIAS="node-1"\nPUBLIC_KEY="${ACCOUNT}"\nHOST="core.example.com:11625"`,
      ),
    );
    expect(find(result, 'general/lowercase-public-key')).toEqual([]);
  });

  it('flags a lowercase SIGNING_KEY with a warning', () => {
    const lower = ACCOUNT.toLowerCase();
    const result = lint(`SIGNING_KEY="${lower}"`);
    const [d] = find(result, 'general/lowercase-public-key');

    expect(d).toBeDefined();
    expect(d?.severity).toBe('warning');
    expect(d?.rule).toBe('general/lowercase-public-key');
    expect(d?.path).toBe('SIGNING_KEY');
    expect(d?.message).toContain('lowercase');
  });

  it('suggests the uppercase equivalent for SIGNING_KEY', () => {
    const lower = ACCOUNT.toLowerCase();
    const result = lint(`SIGNING_KEY="${lower}"`);
    const [d] = find(result, 'general/lowercase-public-key');

    expect(d?.suggestion).toContain(ACCOUNT);
  });

  it('flags a lowercase currency issuer', () => {
    const lower = ACCOUNT.toLowerCase();
    const result = lint(
      withValidBase(`[[CURRENCIES]]\ncode="AAA"\nissuer="${lower}"\nis_unlimited=true`),
    );
    const [d] = find(result, 'general/lowercase-public-key');

    expect(d?.severity).toBe('warning');
    expect(d?.path).toBe('CURRENCIES[0].issuer');
    expect(d?.suggestion).toContain(ACCOUNT);
  });

  it('flags a lowercase validator PUBLIC_KEY', () => {
    const lower = ACCOUNT.toLowerCase();
    const result = lint(
      withValidBase(
        `[[VALIDATORS]]\nALIAS="node-1"\nPUBLIC_KEY="${lower}"\nHOST="core.example.com:11625"`,
      ),
    );
    const [d] = find(result, 'general/lowercase-public-key');

    expect(d?.severity).toBe('warning');
    expect(d?.path).toBe('VALIDATORS[0].PUBLIC_KEY');
    expect(d?.suggestion).toContain(ACCOUNT);
  });

  it('flags a mixed-case key', () => {
    const mixed = ACCOUNT.slice(0, 10) + ACCOUNT.slice(10).toLowerCase();
    const result = lint(`SIGNING_KEY="${mixed}"`);
    expect(find(result, 'general/lowercase-public-key')).toHaveLength(1);
  });

  it('stays silent when the field is missing', () => {
    const result = lint('VERSION="2.7.0"');
    expect(find(result, 'general/lowercase-public-key')).toEqual([]);
  });

  it('stays silent on a non-string value', () => {
    // Structurally wrong type — this rule only cares about string casing.
    const result = lint('SIGNING_KEY=42');
    expect(find(result, 'general/lowercase-public-key')).toEqual([]);
  });

  it('can be disabled with --off', () => {
    const lower = ACCOUNT.toLowerCase();
    const result = lint(`SIGNING_KEY="${lower}"`, {
      rules: { 'general/lowercase-public-key': 'off' },
    });
    expect(find(result, 'general/lowercase-public-key')).toEqual([]);
  });

  it('does not fire on the valid fixture', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { dirname, join } = await import('node:path');
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');
    expect(find(lint(source), 'general/lowercase-public-key')).toEqual([]);
  });
});
