import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CANONICAL_ARRAY_ORDER,
  CANONICAL_KEY_ORDER,
  CanonicalSortCodemod,
  sortCanonical,
} from '../src/cst/canonicalSortCodemod.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => join(here, 'fixtures', name);

/** Keys of a `[[CURRENCIES]]` block, in the order they are written. */
function keysOf(source: string, occurrence = 0): string[] {
  let seen = -1;
  const keys: string[] = [];
  let inside = false;
  for (const line of source.split('\n')) {
    if (line.startsWith('[[')) {
      inside = ++seen === occurrence;
      continue;
    }
    if (line.startsWith('[')) {
      inside = false;
      continue;
    }
    if (!inside) continue;
    const match = /^([A-Za-z0-9_.]+)\s*=/.exec(line);
    if (match?.[1] !== undefined) keys.push(match[1]);
  }
  return keys;
}

/** Header lines in the order they ended up in. */
function headersOf(source: string): string[] {
  return source
    .split('\n')
    .filter((line) => line.startsWith('['))
    .map((line) => line.trim());
}

describe('sortCanonical', () => {
  it('puts the canonical currency fields first', () => {
    const source = [
      '[[CURRENCIES]]',
      'status = "live"',
      'issuer = "GABC"',
      'name = "USD Coin"',
      'code = "USDC"',
      '',
    ].join('\n');

    const result = sortCanonical(source);

    expect(result.changed).toBe(true);
    expect(keysOf(result.output)).toEqual(['code', 'issuer', 'status', 'name']);
    expect(result.tablesSorted).toContain('CURRENCIES');
  });

  it('carries an attached comment along with the key it annotates', () => {
    const source = [
      '[[CURRENCIES]]',
      '# the issuing account',
      'issuer = "GABC"',
      '# the asset code',
      'code = "USDC"',
      '',
    ].join('\n');

    const output = sortCanonical(source).output;

    expect(output).toContain('# the asset code\ncode = "USDC"');
    expect(output).toContain('# the issuing account\nissuer = "GABC"');
    expect(output.indexOf('# the asset code')).toBeLessThan(
      output.indexOf('# the issuing account'),
    );
  });

  it('keeps the blank line at its slot and the comment with its key', () => {
    const source = [
      '[[CURRENCIES]]',
      'issuer = "GABC"',
      '',
      '# separated by a blank line',
      'code = "USDC"',
      '',
    ].join('\n');

    const result = sortCanonical(source);

    // The comment sits directly above `code`, so it annotates `code` and moves
    // with it. The blank line is what the *layout* owns, so it stays in the
    // second slot and the file keeps exactly one gap between its two keys.
    expect(result.output).toBe(
      '[[CURRENCIES]]\n# separated by a blank line\ncode = "USDC"\n\nissuer = "GABC"\n',
    );
    const blankLines = (text: string) => text.split('\n').filter((line) => line === '').length;
    expect(blankLines(result.output)).toBe(blankLines(source));
    expect(sortCanonical(result.output).output).toBe(result.output);
  });

  it('leaves unknown keys at the end in the order the author wrote them', () => {
    const source = [
      '[[CURRENCIES]]',
      'zeta = 1',
      'code = "USDC"',
      'alpha = 2',
      'issuer = "GABC"',
      '',
    ].join('\n');

    expect(keysOf(sortCanonical(source).output)).toEqual(['code', 'issuer', 'zeta', 'alpha']);
  });

  it('sorts currency entries by code and validators by public key', () => {
    const source = [
      '[[CURRENCIES]]',
      'code = "USDC"',
      '',
      '[[CURRENCIES]]',
      'code = "ALPHA"',
      '',
      '[[CURRENCIES]]',
      'code = "beta"',
      '',
      '[[VALIDATORS]]',
      'public_key = "GDDH"',
      '',
      '[[VALIDATORS]]',
      'public_key = "AAAA"',
      '',
    ].join('\n');

    const result = sortCanonical(source);
    const codes = [...result.output.matchAll(/code = "([^"]+)"/g)].map((match) => match[1]);
    const keys = [...result.output.matchAll(/public_key = "([^"]+)"/g)].map((match) => match[1]);

    expect(codes).toEqual(['ALPHA', 'beta', 'USDC']);
    expect(keys).toEqual(['AAAA', 'GDDH']);
    expect(result.arraysSorted).toEqual(['CURRENCIES', 'VALIDATORS']);
  });

  it('is idempotent and reports no change on the second pass', () => {
    const source = [
      '[[CURRENCIES]]',
      'issuer = "GABC"',
      'code = "USDC"',
      'custom = 1',
      '',
      '[[CURRENCIES]]',
      'code = "ALPHA"',
      'issuer = "GDEF"',
      '',
    ].join('\n');

    const once = sortCanonical(source);
    const twice = sortCanonical(once.output);
    const thrice = sortCanonical(twice.output);

    expect(twice.changed).toBe(false);
    expect(twice.output).toBe(once.output);
    expect(thrice.output).toBe(once.output);
  });

  it('returns the file untouched when it is already canonical', () => {
    const source = [
      '[[CURRENCIES]]',
      'code = "ALPHA"',
      'issuer = "GDEF"',
      '',
      '[[CURRENCIES]]',
      'code = "USDC"',
      'issuer = "GABC"',
      '',
    ].join('\n');

    const result = sortCanonical(source);

    expect(result.changed).toBe(false);
    expect(result.output).toBe(source);
    expect(result.tablesSorted).toEqual([]);
    expect(result.arraysSorted).toEqual([]);
  });

  it('refuses to reorder a file that does not parse', () => {
    const source = '[[CURRENCIES]\ncode = ';

    const result = sortCanonical(source);

    expect(result.output).toBe(source);
    expect(result.changed).toBe(false);
    expect(result.warnings).toContain('file does not parse; nothing was reordered');
  });

  it('leaves a table it has no canonical order for alone', () => {
    const source = ['[CUSTOM_SECTION]', 'zebra = 1', 'apple = 2', ''].join('\n');

    const result = sortCanonical(source);

    expect(result.changed).toBe(false);
    expect(result.output).toBe(source);
  });

  it('does not sort an array whose entries are not contiguous', () => {
    const source = [
      '[[CURRENCIES]]',
      'code = "USDC"',
      '',
      '[DOCUMENTATION]',
      'ORG_NAME = "Example"',
      '',
      '[[CURRENCIES]]',
      'code = "ALPHA"',
      '',
    ].join('\n');

    expect(headersOf(sortCanonical(source).output)).toEqual([
      '[[CURRENCIES]]',
      '[DOCUMENTATION]',
      '[[CURRENCIES]]',
    ]);
  });

  it('leaves an array run alone when an entry is missing the identity key', () => {
    const source = [
      '[[CURRENCIES]]',
      'code = "USDC"',
      '',
      '[[CURRENCIES]]',
      'issuer = "GDEF"',
      '',
    ].join('\n');

    const result = sortCanonical(source);

    expect(result.arraysSorted).toEqual([]);
    expect(result.warnings.some((warning) => warning.includes('no `code`'))).toBe(true);
  });

  it('preserves every byte it does not have to move', () => {
    const source = [
      '# file header',
      'VERSION = "2.7.0"',
      '',
      '[[CURRENCIES]]',
      'code = "USDC"',
      'name = """',
      'multi',
      '"""',
      'issuer = "GABC" # trailing comment',
      'status = "live"',
      '',
    ].join('\n');

    const output = sortCanonical(source).output;

    expect(output).toContain('# file header\nVERSION = "2.7.0"');
    expect(output).toContain('name = """\nmulti\n"""');
    expect(output).toContain('issuer = "GABC" # trailing comment');
    expect(keysOf(output)).toEqual(['code', 'issuer', 'status', 'name']);
  });

  it('sorts dotted keys inside a sub-table against their last segment', () => {
    const source = ['[[CURRENCIES]]', 'code = "USDC"', 'sep38 = true', 'issuer = "GABC"', ''].join(
      '\n',
    );

    expect(keysOf(sortCanonical(source).output)).toEqual(['code', 'issuer', 'sep38']);
  });

  it('matches quoted keys with the decoded name', () => {
    const source = ['[[CURRENCIES]]', '"issuer" = "GABC"', '"code" = "USDC"', ''].join('\n');

    const output = sortCanonical(source).output;

    expect(output.indexOf('"code"')).toBeLessThan(output.indexOf('"issuer"'));
    // Quoting is the author's, not ours to change.
    expect(output).toContain('"code" = "USDC"');
  });

  it('keeps the preamble before the first table where it was written', () => {
    const source = ['SIGNING_KEY = "GABC"', 'VERSION = "2.7.0"', ''].join('\n');

    const result = sortCanonical(source);

    expect(result.changed).toBe(false);
    expect(result.output).toBe(source);
  });

  it('orders documentation fields the way SEP-1 lists them', () => {
    const source = [
      '[DOCUMENTATION]',
      'ORG_SUPPORT_EMAIL = "support@example.com"',
      'ORG_URL = "https://example.com"',
      'ORG_NAME = "Example Anchor"',
      'ORG_LOGO = "https://example.com/logo.png"',
      '',
    ].join('\n');

    const output = sortCanonical(source).output;
    const order = [...output.matchAll(/^(ORG_[A-Z_]+) =/gm)].map((match) => match[1]);

    expect(order).toEqual(['ORG_NAME', 'ORG_URL', 'ORG_LOGO', 'ORG_SUPPORT_EMAIL']);
  });

  it('orders principal fields the way SEP-1 lists them', () => {
    const source = [
      '[[PRINCIPALS]]',
      'keybase = "crypto_jane"',
      'email = "jane@example.com"',
      'name = "Jane Johnson"',
      '',
    ].join('\n');

    expect(keysOf(sortCanonical(source).output)).toEqual(['name', 'email', 'keybase']);
  });

  it('sorts validators by PUBLIC_KEY however the author spelled the key', () => {
    const source = [
      '[[VALIDATORS]]',
      'PUBLIC_KEY = "GC7T6T56"',
      'ALIAS = "us"',
      '',
      '[[VALIDATORS]]',
      'public_key = "GBXHQL5S"',
      'HOST = "core-eu.example.com:11625"',
      '',
    ].join('\n');

    const result = sortCanonical(source);

    // `B` sorts before `C`, and the lowercase spelling is still the identity key
    // and still ranks where SEP-1 puts PUBLIC_KEY.
    expect(result.arraysSorted).toEqual(['VALIDATORS']);
    expect(keysOf(result.output)).toEqual(['public_key', 'HOST']);
    expect(keysOf(result.output, 1)).toEqual(['ALIAS', 'PUBLIC_KEY']);
  });

  it('exposes the canonical tables the codemod knows about', () => {
    expect(Object.keys(CANONICAL_KEY_ORDER)).toEqual([
      'DOCUMENTATION',
      'PRINCIPALS',
      'CURRENCIES',
      'VALIDATORS',
    ]);
    // The order comes from `src/spec.ts`, so a field a future SEP adds lands in
    // the same place here and in `--json-schema`.
    expect(CANONICAL_KEY_ORDER.CURRENCIES?.slice(0, 3)).toEqual(['code', 'issuer', 'contract']);
    expect(CANONICAL_KEY_ORDER.VALIDATORS?.[0]).toBe('ALIAS');
    expect(CANONICAL_ARRAY_ORDER.CURRENCIES).toBe('code');
    expect(CANONICAL_ARRAY_ORDER.VALIDATORS).toBe('PUBLIC_KEY');
  });

  it('moves lines without losing or inventing one', async () => {
    const source = await readFile(fixture('valid.toml'), 'utf8');

    const once = sortCanonical(source);
    const twice = sortCanonical(once.output);
    const comments = (text: string) =>
      text.split('\n').filter((line) => line.trim().startsWith('#'));

    expect(once.changed).toBe(true);
    expect(twice.changed).toBe(false);
    // Same characters, same comments: the reorder is a permutation, not a rewrite.
    expect([...once.output].sort()).toEqual([...source].sort());
    expect(comments(once.output)).toEqual(comments(source));
    // Nothing in the fixture is a custom key, so no known field may end up
    // behind an unknown one. `[[` block 0 is the principal and block 1 the first
    // currency, which after sorting by code is the SEP-41 `EXPL` entry — it
    // carries a contract instead of an issuer.
    const canonical = new Set(CANONICAL_KEY_ORDER.CURRENCIES ?? []);
    const currencies = keysOf(once.output, 1);
    expect(currencies.filter((key) => !canonical.has(key))).toEqual([]);
    expect(currencies.slice(0, 2)).toEqual(['code', 'contract']);
  });

  it('is usable as the stateless codemod the issue names', () => {
    const source = ['[[CURRENCIES]]', 'issuer = "GABC"', 'code = "USDC"', ''].join('\n');
    const codemod = new CanonicalSortCodemod();

    const result = codemod.run(source);

    expect(result.output).toBe(sortCanonical(source).output);
    // One instance serves every file in a run, so nothing may accumulate between
    // calls: the sorted text is already canonical and says so.
    expect(codemod.run(result.output).changed).toBe(false);
  });
});
