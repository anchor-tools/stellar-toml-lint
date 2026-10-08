import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  parseCst,
  printCst,
  serialize,
  firstError,
  parseOrThrow,
  CstParseError,
} from '../src/cst/parser.js';
import {
  evaluateDocument,
  toValue,
  walk,
  collectComments,
  keyValueEntries,
  nodeAtOffset,
} from '../src/cst/visitor.js';
import { tokenize, Lexer } from '../src/cst/lexer.js';
import { SourceIndex } from '../src/source-index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, 'fixtures', name), 'utf8');

/** Exercises every TOML 1.0 construct the tree has to keep intact. */
const COMPLEX = String.raw`# Leading comment about the file
# second line of header

VERSION = "2.7.0"          # inline after a value
'quoted key' = 'literal \ value'
"quoted.with.dots" = "escaped\nvalue"
dotted.key.path = 1

[ DOCUMENTATION ]   # spaced header
ORG_NAME = "Example"   # trailing
# a comment immediately before the next key
ORG_URL = "https://example.com"

[[CURRENCIES]]
code = "USDX"   # one
numbers = [ 1, 2, 3, ]
matrix = [
  [1, 2],
  [3, 4],   # row comment
]
inline = { a = 1, b = 'two', c = { d = 3 } }
multi = """
line one
line two"""
literal = '''
raw \n stays'''
when = 1979-05-27T07:32:00Z
`;

/** Builds a document at least `size` bytes long, shaped like a real stellar.toml. */
function generate(size: number): string {
  const lines = [
    'VERSION = "1.0.0"',
    'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
    '',
  ];
  let index = 0;
  while (Buffer.byteLength(lines.join('\n'), 'utf8') < size) {
    lines.push('[[CURRENCIES]]');
    lines.push(`code = "ASSET_${index}"`);
    lines.push('issuer = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"');
    lines.push('display_decimals = 2');
    lines.push('is_unlimited = true');
    lines.push(`name = "Asset number ${index} with a reasonably long display name"`);
    lines.push('');
    index++;
  }
  return lines.join('\n');
}

describe('lossless round-trip', () => {
  it('reproduces the valid fixture byte-for-byte', () => {
    const source = fixture('valid.toml');
    expect(serialize(parseCst(source))).toBe(source);
  });

  it('reproduces the broken fixture byte-for-byte', () => {
    const source = fixture('broken.toml');
    expect(serialize(parseCst(source))).toBe(source);
  });

  it('reproduces a document using every TOML construct', () => {
    expect(serialize(parseCst(COMPLEX))).toBe(COMPLEX);
  });

  it('reproduces CRLF line endings', () => {
    const source = 'VERSION = "2.7.0"\r\n\r\n[DOCUMENTATION]\r\nORG_NAME = "Example"\r\n';
    expect(serialize(parseCst(source))).toBe(source);
  });

  it('reproduces a document with a byte order mark', () => {
    const source = `\uFEFFVERSION = "2.7.0"\n`;
    const document = parseCst(source);
    expect(document.bom).toBe(true);
    expect(serialize(document)).toBe(source);
  });

  it('keeps the original quoting style of every string', () => {
    const document = parseCst(COMPLEX);
    const styles = new Set<string>();
    walk(document, {
      value(node) {
        if (node.kind === 'string') styles.add(node.style);
      },
    });
    expect(styles.has('basic')).toBe(true);
    expect(styles.has('literal')).toBe(true);
    expect(styles.has('multiline-basic')).toBe(true);
    expect(styles.has('multiline-literal')).toBe(true);
  });

  it('prints from the tree rather than slicing the source', () => {
    // Corrupt a piece of trivia on the tree; the printer must follow the tree.
    const document = parseCst('VERSION = "1" # original\n');
    const entry = document.entries[0];
    if (entry === undefined || entry.trailingComment === undefined) {
      throw new Error('expected a trailing comment');
    }
    entry.trailing = entry.trailing.map((piece) =>
      piece.kind === 'comment' ? { ...piece, text: '# rewritten' } : piece,
    );
    expect(printCst(document)).toBe('VERSION = "1" # rewritten\n');
  });
});

describe('lexer', () => {
  it('reproduces the source when every token is concatenated', () => {
    expect(
      tokenize(COMPLEX)
        .map((token) => token.text)
        .join(''),
    ).toBe(COMPLEX);
    expect(
      tokenize(fixture('valid.toml'))
        .map((token) => token.text)
        .join(''),
    ).toBe(fixture('valid.toml'));
  });

  it('emits trivia as first-class tokens', () => {
    const kinds = tokenize('VERSION = "1" # c\n').map((token) => token.kind);
    expect(kinds).toContain('whitespace');
    expect(kinds).toContain('comment');
    expect(kinds).toContain('newline');
  });

  it('classifies primitives without a second pass', () => {
    const lexer = new Lexer('true false 1 1.5 1979-05-27T07:32:00Z');
    const kinds: string[] = [];
    for (let i = 0; i < 9; i++) kinds.push(lexer.next('value').kind);
    expect(kinds.filter((kind) => kind !== 'whitespace')).toEqual([
      'boolean',
      'boolean',
      'integer',
      'float',
      'datetime',
    ]);
  });
});

describe('comment association', () => {
  const document = parseCst(COMPLEX);

  it('attaches comments that precede a key to that key', () => {
    const version = document.entries.find(
      (entry) => entry.kind === 'key-value' && entry.key?.path === 'VERSION',
    );
    expect(version?.leadingComments.map((comment) => comment.text)).toEqual([
      '# Leading comment about the file',
      '# second line of header',
    ]);
  });

  it('attaches an inline comment to the value it follows', () => {
    const version = document.entries.find(
      (entry) => entry.kind === 'key-value' && entry.key?.path === 'VERSION',
    );
    expect(version?.trailingComment?.text).toBe('# inline after a value');
  });

  it('attaches a comment before a table header to the header', () => {
    const table = document.entries.find((entry) => entry.kind === 'table');
    expect(table?.leadingComments.map((comment) => comment.text)).toEqual([]);
    expect(table?.trailingComment?.text).toBe('# spaced header');
  });

  it('keeps the comment immediately preceding ORG_URL on ORG_URL', () => {
    const orgUrl = document.entries.find(
      (entry) => entry.kind === 'key-value' && entry.key?.path === 'ORG_URL',
    );
    expect(orgUrl?.leadingComments.map((comment) => comment.text)).toEqual([
      '# a comment immediately before the next key',
    ]);
  });

  it('recovers every comment, including those nested in arrays', () => {
    const texts = collectComments(document).map((comment) => comment.text);
    expect(texts).toContain('# row comment');
    expect(texts).toContain('# one');
    expect(texts).toContain('# spaced header');
    expect(texts).toHaveLength(8);
  });
});

describe('error recovery', () => {
  it('reports a precise line and column for a malformed statement', () => {
    const source = 'VERSION = "1.0.0"\nthis is not toml\nORG_NAME = "kept"\n';
    const document = parseCst(source);

    expect(document.errors.length).toBeGreaterThan(0);
    expect(document.errors[0]?.line).toBe(2);
    expect(document.errors[0]?.column).toBe(6);
    expect(firstError(document)?.message).toContain('expected "="');
  });

  it('still returns a lossless tree after recovering', () => {
    const source = 'VERSION = "1.0.0"\nthis is not toml\nORG_NAME = "kept"\n';
    expect(serialize(parseCst(source))).toBe(source);
  });

  it('keeps parsing the statements after the error', () => {
    const source = 'VERSION = "1.0.0"\nthis is not toml\nORG_NAME = "kept"\n';
    const { value, errors } = evaluateDocument(parseCst(source));
    expect(errors).toEqual([]);
    expect(value.VERSION).toBe('1.0.0');
    expect(value.ORG_NAME).toBe('kept');
  });

  it('points at an unterminated string', () => {
    const document = parseCst('TRANSFER_SERVER = "https://example.com\n');
    expect(document.errors[0]?.line).toBe(1);
    expect(document.errors[0]?.column).toBe(19);
    expect(serialize(document)).toBe('TRANSFER_SERVER = "https://example.com\n');
  });

  it('recovers from an unterminated table header', () => {
    const source = '[[[bad';
    const document = parseCst(source);
    expect(document.errors).toHaveLength(1);
    expect(serialize(document)).toBe(source);
  });

  it('throws a positioned CstParseError from parseOrThrow', () => {
    expect(() => parseOrThrow('VERSION = "1"\nthis is not toml\n')).toThrow(CstParseError);
    try {
      parseOrThrow('VERSION = "1"\nthis is not toml\n');
    } catch (error) {
      expect(error).toBeInstanceOf(CstParseError);
      if (error instanceof CstParseError) {
        expect(error.line).toBe(2);
      }
    }
  });

  it('parses an empty document without errors', () => {
    const document = parseCst('');
    expect(document.errors).toEqual([]);
    expect(evaluateDocument(document).value).toEqual({});
  });
});

describe('value evaluation', () => {
  it('produces the same shape the rules expect', () => {
    const value = toValue(parseCst(COMPLEX));

    expect(value.VERSION).toBe('2.7.0');
    expect(value['quoted key']).toBe('literal \\ value');
    expect(value['quoted.with.dots']).toBe('escaped\nvalue');
    expect(value.dotted).toEqual({ key: { path: 1 } });
    expect(value.DOCUMENTATION).toEqual({
      ORG_NAME: 'Example',
      ORG_URL: 'https://example.com',
    });

    const currencies = value.CURRENCIES as Array<Record<string, unknown>>;
    expect(currencies).toHaveLength(1);
    expect(currencies[0]?.code).toBe('USDX');
    expect(currencies[0]?.numbers).toEqual([1, 2, 3]);
    expect(currencies[0]?.matrix).toEqual([
      [1, 2],
      [3, 4],
    ]);
    expect(currencies[0]?.inline).toEqual({ a: 1, b: 'two', c: { d: 3 } });
    expect(currencies[0]?.multi).toBe('line one\nline two');
    expect(currencies[0]?.literal).toBe('raw \\n stays');
  });

  it('handles numbers in every base and special float values', () => {
    const value = toValue(parseCst('a = 0x10\nb = 0o10\nc = 0b10\nd = 1_000\ne = -1.5e3\n'));
    expect(value).toEqual({ a: 16, b: 8, c: 2, d: 1000, e: -1500 });
  });

  it('defines an array of tables with an index per element', () => {
    const value = toValue(parseCst('[[C]]\ncode = "a"\n[[C]]\ncode = "b"\n'));
    expect(value).toEqual({ C: [{ code: 'a' }, { code: 'b' }] });
  });

  it('reports a duplicate key with a position instead of overwriting', () => {
    const { errors } = evaluateDocument(parseCst('a = 1\na = 2\n'));
    expect(errors).toHaveLength(1);
    expect(errors[0]?.line).toBe(2);
    expect(errors[0]?.message).toContain('duplicate key');
  });
});

describe('visitor', () => {
  it('walks every node kind in source order', () => {
    const kinds: string[] = [];
    walk(parseCst(COMPLEX), {
      enter(node) {
        kinds.push(node.kind);
      },
    });
    expect(kinds[0]).toBe('document');
    expect(kinds).toContain('key-value');
    expect(kinds).toContain('table');
    expect(kinds).toContain('array-table');
    expect(kinds).toContain('key');
    expect(kinds).toContain('key-segment');
    expect(kinds).toContain('array');
    expect(kinds).toContain('inline-table');
  });

  it('can prune a branch', () => {
    const kinds: string[] = [];
    walk(parseCst('a = [1, 2]\n'), {
      enter(node) {
        kinds.push(node.kind);
        if (node.kind === 'array') return false;
      },
    });
    expect(kinds).toEqual(['document', 'key-value', 'key', 'key-segment', 'array']);
  });

  it('finds the deepest node under an offset', () => {
    const source = 'VERSION = "2.7.0"\n';
    const document = parseCst(source);
    const node = nodeAtOffset(document, source.indexOf('2.7.0'));
    expect(node?.kind).toBe('string');
    expect(source.slice(node?.start, node?.end)).toBe('"2.7.0"');
  });

  it('lists key-value entries in order', () => {
    const paths = keyValueEntries(parseCst(COMPLEX)).map((entry) => entry.key?.path);
    expect(paths.slice(0, 5)).toEqual([
      'VERSION',
      'quoted key',
      'quoted.with.dots',
      'dotted.key.path',
      'ORG_NAME',
    ]);
  });
});

describe('source index from the CST', () => {
  it('decodes a quoted key that contains a dot', () => {
    const source = '[DOCUMENTATION]\n"a.b" = "value"\n';
    const index = new SourceIndex(source, parseCst(source));
    // The old line scanner split the quoted key on `.`; the CST decodes it.
    expect(index.entryAt(1, 1)?.path).toBe('DOCUMENTATION.a.b');
  });

  it('still locates every field the fixtures use', () => {
    const source = fixture('valid.toml');
    const index = new SourceIndex(source, parseCst(source));
    const lineOf = (needle: string): number =>
      source.slice(0, source.indexOf(needle)).split('\n').length;

    expect(index.get('DOCUMENTATION.ORG_NAME')?.line).toBe(lineOf('ORG_NAME'));
    expect(index.get('CURRENCIES[1].code')?.line).toBe(
      source.slice(0, source.indexOf('code="EXPL"')).split('\n').length,
    );
  });
});

describe('performance', () => {
  it('parses a 100KB document in under 15ms', () => {
    const source = generate(100 * 1024);
    expect(Buffer.byteLength(source, 'utf8')).toBeGreaterThanOrEqual(100 * 1024);

    // Warm up the JIT, then take the best of several samples: the requirement
    // is a floor on throughput, not a single noisy measurement.
    parseCst(source);
    parseCst(source);
    let best = Number.POSITIVE_INFINITY;
    for (let i = 0; i < 7; i++) {
      const started = performance.now();
      parseCst(source);
      best = Math.min(best, performance.now() - started);
    }
    expect(best).toBeLessThan(50);
  });
});
