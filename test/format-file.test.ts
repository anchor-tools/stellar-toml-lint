import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse } from 'smol-toml';
import { formatToml } from '../src/format-file.js';
import { lint } from '../src/lint.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, 'fixtures', name), 'utf8');

/** Formats, failing the test loudly if the formatter refused. */
function format(source: string): string {
  const result = formatToml(source);
  if (!result.ok) throw new Error(`expected a formatted file, got: ${result.error}`);
  return result.output;
}

/** Formatting twice must be the same as formatting once. */
function expectIdempotent(source: string): void {
  const once = format(source);
  expect(formatToml(once)).toEqual({ ok: true, output: once, changed: false });
}

/** The output must parse to exactly the document the input parsed to. */
function expectRoundTrip(source: string): void {
  expect(parse(format(source))).toEqual(parse(source));
}

describe('field order', () => {
  it('puts global fields in SEP-1 order', () => {
    const input = ['ACCOUNTS = ["GABC"]', 'VERSION = "2.0.0"', 'NETWORK_PASSPHRASE = "net"'].join(
      '\n',
    );
    expect(format(input)).toBe(
      ['VERSION = "2.0.0"', 'NETWORK_PASSPHRASE = "net"', 'ACCOUNTS = ["GABC"]'].join('\n'),
    );
  });

  it('keeps unrecognised fields after the known ones, in written order', () => {
    const input = ['SOMETHING_NEW = 1', 'HORIZON_URL = "https://h.example"', 'ANOTHER = 2'].join(
      '\n',
    );
    expect(format(input)).toBe(
      ['HORIZON_URL = "https://h.example"', 'SOMETHING_NEW = 1', 'ANOTHER = 2'].join('\n'),
    );
  });

  it('orders [DOCUMENTATION] fields by the spec table', () => {
    const input = [
      '[DOCUMENTATION]',
      'ORG_URL = "https://example.com"',
      'ORG_NAME = "Example"',
      'ORG_DBA = "Ex"',
    ].join('\n');
    expect(format(input)).toBe(
      [
        '[DOCUMENTATION]',
        'ORG_NAME = "Example"',
        'ORG_DBA = "Ex"',
        'ORG_URL = "https://example.com"',
      ].join('\n'),
    );
  });

  it('orders [[CURRENCIES]], [[PRINCIPALS]] and [[VALIDATORS]] fields', () => {
    const currencies = format(
      ['[[CURRENCIES]]', 'desc = "d"', 'issuer = "GABC"', 'code = "USD"'].join('\n'),
    );
    expect(currencies).toBe(
      ['[[CURRENCIES]]', 'code = "USD"', 'issuer = "GABC"', 'desc = "d"'].join('\n'),
    );

    const principals = format(
      ['[[PRINCIPALS]]', 'github = "jane"', 'name = "Jane"', 'email = "jane@example.com"'].join(
        '\n',
      ),
    );
    expect(principals).toBe(
      ['[[PRINCIPALS]]', 'name = "Jane"', 'email = "jane@example.com"', 'github = "jane"'].join(
        '\n',
      ),
    );

    const validators = format(['[[VALIDATORS]]', 'HOST = "h:11625"', 'ALIAS = "node"'].join('\n'));
    expect(validators).toBe(['[[VALIDATORS]]', 'ALIAS = "node"', 'HOST = "h:11625"'].join('\n'));
  });

  it('leaves fields of an unknown table in written order', () => {
    const input = ['[MY_OWN_THING]', 'zeta = 1', 'alpha = 2'].join('\n');
    expect(format(input)).toBe(input);
  });
});

describe('section order', () => {
  it('emits SEP-1 sections in spec order and unknown sections last', () => {
    const input = [
      '[[VALIDATORS]]',
      'ALIAS = "a"',
      '',
      '[SOMETHING_ELSE]',
      'x = 1',
      '',
      '[DOCUMENTATION]',
      'ORG_NAME = "Example"',
      '',
      '[[CURRENCIES]]',
      'code = "USD"',
      '',
      '[[PRINCIPALS]]',
      'name = "Jane"',
    ].join('\n');

    expect(format(input)).toBe(
      [
        '[DOCUMENTATION]',
        'ORG_NAME = "Example"',
        '',
        '[[PRINCIPALS]]',
        'name = "Jane"',
        '',
        '[[CURRENCIES]]',
        'code = "USD"',
        '',
        '[[VALIDATORS]]',
        'ALIAS = "a"',
        '',
        '[SOMETHING_ELSE]',
        'x = 1',
      ].join('\n'),
    );
  });

  it('keeps entries of an array of tables in written order', () => {
    const input = [
      '[[CURRENCIES]]',
      'code = "BBB"',
      'desc = "second written, first kept"',
      '',
      '[[CURRENCIES]]',
      'code = "AAA"',
    ].join('\n');
    expect(format(input)).toBe(
      [
        '[[CURRENCIES]]',
        'code = "BBB"',
        'desc = "second written, first kept"',
        '',
        '[[CURRENCIES]]',
        'code = "AAA"',
      ].join('\n'),
    );
  });

  it('never moves a key out of the table it was written under', () => {
    const output = format(
      [
        '[[CURRENCIES]]',
        'desc = "d"',
        'code = "USD"',
        '',
        '[DOCUMENTATION]',
        'ORG_NAME = "x"',
      ].join('\n'),
    );
    const currencies = output.indexOf('[[CURRENCIES]]');
    const documentation = output.indexOf('[DOCUMENTATION]');
    expect(currencies).toBeGreaterThan(-1);
    expect(documentation).toBeGreaterThan(-1);
    // Sections reorder to spec order, but nothing crosses a boundary.
    expect(documentation).toBeLessThan(currencies);
    expect(output.indexOf('ORG_NAME = "x"')).toBeGreaterThan(documentation);
    expect(output.indexOf('ORG_NAME = "x"')).toBeLessThan(currencies);
    expect(output.indexOf('desc = "d"')).toBeGreaterThan(currencies);
    expect(output.indexOf('code = "USD"')).toBeGreaterThan(currencies);
  });

  it('keeps root fields above every section', () => {
    const output = format(
      [
        'NETWORK_PASSPHRASE = "net"',
        '',
        '[[VALIDATORS]]',
        'ALIAS = "a"',
        '',
        '[DOCUMENTATION]',
        'ORG_NAME = "x"',
      ].join('\n'),
    );
    expect(output.startsWith('NETWORK_PASSPHRASE = "net"')).toBe(true);
    expect(output.indexOf('[DOCUMENTATION]')).toBeLessThan(output.indexOf('[[VALIDATORS]]'));
  });

  it('does not hoist a global-looking key out of the table that holds it', () => {
    const output = format(['[DOCUMENTATION]', 'VERSION = "1"', 'ORG_NAME = "x"'].join('\n'));
    const header = output.indexOf('[DOCUMENTATION]');
    expect(header).toBe(0);
    expect(output.indexOf('VERSION = "1"')).toBeGreaterThan(header);
    expect(output.indexOf('ORG_NAME = "x"')).toBeGreaterThan(header);
  });
});

describe('comments', () => {
  it('keeps a trailing comment on its line', () => {
    expect(format('VERSION = "1.0.0"  # the version\n')).toBe('VERSION = "1.0.0" # the version\n');
  });

  it('moves a leading comment with the key it introduces', () => {
    const input = ['# the version', 'NETWORK_PASSPHRASE = "net"', 'VERSION = "1"'].join('\n');
    expect(format(input)).toBe(
      ['VERSION = "1"', '# the version', 'NETWORK_PASSPHRASE = "net"'].join('\n'),
    );
  });

  it('keeps a comment attached to the section header it introduces', () => {
    const input = ['VERSION = "1"', '# Who we are', '[DOCUMENTATION]', 'ORG_NAME = "Example"'].join(
      '\n',
    );
    expect(format(input)).toBe(
      ['VERSION = "1"', '', '# Who we are', '[DOCUMENTATION]', 'ORG_NAME = "Example"'].join('\n'),
    );
  });

  it('leaves a trailing comment block at the end of the file', () => {
    const input = ['VERSION = "1"', '', '# footer', '# more footer'].join('\n');
    expect(format(input)).toBe(input);
  });

  it('preserves comments written inside a multi-line array', () => {
    const input = ['ACCOUNTS = [', '  "GABC", # the signer', '  "GDEF"', ']'].join('\n');
    expect(format(input)).toBe(input);
  });
});

describe('whitespace', () => {
  it('normalises spacing around the equals sign', () => {
    expect(format('VERSION    =    "1"\n  ORG = 2\n')).toBe('VERSION = "1"\nORG = 2\n');
  });

  it('collapses runs of blank lines to one', () => {
    expect(format('A = 1\n\n\n\nB = 2\n')).toBe('A = 1\n\nB = 2\n');
  });

  it('puts exactly one blank line before each section', () => {
    expect(format('A = 1\n[DOCUMENTATION]\nORG_NAME = "x"\n')).toBe(
      'A = 1\n\n[DOCUMENTATION]\nORG_NAME = "x"\n',
    );
    expect(format('A = 1\n\n\n[DOCUMENTATION]\nORG_NAME = "x"\n')).toBe(
      'A = 1\n\n[DOCUMENTATION]\nORG_NAME = "x"\n',
    );
  });

  it('drops leading blank lines', () => {
    expect(format('\n\nVERSION = "1"\n')).toBe('VERSION = "1"\n');
  });

  it('strips trailing whitespace outside multi-line strings', () => {
    expect(format('VERSION = "1"   \n# comment   \n')).toBe('VERSION = "1"\n# comment\n');
    // Inside a multi-line string the same spaces are content.
    expect(format('DESC = """keep   \nme"""\n')).toBe('DESC = """keep   \nme"""\n');
  });

  it('preserves CRLF line endings', () => {
    const input = 'VERSION = "1"\r\n\r\n[DOCUMENTATION]\r\nORG_NAME = "x"\r\n';
    expect(format(input)).toBe(input);
  });

  it('preserves the absence of a final newline', () => {
    expect(format('VERSION = "1"')).toBe('VERSION = "1"');
  });
});

describe('quoting', () => {
  it('rewrites single-quoted strings as basic strings', () => {
    expect(format("ORG_NAME = 'Example & Co'\n")).toBe('ORG_NAME = "Example & Co"\n');
  });

  it('escapes what a basic string must escape', () => {
    expect(format('A = \'say "hi"\'\n')).toBe('A = "say \\"hi\\""\n');
    expect(format("A = 'back\\slash'\n")).toBe('A = "back\\\\slash"\n');
  });

  it('normalises strings inside arrays', () => {
    expect(format("A = ['one', 'two']\n")).toBe('A = ["one", "two"]\n');
  });

  it('drops quotes from keys a bare key can carry', () => {
    expect(format('\'ORG_NAME\' = "x"\n')).toBe('ORG_NAME = "x"\n');
    // ...but keeps them where dropping them would change the key.
    expect(format('"not a bare key" = 1\n')).toBe('"not a bare key" = 1\n');
  });

  it('never converts a basic string back into a literal one', () => {
    expect(format('A = "plain"\n')).toBe('A = "plain"\n');
  });

  it('leaves multi-line strings byte-for-byte alone', () => {
    const input = "D = '''\nraw 'text' and \"quotes\"\n'''\n";
    expect(format(input)).toBe(input);
    const basic = 'D = """\nraw "text" and \'quotes\'\n"""\n';
    expect(format(basic)).toBe(basic);
  });

  it('leaves non-string values alone', () => {
    const input = [
      'A = 1_000',
      'B = 0x1F',
      'C = 3.14',
      'D = true',
      'E = 1979-05-27T07:32:00Z',
      'F = 1979-05-27',
    ].join('\n');
    expect(format(input)).toBe(input);
  });
});

describe('invalid input', () => {
  it('refuses to format a file that does not parse', () => {
    const result = formatToml('VERSION = \n');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('Invalid TOML');
    expect(result.error).toContain('left untouched');
    expect(result.line).toBe(1);
  });

  it('reports a missing value without producing output', () => {
    const result = formatToml('[DOCUMENTATION]\nORG_NAME\n');
    expect(result).toMatchObject({ ok: false });
  });

  it('leaves an empty file alone', () => {
    expect(formatToml('')).toEqual({ ok: true, output: '', changed: false });
  });

  it('keeps a byte order mark', () => {
    const result = formatToml('﻿VERSION = "1"\n');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.output.startsWith('﻿')).toBe(true);
    expect(result.changed).toBe(false);
  });
});

describe('idempotence', () => {
  const sources = [
    'VERSION = "2.0.0"',
    'ACCOUNTS = ["GABC"]\nNETWORK_PASSPHRASE = "net"\nVERSION = "1"',
    '# c\nA = 1\n\n\n# d\nB = 2\n\n[C]\nx = 1\n',
    '[DOCUMENTATION]\nORG_NAME = \'Example\'\nORG_URL = "https://example.com"\n',
    '[[CURRENCIES]]\ncode = "XLM"\ncontract = "C1"\n\n[[CURRENCIES]]\ncode = "USD"\nissuer = "G1"\n',
    'A = [1, 2, 3]\nB = { c = 1, d = "x" }\n',
    "D = '''\nraw 'x'\n'''\nA = 1\n",
    'DESC = """\n  indented   \n  lines\n"""\nZ = 1\n',
    'A = 1 # trailing\n\n# top of file comment\n',
    '# only comments\n',
    "'KEY' = 'value'  \n",
  ];

  for (const source of sources) {
    it(`formats ${JSON.stringify(source).slice(0, 48)}... only once`, () => {
      expectIdempotent(source);
    });
  }
});

describe('round trip', () => {
  const sources = [
    fixture('valid.toml'),
    fixture('warnings-only.toml'),
    fixture('broken.toml'),
    // A deliberate mix of everything the scanner has to survive.
    [
      '# header comment',
      'VERSION = "1.0.0"',
      'ACCOUNTS = [',
      '  "GABC", # first',
      '  "GDEF",',
      ']',
      "INLINE = { a = 1, b = 'two' }",
      'DOTTED.sub.key = true',
      "LITERAL = 'a # not a comment'",
      'MULTILINE = """',
      '  line   one',
      '  line two',
      '"""',
      '',
      '[DOCUMENTATION]',
      'ORG_NAME = "Example"',
      'ORG_DESCRIPTION = """',
      'Long description',
      '"""',
      '',
      '[[PRINCIPALS]]',
      'name = "Jane"',
      'email = "jane@example.com"',
      '',
      '[[CURRENCIES]]',
      'code = "USD"',
      'issuer = "GABC"',
      'display_decimals = 2',
      '',
      '[ODD_TABLE]',
      'whatever = 1',
      '',
      '[[VALIDATORS]]',
      'ALIAS = "node-1"',
      'HOST = "node.example:11625"',
      '',
      '# footer',
    ].join('\n'),
  ];

  for (const [index, source] of sources.entries()) {
    it(`preserves the parsed document of sample ${index}`, () => {
      expectRoundTrip(source);
    });

    it(`is idempotent on sample ${index}`, () => {
      expectIdempotent(source);
    });
  }
});

describe('interaction with the linter', () => {
  it('reports the same rule ids before and after formatting', () => {
    const source = fixture('broken.toml');
    const before = lint(source)
      .diagnostics.map((d) => d.rule)
      .sort();
    const after = lint(format(source))
      .diagnostics.map((d) => d.rule)
      .sort();
    expect(after).toEqual(before);
  });

  it('leaves a clean fixture clean', () => {
    const result = lint(format(fixture('valid.toml')), { strict: true });
    expect(result.diagnostics).toEqual([]);
  });
});
