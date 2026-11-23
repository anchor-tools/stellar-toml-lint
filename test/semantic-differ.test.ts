import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  diffSemanticToml,
  formatValue,
  renderSemanticDiff,
  renderSemanticDiffJson,
  SemanticTomlDiffer,
  type SemanticDiff,
} from '../src/cst/semanticDiffer.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => join(here, 'fixtures', 'diff', name);

/** Nine root fields, two currencies and one validator. */
const LIVE = `VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TRANSFER_SERVER = "https://api.example.com/sep6"
KYC_SERVER = "https://kyc.example.com"
WEB_AUTH_ENDPOINT = "https://api.example.com/auth"
AUTH_SERVER = "https://api.example.com/compliance"
SIGNING_KEY = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"

[[CURRENCIES]]
code = "USDX"
issuer = "GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
name = "Example US Dollar"

[[CURRENCIES]]
code = "EXPL"
contract = "CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU"
name = "Example Points"

[[VALIDATORS]]
ALIAS = "example-us"
HOST = "core-us.example.com:11625"
PUBLIC_KEY = "GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI"
`;

/** `LIVE` with every root key, entry and field written in another order. */
const RESTYLED = `# Restaged by --sort-keys; not one value differs from LIVE.
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
SIGNING_KEY="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"
AUTH_SERVER="https://api.example.com/compliance"
KYC_SERVER="https://kyc.example.com"
TRANSFER_SERVER="https://api.example.com/sep6"
VERSION="2.7.0"
WEB_AUTH_ENDPOINT="https://api.example.com/auth"

[[CURRENCIES]]
name="Example Points"
contract="CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU"
code="EXPL"

[[CURRENCIES]]
name="Example US Dollar"
issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
code="USDX"

[[VALIDATORS]]
PUBLIC_KEY="GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI"
HOST="core-us.example.com:11625"
ALIAS="example-us"
`;

const USDX_ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const OTHER_ISSUER = 'GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI';
const VALIDATOR_KEY = OTHER_ISSUER;

const lines = (report: SemanticDiff): string[] =>
  report.changes.map((change) => `${change.kind} ${change.path}`);

function changeAt(report: SemanticDiff, path: string) {
  const change = report.changes.find((candidate) => candidate.path === path);
  if (change !== undefined) return change;
  throw new Error(`no change at ${path}, got: ${lines(report).join(', ') || 'nothing'}`);
}

describe('SemanticTomlDiffer', () => {
  it('reports nothing for two identical documents', () => {
    const report = diffSemanticToml(LIVE, LIVE);

    expect(report.changes).toEqual([]);
    expect([report.added, report.removed, report.modified, report.breaking]).toEqual([0, 0, 0, 0]);
    expect(report.source.parsed && report.target.parsed).toBe(true);
  });

  it('is blind to ordering, indentation and comments', () => {
    // The reason this exists next to `--sort-keys`: a restaged file is not a
    // changed file.
    expect(diffSemanticToml(LIVE, RESTYLED).changes).toEqual([]);
  });

  it('treats two spellings of the same instant as equal', () => {
    const source = 'ORG_DATA_SENT = 1979-05-27T07:32:00Z\n';
    const target = 'ORG_DATA_SENT = 1979-05-27T09:32:00+02:00\n';

    expect(diffSemanticToml(source, target).changes).toEqual([]);
  });

  it('renders a changed instant rather than a date object', () => {
    const report = diffSemanticToml(
      'ORG_SINCE = 1979-05-27T07:32:00Z\n',
      'ORG_SINCE = 2026-04-05T06:07:08Z\n',
    );

    expect(lines(report)).toEqual(['modified ORG_SINCE']);
    expect(formatValue(changeAt(report, 'ORG_SINCE').before)).toBe('1979-05-27T07:32:00.000Z');
  });

  describe('breaking changes', () => {
    it('flags a rotated signing key', () => {
      const rotated = 'GA3TONZXG43TONZXG43TONZXG43TONZXG43TONZXG43TONZXG43TO5MU';
      const report = diffSemanticToml(LIVE, LIVE.replace(/GCM5\w+/, rotated));
      const change = changeAt(report, 'SIGNING_KEY');

      expect(change.kind).toBe('modified');
      expect(change.category).toBe('signing-key');
      expect(change.breaking).toBe(true);
      expect(change.reason).toContain('SEP-10');
    });

    it('flags a new issuer behind the same asset code', () => {
      const report = diffSemanticToml(LIVE, LIVE.replace(USDX_ISSUER, OTHER_ISSUER));
      const change = changeAt(report, 'CURRENCIES[USDX].issuer');

      expect(change.breaking).toBe(true);
      expect(change.section).toBe('CURRENCIES');
      expect(change.category).toBe('currency');
      expect(change.reason).toContain('different asset');
    });

    it('flags a delisted currency', () => {
      const target = LIVE.replace(
        `\n[[CURRENCIES]]\ncode = "EXPL"\ncontract = "CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU"\nname = "Example Points"\n`,
        '',
      );
      const change = changeAt(diffSemanticToml(LIVE, target), 'CURRENCIES[EXPL]');

      expect(change.kind).toBe('removed');
      expect(change.breaking).toBe(true);
      expect(change.before).toMatchObject({ code: 'EXPL' });
      expect(change.after).toBeUndefined();
    });

    it('flags a retired validator', () => {
      const target = LIVE.replace(
        `\n[[VALIDATORS]]\nALIAS = "example-us"\nHOST = "core-us.example.com:11625"\nPUBLIC_KEY = "${VALIDATOR_KEY}"\n`,
        '',
      );
      const change = changeAt(diffSemanticToml(LIVE, target), `VALIDATORS[${VALIDATOR_KEY}]`);

      expect(change.breaking).toBe(true);
      expect(change.category).toBe('validator');
      expect(change.reason).toContain('contact information');
    });

    it('flags an endpoint that disappears but not one that moves', () => {
      const dropped = diffSemanticToml(
        LIVE,
        LIVE.replace('WEB_AUTH_ENDPOINT = "https://api.example.com/auth"\n', ''),
      );
      const moved = diffSemanticToml(LIVE, LIVE.replace('kyc.example.com', 'kyc-v2.example.com'));

      expect(changeAt(dropped, 'WEB_AUTH_ENDPOINT').reason).toContain('SEP-10');
      expect(changeAt(moved, 'KYC_SERVER').breaking).toBe(false);
    });

    it('does not treat dropping a deprecated field as breaking', () => {
      const target = LIVE.replace('AUTH_SERVER = "https://api.example.com/compliance"\n', '');
      const report = diffSemanticToml(LIVE, target);

      expect(changeAt(report, 'AUTH_SERVER').breaking).toBe(false);
      expect(report.breaking).toBe(0);
    });

    it('does not call the loss of a field SEP-1 does not define breaking', () => {
      const source = `CUSTOM_FLAG = "on"\n\n${LIVE}`;
      const change = changeAt(diffSemanticToml(source, LIVE), 'CUSTOM_FLAG');

      expect(change.kind).toBe('removed');
      expect(change.breaking).toBe(false);
    });

    it('does not flag anything a client has never seen', () => {
      const report = diffSemanticToml('VERSION = "2.7.0"\n', LIVE);

      expect(report.added).toBe(9);
      expect(report.breaking).toBe(0);
    });
  });

  describe('array entries', () => {
    it('pairs currencies by code rather than by position', () => {
      const source =
        '[[CURRENCIES]]\ncode="A"\nname="first"\n\n[[CURRENCIES]]\ncode="B"\nname="second"\n';
      const target =
        '[[CURRENCIES]]\ncode="B"\nname="SECOND"\n\n[[CURRENCIES]]\ncode="A"\nname="first"\n';

      expect(lines(diffSemanticToml(source, target))).toEqual(['modified CURRENCIES[B].name']);
    });

    it('falls back to the position when entries share an identity', () => {
      const source =
        '[[CURRENCIES]]\ncode="USD"\nname="one"\n\n[[CURRENCIES]]\ncode="USD"\nname="two"\n';
      const target =
        '[[CURRENCIES]]\ncode="USD"\nname="one"\n\n[[CURRENCIES]]\ncode="USD"\nname="changed"\n';

      expect(lines(diffSemanticToml(source, target))).toEqual(['modified CURRENCIES[USD#2].name']);
    });

    it('uses the position for an entry whose code is not usable as a key', () => {
      const source =
        '[[CURRENCIES]]\ncode=""\nname="one"\n\n[[CURRENCIES]]\ncode=100\nname="two"\n';
      const target =
        '[[CURRENCIES]]\ncode=""\nname="changed"\n\n[[CURRENCIES]]\ncode=100\nname="two"\n';

      expect(lines(diffSemanticToml(source, target))).toEqual(['modified CURRENCIES[#1].name']);
    });

    it('names each entry when a section vanishes entirely', () => {
      const source =
        'VERSION = "1.0"\n\n[[CURRENCIES]]\ncode="USD"\n\n[[CURRENCIES]]\ncode="EUR"\n';
      const report = diffSemanticToml(source, 'VERSION = "1.0"\n');

      expect(lines(report)).toEqual(['removed CURRENCIES[USD]', 'removed CURRENCIES[EUR]']);
      expect(report.breaking).toBe(2);
    });

    it('matches principals positionally, since SEP-1 gives them no key', () => {
      const source = '[[PRINCIPALS]]\nname="Jane"\nemail="jane@example.com"\n';
      const target = '[[PRINCIPALS]]\nname="Jane"\nemail="jane.doe@example.com"\n';
      const change = changeAt(diffSemanticToml(source, target), 'PRINCIPALS[#1].email');

      expect(change.breaking).toBe(false);
      expect(change.category).toBe('principal');
    });

    it('compares a nested array by position without calling it a delisting', () => {
      const source = '[[CURRENCIES]]\ncode="USD"\ncollateral_addresses=["GA1","GA2","GA3"]\n';
      const target = '[[CURRENCIES]]\ncode="USD"\ncollateral_addresses=["GA1","GA2"]\n';
      const change = changeAt(
        diffSemanticToml(source, target),
        'CURRENCIES[USD].collateral_addresses[#3]',
      );

      expect(change.kind).toBe('removed');
      expect(change.breaking).toBe(false);
    });
  });

  describe('sections', () => {
    it('reports a nested table under the section that contains it', () => {
      const source =
        '[DOCUMENTATION]\nORG_NAME="Example"\n\n[DOCUMENTATION.CONTACT]\nsupport="a@example.com"\n';
      const target =
        '[DOCUMENTATION]\nORG_NAME="Example"\n\n[DOCUMENTATION.CONTACT]\nsupport="b@example.com"\n';
      const change = changeAt(diffSemanticToml(source, target), 'DOCUMENTATION.CONTACT.support');

      expect(change.section).toBe('DOCUMENTATION');
      expect(change.category).toBe('documentation');
    });

    it('keeps a custom table out of the SEP-1 catalogs', () => {
      const report = diffSemanticToml('[CUSTOM]\nsunset="2026"\n', '[CUSTOM]\nsunset="2027"\n');
      const change = changeAt(report, 'CUSTOM.sunset');

      expect(change.category).toBe('general');
      expect(change.breaking).toBe(false);
    });

    it('reads a field that changed type as a modification', () => {
      const report = diffSemanticToml('ORG_URL="https://example.com"\n', '[ORG_URL]\nhref="x"\n');
      const change = changeAt(report, 'ORG_URL');

      expect(change.kind).toBe('modified');
      expect(change.before).toBe('https://example.com');
      expect(change.after).toMatchObject({ href: 'x' });
    });

    it('reads a scalar that became a list as one modification', () => {
      const report = diffSemanticToml(
        'ORG_URL = "https://example.com"\n',
        'ORG_URL = ["https://example.com", "https://example.org"]\n',
      );
      const change = changeAt(report, 'ORG_URL');

      expect(change.kind).toBe('modified');
      expect(lines(report)).toEqual(['modified ORG_URL']);
      expect(change.after).toEqual(['https://example.com', 'https://example.org']);
    });

    it('counts the fields on each side so an empty file is visibly empty', () => {
      const report = diffSemanticToml('', 'VERSION = "2.7.0"\n');

      expect([report.source.fields, report.target.fields]).toEqual([0, 1]);
      expect(report.source.parsed).toBe(true);
    });
  });

  it('refuses to diff a document that does not parse', () => {
    const report = diffSemanticToml(LIVE, 'name = "unterminated\n');

    expect(report.source.parsed).toBe(true);
    expect(report.target.parsed).toBe(false);
    expect(report.target.error).toContain('Invalid TOML');
    expect(report.changes).toEqual([]);
  });

  describe('loading both sides', () => {
    it('fetches one side and reads the other from disk', async () => {
      const calls: string[] = [];
      const fetchImpl = (async (url: string) => {
        calls.push(String(url));
        return new Response(LIVE, { status: 200 });
      }) as unknown as typeof fetch;

      const report = await new SemanticTomlDiffer({ fetchImpl }).diffInputs(
        'https://example.com/.well-known/stellar.toml',
        fixture('live.toml'),
      );

      expect(calls).toEqual(['https://example.com/.well-known/stellar.toml']);
      expect(report.source.fields).toBe(9);
      expect(report.changes.length).toBeGreaterThan(0);
    });

    it('gives up on a non-2xx answer', async () => {
      const fetchImpl = (async () =>
        new Response('nope', { status: 404 })) as unknown as typeof fetch;

      await expect(
        new SemanticTomlDiffer({ fetchImpl }).load('https://gone.example.com/stellar.toml'),
      ).rejects.toThrow('HTTP 404');
    });

    it('reads a side from stdin', async () => {
      const stdin = process.stdin;
      Object.defineProperty(process, 'stdin', {
        value: Readable.from(['VERSION = "2.7.0"\n']),
        configurable: true,
        writable: true,
      });
      try {
        expect(await new SemanticTomlDiffer().load('-')).toBe('VERSION = "2.7.0"\n');
      } finally {
        Object.defineProperty(process, 'stdin', {
          value: stdin,
          configurable: true,
          writable: true,
        });
      }
    });
  });

  describe('the anchor revision fixtures', () => {
    it('separates the real changes from the restaging noise', async () => {
      const report = await new SemanticTomlDiffer().diffInputs(
        fixture('live.toml'),
        fixture('candidate.toml'),
      );

      expect(report.source.fields).toBe(17);
      expect(report.target.fields).toBe(15);
      expect(lines(report)).toEqual([
        'removed AUTH_SERVER',
        'modified KYC_SERVER',
        'removed ANCHOR_QUOTE_SERVER',
        'modified SIGNING_KEY',
        'modified DOCUMENTATION.ORG_TWITTER',
        'modified PRINCIPALS[#1].email',
        'modified CURRENCIES[USDX].issuer',
        'modified CURRENCIES[USDX].display_decimals',
        'removed CURRENCIES[EXPL]',
        'added CURRENCIES[native].desc',
        'added CURRENCIES[EURX]',
        `modified VALIDATORS[${OTHER_ISSUER}].HOST`,
        `removed VALIDATORS[GBXHQL5SHDWJJ2WQXJZOVQBVVIFXLFQQFIKVWMU6XA7YZVMVMB5APS5D]`,
      ]);
      expect(report.breaking).toBe(6);
    });
  });
});

describe('renderSemanticDiff', () => {
  it('says so when the documents agree', () => {
    expect(renderSemanticDiff(diffSemanticToml(LIVE, RESTYLED))).toContain('No semantic changes');
  });

  it('names both sides, the counts and the breaking lines', async () => {
    const [source, target] = await Promise.all([
      readFile(fixture('live.toml'), 'utf8'),
      readFile(fixture('candidate.toml'), 'utf8'),
    ]);
    const text = renderSemanticDiff(
      diffSemanticToml(source, target, { source: 'live', target: 'candidate' }),
    );

    expect(text).toContain('# stellar.toml semantic diff');
    expect(text).toContain('**source:** `live`');
    expect(text).toContain('BREAKING: 6 breaking changes');
    expect(text).toContain('- `ANCHOR_QUOTE_SERVER` BREAKING');
    expect(text).toContain('  - "https://api.example.com/sep38"');
    expect(text).toContain('~ `KYC_SERVER`');
  });

  it('colours additions green and removals red only when asked', () => {
    const target = LIVE.replace(
      'WEB_AUTH_ENDPOINT = "https://api.example.com/auth"\n',
      `ACCOUNTS = ["${USDX_ISSUER}"]\n`,
    );
    const report = diffSemanticToml(LIVE, target);

    expect(renderSemanticDiff(report)).not.toContain('\x1b[');
    expect(renderSemanticDiff(report, true)).toContain('\x1b[31m-\x1b[39m');
    expect(renderSemanticDiff(report, true)).toContain('\x1b[32m+\x1b[39m');
    expect(renderSemanticDiff(report, true)).toContain('\x1b[1m\x1b[31mBREAKING\x1b[39m\x1b[22m');
  });

  it('reports an unparsable side instead of an empty diff', () => {
    const text = renderSemanticDiff(diffSemanticToml(LIVE, 'name = "unterminated\n'));

    expect(text).toContain('did not parse');
    expect(text).not.toContain('No semantic changes');
  });
});

describe('report shape', () => {
  it('serialises to JSON without the parsed documents', () => {
    const report = diffSemanticToml(
      LIVE,
      LIVE.replace('name = "Example US Dollar"', 'name = "Example Dollar"'),
    );
    const parsed = JSON.parse(renderSemanticDiffJson(report)) as SemanticDiff;

    expect(parsed.changes).toHaveLength(1);
    expect(parsed.changes[0]?.path).toBe('CURRENCIES[USDX].name');
    expect(JSON.stringify(parsed)).not.toContain('"document"');
    expect(renderSemanticDiffJson(report).endsWith('\n')).toBe(true);
  });

  it('is reachable through the functional wrapper', () => {
    expect(new SemanticTomlDiffer().diff(LIVE, LIVE).changes).toEqual([]);
    expect(diffSemanticToml(LIVE, LIVE, { source: 'a', target: 'b' }).source.input).toBe('a');
    expect(diffSemanticToml(LIVE, LIVE).source.input).toBe('source');
  });
});

describe('formatValue', () => {
  it('collapses a long collection so one change stays on one line', () => {
    expect(formatValue(['a', 'b', 'c', 'd'])).toBe('["a", "b", "c", … 1 more]');
    expect(formatValue({ code: 'USD', name: 'Dollar', issuer: 'G1', status: 'live' })).toBe(
      '{code="USD", name="Dollar", issuer="G1", … 1 more}',
    );
    expect(formatValue({ nested: [1, 2, 3] })).toBe('{nested=[3 values]}');
    expect(formatValue({ nested: { a: 1, b: 2 } })).toBe('{nested={2 fields}}');
    expect(formatValue(2)).toBe('2');
    expect(formatValue(true)).toBe('true');
  });

  it('renders a value TOML cannot produce rather than throwing', () => {
    // `formatValue` is exported and total, so a value outside TOML's type set still prints.
    expect(formatValue(null)).toBe('null');
    expect(formatValue(undefined)).toBe('undefined');
  });
});
