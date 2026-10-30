import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { lint } from '../src/lint.js';
import { applyFixes, computeFixEdits } from '../src/fix.js';
import { codeActionsFor, offsetToPosition } from '../src/lsp/code-actions.js';
import type { LspRange } from '../src/lsp/code-actions.js';

const here = dirname(fileURLToPath(import.meta.url));

const FULL_DOCUMENT: LspRange = {
  start: { line: 0, character: 0 },
  end: { line: 10_000, character: 0 },
};

const diagnosticsOf = (source: string) => lint(source).diagnostics;

/** Character range of `needle` on its first line, for WorkspaceEdit assertions. */
function valueRange(source: string, needle: string): LspRange {
  const start = source.indexOf(needle);
  if (start < 0) throw new Error(`fixture missing: ${needle}`);
  return {
    start: offsetToPosition(source, start),
    end: offsetToPosition(source, start + needle.length),
  };
}

describe('codeActionsFor', () => {
  it('offers a WorkspaceEdit that strips the trailing slash from an endpoint', () => {
    const source = [
      'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
      'TRANSFER_SERVER = "https://example.com/sep6/"',
      '',
    ].join('\n');
    const uri = 'file:///stellar.toml';

    const actions = codeActionsFor(source, uri, diagnosticsOf(source), FULL_DOCUMENT);
    const slashAction = actions.find((a) =>
      a.title.includes('Strip trailing slash from TRANSFER_SERVER'),
    );

    expect(slashAction).toBeDefined();
    expect(slashAction?.kind).toBe('quickfix');
    expect(slashAction?.edit?.changes[uri]).toEqual([
      {
        range: valueRange(source, 'https://example.com/sep6/'),
        newText: 'https://example.com/sep6',
      },
    ]);
  });

  it('returns no code action for an unfixable parse error', () => {
    const source = 'TRANSFER_SERVER = "https://example.com\n';
    const diagnostics = diagnosticsOf(source);
    expect(diagnostics.some((d) => d.rule === 'file/parse')).toBe(true);
    expect(diagnostics.every((d) => d.fix === undefined)).toBe(true);

    const actions = codeActionsFor(source, 'file:///stellar.toml', diagnostics, FULL_DOCUMENT);

    expect(actions).toEqual([]);
  });

  it('normalizes a whitespace-broken NETWORK_PASSPHRASE', () => {
    const source = 'NETWORK_PASSPHRASE = "Test SDF Network; September 2015"\n';
    const actions = codeActionsFor(
      source,
      'file:///stellar.toml',
      diagnosticsOf(source),
      FULL_DOCUMENT,
    );

    const passphrase = actions.find((a) => a.title.startsWith('Fix: Normalize NETWORK_PASSPHRASE'));
    expect(passphrase?.edit?.changes['file:///stellar.toml']?.[0]?.newText).toBe(
      'Test SDF Network ; September 2015',
    );
  });

  it('rewrites a documentation social URL down to the bare handle', () => {
    const source = [
      '[DOCUMENTATION]',
      'ORG_NAME = "Example"',
      'ORG_URL = "https://example.com"',
      'ORG_DESCRIPTION = "Example anchor"',
      'ORG_TWITTER = "https://twitter.com/example"',
      '',
    ].join('\n');
    const uri = 'file:///stellar.toml';

    const actions = codeActionsFor(source, uri, diagnosticsOf(source), FULL_DOCUMENT);
    const social = actions.find((a) => a.title.startsWith('Fix: Use bare handle'));

    expect(social?.edit?.changes[uri]?.[0]).toEqual({
      range: valueRange(source, 'https://twitter.com/example'),
      newText: 'example',
    });
  });

  it('ignores ranges that do not cover the diagnostic', () => {
    const source = 'TRANSFER_SERVER = "https://example.com/sep6/"\n';
    const actions = codeActionsFor(source, 'file:///stellar.toml', diagnosticsOf(source), {
      start: { line: 5, character: 0 },
      end: { line: 6, character: 0 },
    });

    expect(actions).toEqual([]);
  });
});

describe('computeFixEdits / applyFixes', () => {
  it('replaces only the value content, preserving quotes', () => {
    const source = 'WEB_AUTH_ENDPOINT = "https://auth.example.com/sep6/"\n';
    const diagnostics = diagnosticsOf(source);
    const value = 'https://auth.example.com/sep6/';

    expect(computeFixEdits(source, diagnostics)).toEqual([
      {
        start: source.indexOf(value),
        end: source.indexOf(value) + value.length,
        text: 'https://auth.example.com/sep6',
      },
    ]);
    expect(applyFixes(source, diagnostics)).toBe(
      'WEB_AUTH_ENDPOINT = "https://auth.example.com/sep6"\n',
    );
  });

  it('leaves a clean file untouched', () => {
    const source = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');
    const diagnostics = diagnosticsOf(source).filter((d) => d.fix);

    expect(computeFixEdits(source, diagnostics)).toEqual([]);
    expect(applyFixes(source, diagnostics)).toBe(source);
  });

  it('formats an ORG_PHONE_NUMBER as E.164 when the digits recover', () => {
    const source = ['[DOCUMENTATION]', 'ORG_PHONE_NUMBER = "(415) 555-2671"', ''].join('\n');

    expect(applyFixes(source, diagnosticsOf(source))).toContain('ORG_PHONE_NUMBER = "+4155552671"');
  });
});

describe('rule fix payloads', () => {
  it('attaches fix only when the passphrase is a near miss', () => {
    const near = diagnosticsOf('NETWORK_PASSPHRASE = "Test SDF Network; September 2015"\n');
    const far = diagnosticsOf('NETWORK_PASSPHRASE = "Not a real network"\n');

    expect(near.find((d) => d.rule === 'network/passphrase')?.fix).toEqual({
      value: 'Test SDF Network ; September 2015',
    });
    expect(far.find((d) => d.rule === 'network/passphrase')?.fix).toBeUndefined();
  });

  it('strips a principal twitter URL to a bare handle', () => {
    const source = [
      '[[PRINCIPALS]]',
      'name = "Ada"',
      'email = "ada@example.com"',
      'twitter = "https://twitter.com/ada"',
      '',
    ].join('\n');

    const diagnostic = diagnosticsOf(source).find((d) => d.rule === 'principals/social-handles');
    expect(diagnostic?.fix).toEqual({ value: 'ada' });
  });
});
