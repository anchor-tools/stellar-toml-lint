import { describe, expect, it } from 'vitest';

import { lint } from '../../src/lint.js';
import { codeActionsFor, offsetToPosition } from '../../src/lsp/code-actions-provider.js';
import type { LspCodeAction, LspRange } from '../../src/lsp/code-actions-provider.js';

const FULL_DOCUMENT: LspRange = {
  start: { line: 0, character: 0 },
  end: { line: 10_000, character: 0 },
};

const ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const TESTNET_USDC_SAC = 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA';
const USDC_ISSUER = 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5';

const uri = 'file:///stellar.toml';
const diagnosticsOf = (source: string) => lint(source).diagnostics;
const actionsOf = (source: string, range: LspRange = FULL_DOCUMENT, only?: string[]) =>
  codeActionsFor(source, uri, diagnosticsOf(source), range, only);

/** Zero-width edit range at the first `\n` after `needle`. */
function insertPoint(source: string, needle: string): LspRange {
  const offset = source.indexOf('\n', source.indexOf(needle));
  if (offset < 0) throw new Error(`fixture missing newline after: ${needle}`);
  const position = offsetToPosition(source, offset);
  return { start: position, end: position };
}

/** Range of `needle` as written in `source`. */
function valueRange(source: string, needle: string): LspRange {
  const start = source.indexOf(needle);
  if (start < 0) throw new Error(`fixture missing: ${needle}`);
  return {
    start: offsetToPosition(source, start),
    end: offsetToPosition(source, start + needle.length),
  };
}

function editFor(actions: LspCodeAction[], title: string) {
  const action = actions.find((a) => a.title === title);
  expect(
    action,
    `expected action "${title}" in ${actions.map((a) => a.title).join(', ')}`,
  ).toBeDefined();
  return action?.edit?.changes[uri]?.[0];
}

describe('quick fixes (#332 acceptance)', () => {
  it('returns a quickfix that uppercases a lowercase public key', () => {
    const lower = ACCOUNT.toLowerCase();
    const source = `SIGNING_KEY = "${lower}"\n`;

    const action = actionsOf(source).find((a) => a.title === 'Fix: Uppercase SIGNING_KEY');

    expect(action).toBeDefined();
    expect(action?.kind).toBe('quickfix');
    expect(action?.isPreferred).toBe(true);
    expect(action?.edit?.changes[uri]).toEqual([
      { range: valueRange(source, lower), newText: ACCOUNT },
    ]);
  });

  it('upgrades an insecure http:// endpoint to https://', () => {
    const source = 'FEDERATION_SERVER = "http://example.com/federation"\n';

    expect(editFor(actionsOf(source), 'Fix: Use https:// for FEDERATION_SERVER')).toEqual({
      range: valueRange(source, 'http://example.com/federation'),
      newText: 'https://example.com/federation',
    });
  });

  it('trims leading and trailing whitespace from a string value', () => {
    const source = ['[DOCUMENTATION]', 'ORG_NAME = "  Example  "', ''].join('\n');

    expect(editFor(actionsOf(source), 'Fix: Trim whitespace from DOCUMENTATION.ORG_NAME')).toEqual({
      range: valueRange(source, '  Example  '),
      newText: 'Example',
    });
  });
});

describe('missing-field insertion', () => {
  it('offers to add a missing ORG_NAME under the [DOCUMENTATION] header', () => {
    const source = ['[DOCUMENTATION]', 'ORG_URL = "https://example.com"', ''].join('\n');

    expect(editFor(actionsOf(source), 'Fix: Add missing DOCUMENTATION.ORG_NAME')).toEqual({
      range: insertPoint(source, '[DOCUMENTATION]'),
      newText: '\nORG_NAME = ""',
    });
  });

  it('stays quiet when there is no [DOCUMENTATION] table to insert into', () => {
    // documentation/present fires with no position and nothing to anchor on.
    const source = 'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"\n';
    expect(actionsOf(source).some((a) => a.title.startsWith('Fix: Add missing'))).toBe(false);
  });
});

describe('SAC contract ID derivation refactor', () => {
  const source = [
    'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code = "USDC"',
    `issuer = "${USDC_ISSUER}"`,
    '',
  ].join('\n');
  const insideEntry: LspRange = {
    start: { line: 4, character: 0 },
    end: { line: 4, character: 1 },
  };

  it('derives the Testnet USDC SAC id from code + issuer', () => {
    expect(
      editFor(actionsOf(source, insideEntry), 'Refactor: Derive SAC contract ID for CURRENCIES[0]'),
    ).toEqual({
      range: insertPoint(source, 'issuer'),
      newText: `\ncontract = "${TESTNET_USDC_SAC}"`,
    });
  });

  it('is a refactor.rewrite, not a quickfix', () => {
    const action = actionsOf(source, insideEntry).find((a) =>
      a.title.startsWith('Refactor: Derive SAC contract ID'),
    );
    expect(action?.kind).toBe('refactor.rewrite');
    expect(action?.diagnostics).toBeUndefined();
  });

  it('does not fire when the entry already declares a contract', () => {
    const withContract = [...source.slice(0, -1), `contract = "${TESTNET_USDC_SAC}"`, ''].join(
      '\n',
    );
    expect(actionsOf(withContract, insideEntry).some((a) => a.title.startsWith('Refactor:'))).toBe(
      false,
    );
  });

  it('does not fire when the cursor is outside every [[CURRENCIES]] block', () => {
    expect(actionsOf(source).some((a) => a.title.startsWith('Refactor:'))).toBe(false);
  });

  it('does not fire on an issuer the Asset constructor rejects', () => {
    const broken = source.replace(USDC_ISSUER, 'NOT-A-KEY');
    expect(actionsOf(broken, insideEntry).some((a) => a.title.startsWith('Refactor:'))).toBe(false);
  });
});

describe('fix all auto-fixable problems in file', () => {
  const source = [
    'NETWORK_PASSPHRASE = "Test SDF Network; September 2015"',
    'TRANSFER_SERVER = "https://example.com/sep6/"',
    `SIGNING_KEY = "${ACCOUNT.toLowerCase()}"`,
    '',
  ].join('\n');

  it('merges every value rewrite into one source.fixAll action', () => {
    const action = actionsOf(source).find((a) => a.kind === 'source.fixAll');

    expect(action?.title).toBe('Fix all auto-fixable problems in file');
    expect(action?.edit?.changes[uri]).toHaveLength(3);
  });

  it('applies to the whole file regardless of the requested range', () => {
    const cursor: LspRange = { start: { line: 1, character: 0 }, end: { line: 1, character: 1 } };
    expect(actionsOf(source, cursor).some((a) => a.kind === 'source.fixAll')).toBe(true);
  });

  it('rewrites the document exactly like --fix', () => {
    const edits =
      actionsOf(source).find((a) => a.kind === 'source.fixAll')?.edit?.changes[uri] ?? [];
    let applied = source;
    for (const edit of [...edits].reverse()) {
      const start = offsetOf(applied, edit.range.start);
      const end = offsetOf(applied, edit.range.end);
      applied = applied.slice(0, start) + edit.newText + applied.slice(end);
    }

    expect(applied).toBe(
      [
        'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
        'TRANSFER_SERVER = "https://example.com/sep6"',
        `SIGNING_KEY = "${ACCOUNT}"`,
        '',
      ].join('\n'),
    );
  });
});

describe('context.only filtering', () => {
  const fixable = [
    'TRANSFER_SERVER = "https://example.com/sep6/"',
    'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code = "USDC"',
    `issuer = "${USDC_ISSUER}"`,
    '',
  ].join('\n');
  const insideEntry: LspRange = {
    start: { line: 4, character: 0 },
    end: { line: 4, character: 1 },
  };

  it('honours only: ["quickfix"] by hiding fix-all and refactors', () => {
    const kinds = new Set(actionsOf(fixable, FULL_DOCUMENT, ['quickfix']).map((a) => a.kind));
    expect(kinds).toEqual(new Set(['quickfix']));
  });

  it('honours only: ["source.fixAll"]', () => {
    const kinds = new Set(actionsOf(fixable, FULL_DOCUMENT, ['source.fixAll']).map((a) => a.kind));
    expect(kinds).toEqual(new Set(['source.fixAll']));
  });

  it('matches refactor.rewrite through the refactor prefix', () => {
    const kinds = new Set(actionsOf(fixable, insideEntry, ['refactor']).map((a) => a.kind));
    expect(kinds).toEqual(new Set(['refactor.rewrite']));
  });
});

// ── the server endpoint ───────────────────────────────────────────────────────

describe('textDocument/codeAction over LSP', () => {
  it('advertises the kinds and serves a quickfix over stdio', async () => {
    const { PassThrough } = await import('node:stream');
    const { runLspServer } = await import('../../src/lsp/server.js');

    const input = new PassThrough();
    const output = new PassThrough();
    const chunks: Buffer[] = [];
    output.on('data', (chunk: Buffer) => chunks.push(chunk));

    const frame = (payload: unknown): void => {
      const body = Buffer.from(JSON.stringify(payload), 'utf8');
      input.write(`Content-Length: ${body.length}\r\n\r\n`);
      input.write(body);
    };

    const lower = ACCOUNT.toLowerCase();
    const text = `SIGNING_KEY = "${lower}"\n`;

    const pending = runLspServer(input, output);
    frame({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { capabilities: {} } });
    frame({
      jsonrpc: '2.0',
      method: 'textDocument/didOpen',
      params: { textDocument: { uri, version: 1, text } },
    });
    frame({
      jsonrpc: '2.0',
      id: 2,
      method: 'textDocument/codeAction',
      params: {
        textDocument: { uri },
        range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } },
        context: { diagnostics: [] },
      },
    });
    frame({ jsonrpc: '2.0', method: 'exit' });
    input.end();
    await pending;

    const messages = chunks
      .join('')
      .split('Content-Length:')
      .slice(1)
      .map((part) => JSON.parse(part.slice(part.indexOf('\r\n\r\n') + 4)));

    const initialize = messages.find((m) => m.id === 1);
    expect(initialize?.result.capabilities.codeActionProvider.codeActionKinds).toEqual([
      'quickfix',
      'refactor.rewrite',
      'source.fixAll',
    ]);

    const response = messages.find((m) => m.id === 2);
    const quickfix = response?.result.find(
      (action: LspCodeAction) => action.title === 'Fix: Uppercase SIGNING_KEY',
    );
    expect(quickfix?.kind).toBe('quickfix');
    expect(quickfix?.edit.changes[uri][0].newText).toBe(ACCOUNT);
  });
});

/** Source offset for a 0-based LSP position, mirroring the provider's mapping. */
function offsetOf(source: string, position: { line: number; character: number }): number {
  const lines = source.split('\n');
  let offset = 0;
  for (let i = 0; i < position.line; i++) offset += (lines[i]?.length ?? 0) + 1;
  return offset + position.character;
}
