import { describe, expect, it } from 'vitest';

import {
  collectSemanticTokens,
  computeSemanticTokens,
  encodeSemanticTokens,
  SEMANTIC_TOKEN_LEGEND,
  SEMANTIC_TOKEN_MODIFIERS,
  SEMANTIC_TOKEN_TYPES,
  type SemanticToken,
} from '../../src/lsp/semantic-tokens.js';

const VALID_ADDRESS = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const VALID_CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';

const INVALID_BIT = 1 << SEMANTIC_TOKEN_MODIFIERS.indexOf('invalid');
const DEPRECATED_BIT = 1 << SEMANTIC_TOKEN_MODIFIERS.indexOf('deprecated');

const SAMPLE = [
  `SIGNING_KEY = "${VALID_ADDRESS}"`,
  'AUTH_SERVER = "https://example.com/auth"',
  `WEB_AUTH_CONTRACT_ID = "${VALID_CONTRACT}"`,
  'HORIZON_URL = "not-a-url"',
  '[DOCUMENTATION]',
  'ORG_NAME = "Example"',
  'ORG_PRINCIPALS = "oops"',
  '[[CURRENCIES]]',
  'code = "USDC"',
  'issuer = "not-an-address"',
  `contract = "${VALID_CONTRACT}"`,
  '',
].join('\n');

/** Decodes the LSP delta stream back into absolute positions for assertions. */
function decode(data: number[]): SemanticToken[] {
  const tokens: SemanticToken[] = [];
  let line = 0;
  let startChar = 0;
  for (let i = 0; i < data.length; i += 5) {
    const deltaLine = data[i] as number;
    const deltaStart = data[i + 1] as number;
    line += deltaLine;
    startChar = deltaLine === 0 ? startChar + deltaStart : deltaStart;
    tokens.push({
      line,
      startChar,
      length: data[i + 2] as number,
      type: data[i + 3] as number,
      modifiers: data[i + 4] as number,
    });
  }
  return tokens;
}

/** The classifier's token covering `needle` on `line` (zero-based). */
function tokenFor(
  data: number[],
  source: string,
  line: number,
  needle: string,
): SemanticToken | undefined {
  const text = source.split('\n')[line] ?? '';
  const start = text.indexOf(needle);
  if (start < 0) throw new Error(`fixture missing: ${needle}`);
  return decode(data).find((token) => token.line === line && token.startChar === start);
}

const typeName = (token: SemanticToken | undefined): string | undefined =>
  token === undefined ? undefined : SEMANTIC_TOKEN_TYPES[token.type];

describe('semantic token legend', () => {
  it('advertises the required SEP-1 token types and warning modifiers', () => {
    expect(SEMANTIC_TOKEN_LEGEND.tokenTypes).toEqual(
      expect.arrayContaining([
        'stellarAddress',
        'contractId',
        'endpointUrl',
        'currencyCode',
        'deprecatedKey',
      ]),
    );
    expect(SEMANTIC_TOKEN_LEGEND.tokenModifiers).toEqual(
      expect.arrayContaining(['invalid', 'deprecated']),
    );
  });
});

describe('encodeSemanticTokens', () => {
  it('emits [deltaLine, deltaStart, length, type, modifiers] tuples', () => {
    const data = encodeSemanticTokens([
      { line: 0, startChar: 2, length: 3, type: 5, modifiers: 0 },
      { line: 0, startChar: 8, length: 4, type: 0, modifiers: 1 },
      { line: 2, startChar: 1, length: 5, type: 3, modifiers: 0 },
    ]);

    expect(data).toEqual([
      0,
      2,
      3,
      5,
      0, // line 0, col 2
      0,
      6,
      4,
      0,
      1, // same line: 8 - 2 = 6
      2,
      1,
      5,
      3,
      0, // new line: absolute column
    ]);
  });

  it('sorts by position and drops zero-length and overlapping tokens', () => {
    const data = encodeSemanticTokens([
      { line: 1, startChar: 4, length: 2, type: 5, modifiers: 0 },
      { line: 0, startChar: 0, length: 3, type: 5, modifiers: 0 },
      { line: 0, startChar: 1, length: 2, type: 5, modifiers: 0 }, // overlaps
      { line: 0, startChar: 9, length: 0, type: 5, modifiers: 0 }, // empty
    ]);

    expect(data).toEqual([0, 0, 3, 5, 0, 1, 4, 2, 5, 0]);
  });
});

describe('computeSemanticTokens', () => {
  const data = computeSemanticTokens(SAMPLE);

  it('classifies a valid Ed25519 issuer as a stellar address', () => {
    const token = tokenFor(data, SAMPLE, 0, VALID_ADDRESS);
    expect(typeName(token)).toBe('stellarAddress');
    expect(token?.modifiers).toBe(0);
  });

  it('flags a mistyped issuer with the invalid modifier but keeps its type', () => {
    const token = tokenFor(data, SAMPLE, 9, 'not-an-address');
    expect(typeName(token)).toBe('stellarAddress');
    expect(token?.modifiers).toBe(INVALID_BIT);
  });

  it('classifies a Soroban contract as contractId', () => {
    const root = tokenFor(data, SAMPLE, 2, VALID_CONTRACT);
    const inCurrency = tokenFor(data, SAMPLE, 10, VALID_CONTRACT);
    expect(typeName(root)).toBe('contractId');
    expect(typeName(inCurrency)).toBe('contractId');
  });

  it('classifies an endpoint and marks a malformed URL invalid', () => {
    const valid = tokenFor(data, SAMPLE, 1, 'https://example.com/auth');
    const invalid = tokenFor(data, SAMPLE, 3, 'not-a-url');
    expect(typeName(valid)).toBe('endpointUrl');
    expect(valid?.modifiers).toBe(0);
    expect(typeName(invalid)).toBe('endpointUrl');
    expect(invalid?.modifiers).toBe(INVALID_BIT);
  });

  it('classifies a currency code', () => {
    const token = tokenFor(data, SAMPLE, 8, 'USDC');
    expect(typeName(token)).toBe('currencyCode');
  });

  it('marks a deprecated key with the deprecated modifier', () => {
    const token = tokenFor(data, SAMPLE, 1, 'AUTH_SERVER');
    expect(typeName(token)).toBe('deprecatedKey');
    expect(token?.modifiers).toBe(DEPRECATED_BIT);
  });

  it('marks a key SEP-1 does not define inside a table as invalid', () => {
    const token = tokenFor(data, SAMPLE, 6, 'ORG_PRINCIPALS');
    expect(typeName(token)).toBe('key');
    expect(token?.modifiers).toBe(INVALID_BIT);
  });

  it('produces only well-formed 5-tuples', () => {
    expect(data.length % 5).toBe(0);
    expect(collectSemanticTokens(SAMPLE).every((token) => token.length > 0)).toBe(true);
  });
});

// ── the server endpoint ───────────────────────────────────────────────────────

describe('textDocument/semanticTokens/full over LSP', () => {
  it('advertises the capability and returns the encoded token stream', async () => {
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

    const pending = runLspServer(input, output);
    frame({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { capabilities: {} },
    });
    frame({
      jsonrpc: '2.0',
      method: 'textDocument/didOpen',
      params: {
        textDocument: {
          uri: 'file:///stellar.toml',
          version: 1,
          text: `SIGNING_KEY = "${VALID_ADDRESS}"\n`,
        },
      },
    });
    frame({
      jsonrpc: '2.0',
      id: 2,
      method: 'textDocument/semanticTokens/full',
      params: { textDocument: { uri: 'file:///stellar.toml' } },
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
    expect(initialize?.result.capabilities.semanticTokensProvider.legend.tokenTypes).toContain(
      'stellarAddress',
    );

    const tokens = messages.find((m) => m.id === 2);
    expect(tokens?.result.data).toEqual(
      computeSemanticTokens(`SIGNING_KEY = "${VALID_ADDRESS}"\n`),
    );
    expect(tokens?.result.data.length).toBeGreaterThan(0);
  });
});
