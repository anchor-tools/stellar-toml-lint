import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getHoverInfo } from '../src/lsp/hover.js';
import type { HoverPosition } from '../src/lsp/hover.js';
import {
  FIELD_DOCS,
  fieldDoc,
  qualifiedFieldName,
  KNOWN_CURRENCY_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_GLOBAL_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
} from '../src/spec.js';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const DOC = [
  '# Every field below is documented in SEP-1.',
  'VERSION = "2.7.0"',
  'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
  'SIGNING_KEY = "GAC2CQ7JBSRCCNZRCSJNZK5SMH4R4N5XQVQZQZQZQZQZQZQZQZQZQZQ"',
  '',
  '[DOCUMENTATION]',
  'ORG_NAME = "Example Anchor"',
  'MYSTERY_FIELD = "not a SEP-1 field"',
  '',
  '[[CURRENCIES]]',
  'code = "USDX"',
  'status = "live"',
  'display_decimals = 2',
  '',
  '[[VALIDATORS]]',
  'ALIAS = "example-us-node"',
  '',
].join('\n');

/** Zero-based position of the first character of `needle`. */
function at(source: string, needle: string): HoverPosition {
  const index = source.indexOf(needle);
  if (index < 0) throw new Error(`fixture missing: ${needle}`);
  const before = source.slice(0, index);
  return {
    line: before.split('\n').length - 1,
    character: index - (before.lastIndexOf('\n') + 1),
  };
}

const markdown = (source: string, needle: string): string => {
  const hover = getHoverInfo(source, at(source, needle));
  expect(hover).not.toBeNull();
  expect(hover?.contents.kind).toBe('markdown');
  return hover?.contents.value ?? '';
};

describe('getHoverInfo', () => {
  it('describes SIGNING_KEY with its account ID type and a spec link', () => {
    const value = markdown(DOC, 'SIGNING_KEY');

    expect(value).toContain('`SIGNING_KEY`');
    expect(value).toContain('account ID (`G...`)');
    expect(value).toContain('SEP-10');
    expect(value).toContain(
      '[SEP-1 — General Information](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md#general-information)',
    );
  });

  it('lists the permitted values of [[CURRENCIES]].status', () => {
    const value = markdown(DOC, 'status');

    expect(value).toContain('`[[CURRENCIES]].status`');
    expect(value).toContain('**Permitted values:** `live`, `dead`, `test`, `private`');
    expect(value).toContain('sep-0001.md#currency-documentation');
  });

  it('qualifies a field by its enclosing section', () => {
    expect(markdown(DOC, 'ORG_NAME')).toContain('`[DOCUMENTATION].ORG_NAME`');
    expect(markdown(DOC, 'display_decimals')).toContain('`[[CURRENCIES]].display_decimals`');
    expect(markdown(DOC, 'display_decimals')).toContain('integer (0-7)');
    expect(markdown(DOC, 'VERSION')).toContain('`VERSION`');
  });

  it('explains a table header rather than a field inside it', () => {
    const documentation = markdown(DOC, '[DOCUMENTATION]');
    expect(documentation).toContain('`[DOCUMENTATION]`');
    expect(documentation).toContain('*table*');
    expect(documentation).toContain('[SEP-1 — Organization Documentation]');

    const currencies = markdown(DOC, '[[CURRENCIES]]');
    expect(currencies).toContain('`[[CURRENCIES]]`');
    expect(currencies).toContain('*array of tables*');
    expect(currencies).toContain('[SEP-1 — Currency Documentation]');
  });

  it('returns null on whitespace, comments, and unknown keys', () => {
    const lines = DOC.split('\n');
    const blank = lines.findIndex((line) => line === '');
    const comment = lines.findIndex((line) => line.startsWith('#'));

    expect(getHoverInfo(DOC, { line: blank, character: 0 })).toBeNull();
    expect(getHoverInfo(DOC, { line: comment, character: 3 })).toBeNull();

    expect(getHoverInfo(DOC, at(DOC, 'MYSTERY_FIELD'))).toBeNull();
    expect(getHoverInfo(DOC, at(DOC, '"not a SEP-1 field"'))).toBeNull();
    expect(getHoverInfo(DOC, { line: 999, character: 0 })).toBeNull();
  });

  it('treats the space immediately after a key as not part of it', () => {
    const start = at(DOC, 'SIGNING_KEY');
    const key = 'SIGNING_KEY';

    expect(
      getHoverInfo(DOC, { ...start, character: start.character + key.length - 1 }),
    ).not.toBeNull();
    expect(getHoverInfo(DOC, { ...start, character: start.character + key.length })).toBeNull();
    expect(getHoverInfo(DOC, { ...start, character: start.character - 1 })).toBeNull();
  });

  it('covers the hovered token with the hover range', () => {
    const hover = getHoverInfo(DOC, at(DOC, 'display_decimals'));
    const line = DOC.split('\n')[hover?.range.start.line ?? -1] ?? '';

    expect(hover?.range.start.character).toBe(line.indexOf('display_decimals'));
    expect(hover?.range.end.character).toBe(
      line.indexOf('display_decimals') + 'display_decimals'.length,
    );
    expect(hover?.range.start.line).toBe(hover?.range.end.line);
  });

  it('ignores keys a table does not document', () => {
    const source = ['[DOCUMENTATION]', 'ORG_NAME = "Example"', 'ORG_STATUS = "live"', ''].join(
      '\n',
    );

    expect(getHoverInfo(source, at(source, 'ORG_NAME'))).not.toBeNull();
    expect(getHoverInfo(source, at(source, 'ORG_STATUS'))).toBeNull();
  });
});

describe('field documentation coverage', () => {
  const known: [string, Set<string>][] = [
    ['', KNOWN_GLOBAL_FIELDS],
    ['DOCUMENTATION', KNOWN_DOCUMENTATION_FIELDS],
    ['PRINCIPALS', KNOWN_PRINCIPAL_FIELDS],
    ['CURRENCIES', KNOWN_CURRENCY_FIELDS],
    ['VALIDATORS', KNOWN_VALIDATOR_FIELDS],
  ];

  it('documents every field the linter recognises', () => {
    for (const [section, names] of known) {
      for (const name of names) {
        expect(
          fieldDoc(section, name),
          `missing hover doc for ${qualifiedFieldName(section, name)}`,
        ).toBeDefined();
      }
    }
  });

  it('carries no documentation for fields the linter does not know', () => {
    const knownKeys = new Set(
      known.flatMap(([section, names]) => [...names].map((name) => `${section}/${name}`)),
    );

    for (const doc of FIELD_DOCS) {
      expect(
        knownKeys.has(`${doc.section}/${doc.name}`),
        `stale hover doc for ${qualifiedFieldName(doc.section, doc.name)}`,
      ).toBe(true);
    }
  });

  it('quotes the spec with a type and a resolvable anchor', () => {
    const anchors = new Set([
      'general-information',
      'organization-documentation',
      'point-of-contact-documentation',
      'currency-documentation',
      'validator-information',
    ]);

    for (const doc of FIELD_DOCS) {
      const label = qualifiedFieldName(doc.section, doc.name);
      expect(doc.description.length, label).toBeGreaterThan(10);
      expect(doc.type.length, label).toBeGreaterThan(0);
      expect(anchors.has(doc.anchor), label).toBe(true);
      if (doc.values !== undefined) expect(doc.values.length, label).toBeGreaterThan(0);
    }
  });

  it('qualifies names the way the file writes them', () => {
    expect(qualifiedFieldName('', 'SIGNING_KEY')).toBe('SIGNING_KEY');
    expect(qualifiedFieldName('DOCUMENTATION', 'ORG_NAME')).toBe('[DOCUMENTATION].ORG_NAME');
    expect(qualifiedFieldName('CURRENCIES', 'status')).toBe('[[CURRENCIES]].status');
    expect(qualifiedFieldName('VALIDATORS', 'HOST')).toBe('[[VALIDATORS]].HOST');
  });
});

// ── end to end through the built `--lsp` binary ─────────────────────────────

interface RpcMessage {
  jsonrpc: string;
  id?: number;
  method?: string;
  params?: unknown;
  result?: unknown;
}

/** Speaks the framed protocol to `stellar-toml-lint --lsp`. */
function startServer(): {
  request: (id: number, method: string, params: unknown) => Promise<RpcMessage>;
  notify: (method: string, params: unknown) => void;
  close: () => void;
} {
  const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [CLI, '--lsp'], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child.stderr.resume();
  // The server is killed at the end of the test; a late write must not throw.
  child.stdin.on('error', () => {});

  let buffer = Buffer.alloc(0);
  const waiting = new Map<number, { resolve: (m: RpcMessage) => void; timer: NodeJS.Timeout }>();

  child.stdout.on('data', (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd < 0) return;
      const header = buffer.subarray(0, headerEnd).toString('ascii');
      const match = /Content-Length:\s*(\d+)/i.exec(header);
      if (!match) {
        buffer = buffer.subarray(headerEnd + 4);
        continue;
      }
      const bodyStart = headerEnd + 4;
      const length = Number(match[1]);
      if (buffer.length < bodyStart + length) return;

      const body = buffer.subarray(bodyStart, bodyStart + length).toString('utf8');
      buffer = buffer.subarray(bodyStart + length);

      const message = JSON.parse(body) as RpcMessage;
      const pending = message.id === undefined ? undefined : waiting.get(message.id);
      if (pending === undefined) continue;
      clearTimeout(pending.timer);
      waiting.delete(message.id as number);
      pending.resolve(message);
    }
  });

  const send = (message: unknown): void => {
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    child.stdin.write(`Content-Length: ${body.length}\r\n\r\n`);
    child.stdin.write(body);
  };

  return {
    request: (id, method, params) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiting.delete(id);
          reject(new Error(`timed out waiting for a response to ${method}`));
        }, 10_000);
        waiting.set(id, { resolve, timer });
        send({ jsonrpc: '2.0', id, method, params });
      }),
    notify: (method, params) => send({ jsonrpc: '2.0', method, params }),
    close: () => child.kill(),
  };
}

describe('textDocument/hover over stdio', () => {
  it('advertises hover and answers a hover request with the field docs', async () => {
    const server = startServer();
    try {
      const init = await server.request(1, 'initialize', { capabilities: {} });
      const capabilities = (init.result as { capabilities: Record<string, unknown> }).capabilities;
      expect(capabilities.hoverProvider).toBe(true);

      server.notify('initialized', {});
      const uri = 'file:///stellar.toml';
      server.notify('textDocument/didOpen', {
        textDocument: { uri, version: 1, text: DOC },
      });

      const hover = await server.request(2, 'textDocument/hover', {
        textDocument: { uri },
        position: at(DOC, 'SIGNING_KEY'),
      });
      const contents = (hover.result as { contents: { kind: string; value: string } }).contents;
      expect(contents.kind).toBe('markdown');
      expect(contents.value).toContain('account ID (`G...`)');
      expect(contents.value).toContain('sep-0001.md#general-information');

      const blankLine = DOC.split('\n').findIndex((line) => line === '');
      const blank = await server.request(3, 'textDocument/hover', {
        textDocument: { uri },
        position: { line: blankLine, character: 0 },
      });
      expect(blank.result).toBeNull();
    } finally {
      server.close();
    }
  }, 20_000);
});
