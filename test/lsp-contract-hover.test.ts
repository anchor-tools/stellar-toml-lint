import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import {
  ContractErrorDocs,
  contractErrorEnums,
  contractIdAt,
  renderContractErrors,
  withContractErrors,
} from '../src/lsp/contract-hover.js';
import { getHoverInfo } from '../src/lsp/hover.js';
import { runLspServer } from '../src/lsp/server.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const RPC = 'https://soroban-testnet.stellar.org';

// ---------------------------------------------------------------------------
// Fixtures: a WASM module whose spec declares an error enum
// ---------------------------------------------------------------------------

function u32(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return Buffer.from(bytes);
}

function errorEnum(name: string, doc: string, cases: [string, number, string][]): xdr.ScSpecEntry {
  return xdr.ScSpecEntry.scSpecEntryUdtErrorEnumV0(
    new xdr.ScSpecUdtErrorEnumV0({
      doc,
      lib: '',
      name,
      cases: cases.map(
        ([caseName, value, caseDoc]) =>
          new xdr.ScSpecUdtErrorEnumCaseV0({ doc: caseDoc, name: caseName, value }),
      ),
    }),
  );
}

function wasmWithSpec(entries: xdr.ScSpecEntry[]): Buffer {
  const payload = Buffer.concat(entries.map((entry) => entry.toXDR()));
  const name = Buffer.from('contractspecv0', 'utf8');
  const content = Buffer.concat([u32(name.length), name, payload]);
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, Buffer.from([0x00]), u32(content.length), content]);
}

const TOKEN_WASM = wasmWithSpec([
  xdr.ScSpecEntry.scSpecEntryFunctionV0(
    new xdr.ScSpecFunctionV0({ doc: '', name: 'transfer', inputs: [], outputs: [] }),
  ),
  errorEnum('TokenError', 'Errors raised by the token.', [
    ['InsufficientBalance', 2, 'The sender holds less than | the amount.'],
    ['NotInitialized', 1, 'Call `initialize` first.'],
    ['Frozen', 7, 'The account is frozen\nby the issuer.'],
  ]),
]);

const TOML = [
  'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
  '',
  '[[CURRENCIES]]',
  'code = "USDC"',
  `contract = "${CONTRACT}"`,
  '',
  `contract_id = "${CONTRACT}" # a custom key naming the same contract`,
].join('\n');

const CONTRACT_LINE = 4;
const CONTRACT_ID_LINE = 6;

function docsServing(wasm: Buffer | undefined): { docs: ContractErrorDocs; loads: () => number } {
  let loads = 0;
  const docs = new ContractErrorDocs(async () => {
    loads++;
    return wasm;
  });
  return { docs, loads: () => loads };
}

// ---------------------------------------------------------------------------

describe('contractErrorEnums', () => {
  it('decodes every error enum case with its code and doc comment', () => {
    expect(contractErrorEnums(TOKEN_WASM)).toEqual([
      {
        name: 'TokenError',
        doc: 'Errors raised by the token.',
        cases: [
          { name: 'InsufficientBalance', code: 2, doc: 'The sender holds less than | the amount.' },
          { name: 'NotInitialized', code: 1, doc: 'Call `initialize` first.' },
          { name: 'Frozen', code: 7, doc: 'The account is frozen\nby the issuer.' },
        ],
      },
    ]);
  });

  it('returns undefined for a module without a spec section', () => {
    expect(
      contractErrorEnums(Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])),
    ).toBeUndefined();
  });
});

describe('renderContractErrors', () => {
  it('renders a Markdown table sorted by code, keeping each row on one line', () => {
    const markdown = renderContractErrors(CONTRACT, contractErrorEnums(TOKEN_WASM)!);

    expect(markdown).toContain('`TokenError` — Errors raised by the token.');
    expect(markdown).toContain('| Code | Error | Description |');
    expect(markdown).toContain(
      [
        '| 1 | `NotInitialized` | Call `initialize` first. |',
        '| 2 | `InsufficientBalance` | The sender holds less than \\| the amount. |',
        '| 7 | `Frozen` | The account is frozen by the issuer. |',
      ].join('\n'),
    );
  });

  it('says so when the spec declares no error enums', () => {
    expect(renderContractErrors(CONTRACT, [])).toContain('declares no custom error enums');
  });
});

describe('contractIdAt', () => {
  it('finds the contract ID on the hovered line', () => {
    expect(contractIdAt(TOML, { line: CONTRACT_ID_LINE, character: 0 })).toEqual({
      id: CONTRACT,
      start: 15,
      end: 15 + CONTRACT.length,
    });
  });

  it('ignores lines without one, commented-out IDs, and invalid strkeys', () => {
    expect(contractIdAt(TOML, { line: 3, character: 2 })).toBeUndefined();
    expect(contractIdAt(`# contract = "${CONTRACT}"`, { line: 0, character: 3 })).toBeUndefined();
    expect(
      contractIdAt(`contract = "C${'A'.repeat(55)}"`, { line: 0, character: 3 }),
    ).toBeUndefined();
  });
});

describe('withContractErrors', () => {
  it('hovering a contract_id line shows a markdown table of error codes', async () => {
    const { docs } = docsServing(TOKEN_WASM);
    const position = { line: CONTRACT_ID_LINE, character: 3 };

    const hover = await withContractErrors(TOML, position, getHoverInfo(TOML, position), docs);

    expect(hover?.contents.kind).toBe('markdown');
    expect(hover?.contents.value).toContain('**Contract errors**');
    expect(hover?.contents.value).toContain('| 7 | `Frozen` |');
    expect(hover?.range).toEqual({
      start: { line: CONTRACT_ID_LINE, character: 15 },
      end: { line: CONTRACT_ID_LINE, character: 15 + CONTRACT.length },
    });
  });

  it('appends the table below the SEP-1 field documentation', async () => {
    const { docs } = docsServing(TOKEN_WASM);
    const position = { line: CONTRACT_LINE, character: 2 };
    const base = getHoverInfo(TOML, position);
    expect(base).not.toBeNull();

    const hover = await withContractErrors(TOML, position, base, docs);

    expect(hover?.range).toEqual(base?.range);
    expect(hover?.contents.value.startsWith(base!.contents.value)).toBe(true);
    expect(hover?.contents.value).toContain('\n\n---\n\n**Contract errors**');
  });

  it('caches lookups per contract', async () => {
    const { docs, loads } = docsServing(TOKEN_WASM);
    for (const line of [CONTRACT_LINE, CONTRACT_ID_LINE, CONTRACT_LINE]) {
      await withContractErrors(TOML, { line, character: 2 }, null, docs);
    }
    expect(loads()).toBe(1);
  });

  it('leaves the hover unchanged when there is no contract or no readable spec', async () => {
    const base = getHoverInfo(TOML, { line: 3, character: 1 });
    const offLine = docsServing(TOKEN_WASM);
    expect(await withContractErrors(TOML, { line: 3, character: 1 }, base, offLine.docs)).toBe(
      base,
    );
    expect(offLine.loads()).toBe(0);

    const unreadable = docsServing(undefined);
    expect(
      await withContractErrors(
        TOML,
        { line: CONTRACT_ID_LINE, character: 1 },
        null,
        unreadable.docs,
      ),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// End to end over the LSP wire
// ---------------------------------------------------------------------------

function rpcServing(wasm: Buffer): { fetchImpl: typeof fetch; calls: () => number } {
  let calls = 0;
  const instanceXdr = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32)),
          storage: [],
        }),
      ),
    }),
  ).toXDR('base64');
  const codeXdr = xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: Buffer.alloc(32),
      code: wasm,
    }),
  ).toXDR('base64');

  const fetchImpl = (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    calls++;
    const key = (JSON.parse(String(init?.body)) as { params: { keys: string[] } }).params
      .keys[0] as string;
    const isCode = xdr.LedgerKey.fromXDR(key, 'base64').switch().name === 'contractCode';
    const entry = {
      key,
      xdr: isCode ? codeXdr : instanceXdr,
      lastModifiedLedgerSeq: 1,
      liveUntilLedgerSeq: 200_000,
    };
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { latestLedger: 100_000, entries: [entry] },
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    );
  }) as unknown as typeof fetch;
  return { fetchImpl, calls: () => calls };
}

function frame(message: unknown): string {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`;
}

/** Runs a session and returns the response to the request with `id`. */
async function hoverOverWire(
  initializationOptions: unknown,
  fetchImpl: typeof fetch,
  position: { line: number; character: number },
): Promise<{ contents: { value: string } } | null> {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: Buffer[] = [];
  output.on('data', (chunk: Buffer) => chunks.push(chunk));

  const server = runLspServer(input, output, { fetchImpl });
  const uri = 'file:///stellar.toml';
  input.write(
    frame({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { initializationOptions } }),
  );
  input.write(
    frame({
      jsonrpc: '2.0',
      method: 'textDocument/didOpen',
      params: { textDocument: { uri, version: 1, text: TOML } },
    }),
  );
  input.write(
    frame({
      jsonrpc: '2.0',
      id: 2,
      method: 'textDocument/hover',
      params: { textDocument: { uri }, position },
    }),
  );

  const response = await new Promise<{ id: number; result: unknown }>((resolve) => {
    const check = () => {
      for (const part of Buffer.concat(chunks)
        .toString('utf8')
        .split(/Content-Length: \d+\r\n\r\n/)) {
        if (!part) continue;
        const message = JSON.parse(part) as { id?: number; result: unknown };
        if (message.id === 2) return resolve(message as { id: number; result: unknown });
      }
      setTimeout(check, 5);
    };
    check();
  });

  input.write(frame({ jsonrpc: '2.0', method: 'exit' }));
  input.end();
  await server;
  return response.result as { contents: { value: string } } | null;
}

describe('LSP server contract hover', () => {
  it('answers hover with the error table when the editor opts in', async () => {
    const rpc = rpcServing(TOKEN_WASM);
    const result = await hoverOverWire({ checkContracts: true, sorobanRpc: RPC }, rpc.fetchImpl, {
      line: CONTRACT_LINE,
      character: 2,
    });

    expect(result?.contents.value).toContain('| 1 | `NotInitialized` |');
    expect(rpc.calls()).toBe(2); // instance entry, then code entry
  });

  it('derives the RPC from NETWORK_PASSPHRASE when no endpoint is given', async () => {
    const rpc = rpcServing(TOKEN_WASM);
    const result = await hoverOverWire({ checkContracts: true }, rpc.fetchImpl, {
      line: CONTRACT_LINE,
      character: 2,
    });
    expect(result?.contents.value).toContain('**Contract errors**');
  });

  it('stays offline without opt-in and keeps the SEP-1 hover', async () => {
    const rpc = rpcServing(TOKEN_WASM);
    const result = await hoverOverWire(undefined, rpc.fetchImpl, {
      line: CONTRACT_LINE,
      character: 2,
    });

    expect(rpc.calls()).toBe(0);
    expect(result?.contents.value).not.toContain('Contract errors');
    expect(result?.contents.value).toContain('`[[CURRENCIES]].contract`');
  });
});
