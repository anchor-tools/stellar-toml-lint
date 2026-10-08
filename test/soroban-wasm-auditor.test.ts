import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import {
  INVALID_SEP41_SIGNATURE_RULE,
  MISSING_CONTRACT_SPEC_RULE,
  MISSING_SEP41_FUNCTION_RULE,
  WASM_NOT_FOUND_RULE,
  auditContractWasm,
  auditTomlContractWasm,
  decompressWasm,
  verifySep41Wasm,
  wasmAuditorRules,
} from '../src/soroban/wasm-auditor.js';
import { lint } from '../src/lint.js';

const CONTRACT_ID = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const RPC_URL = 'https://soroban-testnet.stellar.org';

function encodeLeb128(value: number): Buffer {
  const bytes: number[] = [];
  let v = value;
  while (true) {
    const byte = v & 0x7f;
    v >>>= 7;
    if (v === 0) {
      bytes.push(byte);
      break;
    } else {
      bytes.push(byte | 0x80);
    }
  }
  return Buffer.from(bytes);
}

function buildWasmFromSpecEntries(entries: xdr.ScSpecEntry[]): Buffer {
  const payload = Buffer.concat(entries.map((e) => e.toXDR()));
  const sectionName = Buffer.from('contractspecv0', 'utf8');
  const nameLenLeb = encodeLeb128(sectionName.length);
  const sectionContent = Buffer.concat([nameLenLeb, sectionName, payload]);
  const sectionLenLeb = encodeLeb128(sectionContent.length);
  const customSection = Buffer.concat([Buffer.from([0]), sectionLenLeb, sectionContent]);
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, customSection]);
}

function createFullSep41SpecEntries(): xdr.ScSpecEntry[] {
  const fns: xdr.ScSpecFunctionV0[] = [
    new xdr.ScSpecFunctionV0({
      doc: 'initialize',
      name: 'initialize',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'admin',
          name: 'admin',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'decimal',
          name: 'decimal',
          type: xdr.ScSpecTypeDef.scSpecTypeU32(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'name',
          name: 'name',
          type: xdr.ScSpecTypeDef.scSpecTypeString(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'symbol',
          name: 'symbol',
          type: xdr.ScSpecTypeDef.scSpecTypeString(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeVoid()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'balance',
      name: 'balance',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'id',
          name: 'id',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeI128()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'spendable_balance',
      name: 'spendable_balance',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'id',
          name: 'id',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeI128()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'authorized',
      name: 'authorized',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'id',
          name: 'id',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeBool()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'transfer',
      name: 'transfer',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'from',
          name: 'from',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'to',
          name: 'to',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'amount',
          name: 'amount',
          type: xdr.ScSpecTypeDef.scSpecTypeI128(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeVoid()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'transfer_from',
      name: 'transfer_from',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'spender',
          name: 'spender',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'from',
          name: 'from',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'to',
          name: 'to',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'amount',
          name: 'amount',
          type: xdr.ScSpecTypeDef.scSpecTypeI128(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeVoid()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'burn',
      name: 'burn',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'from',
          name: 'from',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'amount',
          name: 'amount',
          type: xdr.ScSpecTypeDef.scSpecTypeI128(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeVoid()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'burn_from',
      name: 'burn_from',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'spender',
          name: 'spender',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'from',
          name: 'from',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'amount',
          name: 'amount',
          type: xdr.ScSpecTypeDef.scSpecTypeI128(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeVoid()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'decimals',
      name: 'decimals',
      inputs: [],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeU32()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'name',
      name: 'name',
      inputs: [],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeString()],
    }),
    new xdr.ScSpecFunctionV0({
      doc: 'symbol',
      name: 'symbol',
      inputs: [],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeString()],
    }),
  ];

  return fns.map((fn) => xdr.ScSpecEntry.scSpecEntryFunctionV0(fn));
}

function mockInstanceEntryXdr(contractId: string, wasmHash: Buffer, isSac = false): string {
  const executable = isSac
    ? xdr.ContractExecutable.contractExecutableStellarAsset()
    : xdr.ContractExecutable.contractExecutableWasm(wasmHash);
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage: [] })),
    }),
  );
  return entry.toXDR('base64');
}

function mockCodeEntryXdr(wasmHash: Buffer, wasmBytes: Buffer): string {
  const entry = xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: wasmHash,
      code: wasmBytes,
    }),
  );
  return entry.toXDR('base64');
}

describe('Soroban WASM Bytecode Disassembler and SEP-41 Conformance Auditor', () => {
  it('passes cleanly for a valid WASM binary implementing full SEP-41 Token Interface', () => {
    const wasm = buildWasmFromSpecEntries(createFullSep41SpecEntries());
    const diagnostics = verifySep41Wasm(wasm, CONTRACT_ID);
    expect(diagnostics).toEqual([]);
  });

  it('decompresses gzip-compressed WASM bytecode transparently', () => {
    const rawWasm = buildWasmFromSpecEntries(createFullSep41SpecEntries());
    const gzippedWasm = gzipSync(rawWasm);

    expect(decompressWasm(gzippedWasm)).toEqual(rawWasm);
    const diagnostics = verifySep41Wasm(gzippedWasm, CONTRACT_ID);
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/missing-contract-spec when custom section is absent', () => {
    const bareWasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const diagnostics = verifySep41Wasm(bareWasm, CONTRACT_ID);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: MISSING_CONTRACT_SPEC_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts soroban/missing-sep41-function when mandatory functions are missing', () => {
    // Only include transfer and balance, omit remaining 9 functions
    const partialEntries = createFullSep41SpecEntries().slice(0, 2);
    const wasm = buildWasmFromSpecEntries(partialEntries);

    const diagnostics = verifySep41Wasm(wasm, CONTRACT_ID);
    expect(diagnostics.length).toBeGreaterThan(0);
    expect(diagnostics.some((d) => d.rule === MISSING_SEP41_FUNCTION_RULE)).toBe(true);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: MISSING_SEP41_FUNCTION_RULE,
        message: expect.stringContaining('transfer_from'),
      }),
    );
  });

  it('asserts soroban/invalid-sep41-signature on parameter count mismatch', () => {
    const entries = createFullSep41SpecEntries().filter(
      (e) => e.functionV0().name().toString() !== 'balance',
    );
    // Add balance with 2 parameters instead of 1
    const invalidBalance = new xdr.ScSpecFunctionV0({
      doc: 'balance',
      name: 'balance',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'id',
          name: 'id',
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
        }),
        new xdr.ScSpecFunctionInputV0({
          doc: 'extra',
          name: 'extra',
          type: xdr.ScSpecTypeDef.scSpecTypeU32(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeI128()],
    });
    entries.push(xdr.ScSpecEntry.scSpecEntryFunctionV0(invalidBalance));

    const wasm = buildWasmFromSpecEntries(entries);
    const diagnostics = verifySep41Wasm(wasm, CONTRACT_ID);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INVALID_SEP41_SIGNATURE_RULE,
        severity: 'error',
        message: expect.stringContaining('balance'),
      }),
    );
  });

  it('asserts soroban/invalid-sep41-signature on parameter type mismatch', () => {
    const entries = createFullSep41SpecEntries().filter(
      (e) => e.functionV0().name().toString() !== 'authorized',
    );
    // Add authorized with U32 param instead of Address
    const invalidAuthorized = new xdr.ScSpecFunctionV0({
      doc: 'authorized',
      name: 'authorized',
      inputs: [
        new xdr.ScSpecFunctionInputV0({
          doc: 'id',
          name: 'id',
          type: xdr.ScSpecTypeDef.scSpecTypeU32(),
        }),
      ],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeBool()],
    });
    entries.push(xdr.ScSpecEntry.scSpecEntryFunctionV0(invalidAuthorized));

    const wasm = buildWasmFromSpecEntries(entries);
    const diagnostics = verifySep41Wasm(wasm, CONTRACT_ID);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INVALID_SEP41_SIGNATURE_RULE,
        severity: 'error',
        message: expect.stringContaining('authorized'),
      }),
    );
  });

  it('asserts soroban/invalid-sep41-signature on return type mismatch', () => {
    const entries = createFullSep41SpecEntries().filter(
      (e) => e.functionV0().name().toString() !== 'decimals',
    );
    // Add decimals returning String instead of U32
    const invalidDecimals = new xdr.ScSpecFunctionV0({
      doc: 'decimals',
      name: 'decimals',
      inputs: [],
      outputs: [xdr.ScSpecTypeDef.scSpecTypeString()],
    });
    entries.push(xdr.ScSpecEntry.scSpecEntryFunctionV0(invalidDecimals));

    const wasm = buildWasmFromSpecEntries(entries);
    const diagnostics = verifySep41Wasm(wasm, CONTRACT_ID);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INVALID_SEP41_SIGNATURE_RULE,
        severity: 'error',
        message: expect.stringContaining('decimals'),
      }),
    );
  });

  it('audits contract on-chain via Soroban RPC and passes for valid SEP-41 WASM', async () => {
    const wasmHash = Buffer.alloc(32, 0xaa);
    const wasm = buildWasmFromSpecEntries(createFullSep41SpecEntries());
    const instanceXdr = mockInstanceEntryXdr(CONTRACT_ID, wasmHash);
    const codeXdr = mockCodeEntryXdr(wasmHash, wasm);

    let callCount = 0;
    const fetchImpl = (async () => {
      callCount++;
      const isInstance = callCount === 1;
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 1000,
            entries: [{ xdr: isInstance ? instanceXdr : codeXdr, liveUntilLedgerSeq: 2000 }],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditContractWasm(CONTRACT_ID, RPC_URL, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('passes cleanly without WASM inspection for Stellar Asset Contracts (SAC)', async () => {
    const wasmHash = Buffer.alloc(32);
    const sacInstanceXdr = mockInstanceEntryXdr(CONTRACT_ID, wasmHash, true);

    const fetchImpl = (async () => {
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 1000,
            entries: [{ xdr: sacInstanceXdr, liveUntilLedgerSeq: 2000 }],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditContractWasm(CONTRACT_ID, RPC_URL, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/wasm-not-found when contract instance entry is missing', async () => {
    const fetchImpl = (async () => {
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 1000,
            entries: [],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditContractWasm(CONTRACT_ID, RPC_URL, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: WASM_NOT_FOUND_RULE,
        severity: 'error',
      }),
    );
  });

  it('audits all token contracts in a stellar.toml document', async () => {
    const source = [
      'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      `contract="${CONTRACT_ID}"`,
    ].join('\n');
    const doc = lint(source).parsed ?? {};

    const wasmHash = Buffer.alloc(32, 0xbb);
    const wasm = buildWasmFromSpecEntries(createFullSep41SpecEntries());
    const instanceXdr = mockInstanceEntryXdr(CONTRACT_ID, wasmHash);
    const codeXdr = mockCodeEntryXdr(wasmHash, wasm);

    let callCount = 0;
    const fetchImpl = (async () => {
      callCount++;
      const isInstance = callCount === 1;
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 1000,
            entries: [{ xdr: isInstance ? instanceXdr : codeXdr, liveUntilLedgerSeq: 2000 }],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditTomlContractWasm(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('registers all required Soroban WASM auditor rule definitions', () => {
    expect(wasmAuditorRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: WASM_NOT_FOUND_RULE, severity: 'error' },
      { id: MISSING_CONTRACT_SPEC_RULE, severity: 'error' },
      { id: MISSING_SEP41_FUNCTION_RULE, severity: 'error' },
      { id: INVALID_SEP41_SIGNATURE_RULE, severity: 'error' },
    ]);
  });
});
