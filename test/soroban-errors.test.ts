import { describe, expect, it } from 'vitest';
import { Address, StrKey, xdr } from '@stellar/stellar-base';
import { allRules } from '../src/rules/index.js';
import { contractDataInstanceKey } from '../src/soroban.js';
import {
  buildErrorCodeMatrix,
  checkContractErrorCatalogues,
  checkContractErrorCodes,
  errorCodeMatrixDiagnostics,
  formatContractErrorCatalogues,
  formatErrorCodeMatrix,
  MAX_USER_ERROR_CODE,
  parseContractErrorSpecs,
  sorobanErrorRules,
  SYSTEM_ERROR_CATEGORIES,
} from '../src/soroban/errors.js';

const DUPLICATE = 'soroban/duplicate-error-code';
const COLLISION = 'soroban/system-error-code-collision';

/** Unsigned LEB128, the length and size encoding WASM sections use. */
function encodeU32(value: number): Buffer {
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

/** A WASM module carrying exactly these spec entries in `contractspecv0`. */
function wasmWithEntries(entries: xdr.ScSpecEntry[]): Buffer {
  const payload = Buffer.concat(entries.map((entry) => entry.toXDR()));
  const name = Buffer.from('contractspecv0', 'utf8');
  const content = Buffer.concat([encodeU32(name.length), name, payload]);
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, Buffer.from([0x00]), encodeU32(content.length), content]);
}

/** One `#[contracterror]` enum, as `cargo build --target wasm32-unknown-unknown` ships it. */
function errorEnum(
  name: string,
  cases: Array<{ name: string; code: number; doc?: string }>,
): xdr.ScSpecEntry {
  return xdr.ScSpecEntry.scSpecEntryUdtErrorEnumV0(
    new xdr.ScSpecUdtErrorEnumV0({
      doc: `${name} codes`,
      lib: '',
      name,
      cases: cases.map(
        (one) =>
          new xdr.ScSpecUdtErrorEnumCaseV0({ doc: one.doc ?? '', name: one.name, value: one.code }),
      ),
    }),
  );
}

const VALID = [
  errorEnum('Error', [
    { name: 'NotAuthorized', code: 1 },
    { name: 'NotFound', code: 2, doc: 'missing row' },
  ]),
];

describe('soroban error code matrix', () => {
  it('extracts every declared error case from the spec', () => {
    expect(parseContractErrorSpecs(wasmWithEntries(VALID))).toEqual([
      {
        name: 'Error',
        lib: '',
        doc: 'Error codes',
        cases: [
          { enumName: 'Error', name: 'NotAuthorized', code: 1, doc: '' },
          { enumName: 'Error', name: 'NotFound', code: 2, doc: 'missing row' },
        ],
      },
    ]);
  });

  it('passes a contract whose codes are unique and encodable', () => {
    expect(checkContractErrorCodes(wasmWithEntries(VALID), { contractId: 'CABC' })).toEqual([]);
  });

  it('ignores spec entries that are not error enums', () => {
    const mixed = wasmWithEntries([
      xdr.ScSpecEntry.scSpecEntryFunctionV0(
        new xdr.ScSpecFunctionV0({ doc: '', name: 'transfer', inputs: [], outputs: [] }),
      ),
      ...VALID,
    ]);
    expect(parseContractErrorSpecs(mixed)).toHaveLength(1);
  });

  it('reads nothing from a module without a spec section', () => {
    const bare = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    expect(parseContractErrorSpecs(bare)).toEqual([]);
    expect(checkContractErrorCodes(bare)).toEqual([]);
  });

  it('reports conflicting error codes', () => {
    const wasm = wasmWithEntries([
      errorEnum('Error', [{ name: 'NotAuthorized', code: 3 }]),
      errorEnum('OtherError', [{ name: 'Expired', code: 3 }]),
    ]);
    const diagnostics = checkContractErrorCodes(wasm);

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: DUPLICATE,
      severity: 'error',
      category: 'network',
    });
    expect(diagnostics[0]?.message).toContain('Error::NotAuthorized and OtherError::Expired');
    expect(diagnostics[0]?.message).toContain('same error code 3');
  });

  it('reports a code the host would reinterpret as a system error', () => {
    const wasm = wasmWithEntries([
      errorEnum('Error', [{ name: 'TooBig', code: MAX_USER_ERROR_CODE + 1 }]),
    ]);
    const diagnostics = checkContractErrorCodes(wasm);

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: COLLISION, severity: 'error' });
    expect(diagnostics[0]?.suggestion).toContain(String(MAX_USER_ERROR_CODE));
  });

  it('sorts the matrix by code and names each group of duplicates', () => {
    const matrix = buildErrorCodeMatrix(
      parseContractErrorSpecs(
        wasmWithEntries([
          errorEnum('Error', [
            { name: 'Second', code: 2 },
            { name: 'First', code: 1 },
            { name: 'AlsoFirst', code: 1 },
          ]),
        ]),
      ),
    );

    expect(matrix.cases.map((one) => `${one.code}:${one.name}`)).toEqual([
      '1:AlsoFirst',
      '1:First',
      '2:Second',
    ]);
    expect(matrix.duplicates).toHaveLength(1);
    expect(matrix.duplicates[0]?.map((one) => one.name)).toEqual(['AlsoFirst', 'First']);
  });

  it('tracks undocumented cases without turning them into diagnostics', () => {
    const matrix = buildErrorCodeMatrix(parseContractErrorSpecs(wasmWithEntries(VALID)));
    const diagnostics = errorCodeMatrixDiagnostics(matrix);

    expect(matrix.undocumented.map((one) => one.name)).toEqual(['NotAuthorized']);
    expect(diagnostics).toEqual([]);
  });

  it('renders the matrix as text, flagging rows that are wrong', () => {
    const matrix = buildErrorCodeMatrix(
      parseContractErrorSpecs(
        wasmWithEntries([
          errorEnum('Error', [
            { name: 'NotAuthorized', code: 1, doc: 'caller is not the admin' },
            { name: 'Expired', code: 1 },
          ]),
        ]),
      ),
    );
    const output = formatErrorCodeMatrix(matrix, { contractId: 'CACT', helpUrls: true });

    expect(output).toContain('CACT error code matrix');
    expect(output).toContain('1  Error::NotAuthorized');
    expect(output).toContain('1  Error::Expired  <- duplicate');
    expect(output).toContain('https://github.com/stellar/stellar-xdr');
    expect(output).toContain('host categories: sceWasmVm=1');
  });

  it('says so when a contract declares no errors', () => {
    const matrix = buildErrorCodeMatrix([]);
    expect(formatErrorCodeMatrix(matrix)).toContain('declares no custom errors');
  });

  it('honours severity overrides, including switching a rule off', () => {
    const wasm = wasmWithEntries([
      errorEnum('Error', [
        { name: 'A', code: 1 },
        { name: 'B', code: 1 },
      ]),
    ]);

    expect(checkContractErrorCodes(wasm, { rules: { [DUPLICATE]: 'off' } })).toEqual([]);
    expect(checkContractErrorCodes(wasm, { rules: { [DUPLICATE]: 'warning' } })[0]).toMatchObject({
      severity: 'warning',
    });
  });

  it('attaches the file path and contract that named the wasm', () => {
    const wasm = wasmWithEntries([
      errorEnum('Error', [{ name: 'Huge', code: MAX_USER_ERROR_CODE + 5 }]),
    ]);
    const diagnostics = checkContractErrorCodes(wasm, { path: 'CURRENCIES[0].contract' });

    expect(diagnostics[0]).toMatchObject({ path: 'CURRENCIES[0].contract' });
  });

  it('derives the host categories from the XDR rather than hand-typing them', () => {
    expect(SYSTEM_ERROR_CATEGORIES).toEqual([
      { name: 'sceWasmVm', code: 1 },
      { name: 'sceContext', code: 2 },
      { name: 'sceStorage', code: 3 },
      { name: 'sceObject', code: 4 },
      { name: 'sceCrypto', code: 5 },
      { name: 'sceEvents', code: 6 },
      { name: 'sceBudget', code: 7 },
      { name: 'sceValue', code: 8 },
      { name: 'sceAuth', code: 9 },
    ]);
  });

  it('registers its rules so --list-rules and --off know the ids', () => {
    const registered = allRules.map((rule) => rule.id);
    for (const rule of sorobanErrorRules) {
      expect(registered).toContain(rule.id);
    }
  });
});

const TESTNET = 'Test SDF Network ; September 2015';
const PRIVATE_NET = 'Private Anchor Net ; January 2026';
const TOKEN = StrKey.encodeContract(Buffer.alloc(32, 1));
const WRAPPER = StrKey.encodeContract(Buffer.alloc(32, 2));

/** A live instance entry whose executable runs the WASM with this hash. */
function instanceXdr(contractId: string, wasmHash: Buffer): string {
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(wasmHash),
          storage: [],
        }),
      ),
    }),
  );
  return entry.toXDR('base64');
}

function codeXdr(wasm: Buffer): string {
  return xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: Buffer.alloc(32),
      code: wasm,
    }),
  ).toXDR('base64');
}

/**
 * An RPC serving each contract's own instance and code entry. A contract mapped
 * to `undefined` has no instance, so its WASM is unreadable.
 */
function rpcServing(wasms: Record<string, Buffer | undefined>): typeof fetch {
  const entries = (key: string): unknown[] => {
    const ledgerKey = xdr.LedgerKey.fromXDR(key, 'base64');
    const live = (xdrValue: string): unknown[] => [
      { key, xdr: xdrValue, lastModifiedLedgerSeq: 1, liveUntilLedgerSeq: 500 },
    ];

    if (ledgerKey.switch().name === 'contractCode') {
      const hash = Buffer.from(
        (ledgerKey.value() as xdr.LedgerKeyContractCode).hash() as Uint8Array,
      );
      const wasm = Object.entries(wasms).find(([contractId]) =>
        wasmHashOf(contractId).equals(hash),
      )?.[1];
      return wasm === undefined ? [] : live(codeXdr(wasm));
    }

    const contractId = Object.keys(wasms).find((one) => contractDataInstanceKey(one) === key);
    if (contractId === undefined) return [];
    const wasm = wasms[contractId];
    return wasm === undefined ? [] : live(instanceXdr(contractId, wasmHashOf(contractId)));
  };

  return (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    return jsonResponse(entries(body.params.keys[0] as string));
  }) as unknown as typeof fetch;
}

/** Each contract gets its own code hash, so the two WASMs stay distinguishable. */
function wasmHashOf(contractId: string): Buffer {
  return Buffer.from(StrKey.decodeContract(contractId));
}

function jsonResponse(entries: unknown[]): Response {
  return new Response(
    JSON.stringify({ jsonrpc: '2.0', id: 1, result: { latestLedger: 100, entries } }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

const DUPLICATING = wasmWithEntries([
  errorEnum('Error', [
    { name: 'NotAuthorized', code: 1 },
    { name: 'AlreadyClaimed', code: 1 },
  ]),
]);
const CLEAN = wasmWithEntries(VALID);

describe('contract error catalogues across a file', () => {
  const file = (passphrase: string): Record<string, unknown> => ({
    NETWORK_PASSPHRASE: passphrase,
    CURRENCIES: [
      { code: 'USD', contract: TOKEN },
      { code: 'EUR', contract: WRAPPER },
    ],
  });

  it('audits every declared contract and names the path that declared it', async () => {
    const { catalogues, diagnostics } = await checkContractErrorCatalogues(
      file(TESTNET),
      rpcServing({ [TOKEN]: DUPLICATING, [WRAPPER]: CLEAN }),
    );

    expect(catalogues.map((one) => one.path)).toEqual([
      'CURRENCIES[0].contract',
      'CURRENCIES[1].contract',
    ]);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: DUPLICATE,
      path: 'CURRENCIES[0].contract',
    });
    expect(diagnostics[0]?.message).toContain(TOKEN);
  });

  it('skips a contract whose WASM cannot be read', async () => {
    const { catalogues, diagnostics } = await checkContractErrorCatalogues(
      file(TESTNET),
      rpcServing({ [TOKEN]: DUPLICATING, [WRAPPER]: undefined }),
    );

    expect(catalogues).toHaveLength(1);
    expect(diagnostics).toHaveLength(1);
  });

  it('reads nothing when the network has no known RPC endpoint', async () => {
    const audit = await checkContractErrorCatalogues(file(PRIVATE_NET), rpcServing({}));
    expect(audit).toEqual({ catalogues: [], diagnostics: [] });
  });

  it('honours rule overrides across every contract', async () => {
    const { diagnostics } = await checkContractErrorCatalogues(
      file(TESTNET),
      rpcServing({ [TOKEN]: DUPLICATING, [WRAPPER]: DUPLICATING }),
      { rules: { [DUPLICATE]: 'off' } },
    );
    expect(diagnostics).toEqual([]);
  });

  it('prints one matrix per contract for --format text --show-help-urls', async () => {
    const { catalogues } = await checkContractErrorCatalogues(
      file(TESTNET),
      rpcServing({ [TOKEN]: DUPLICATING, [WRAPPER]: CLEAN }),
    );
    const output = formatContractErrorCatalogues(catalogues, { helpUrls: true });

    expect(output).toContain(`${TOKEN} error code matrix`);
    expect(output).toContain(`${WRAPPER} error code matrix`);
    expect(output).toContain('1  Error::NotAuthorized  <- duplicate');
  });
});
