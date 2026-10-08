/**
 * Shared fixtures for the Soroban on-chain audit tests.
 *
 * Not a `*.test.ts` file, so vitest does not collect it; it only provides the
 * small amount of XDR construction the four audit suites otherwise repeat.
 */
import { Address, xdr } from '@stellar/stellar-base';

/** Unsigned LEB128, the length and size encoding WASM sections use. */
export function encodeLeb128(value: number): Buffer {
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

/** A minimal WASM module carrying one named custom section. */
export function wasmWithCustomSection(sectionName: string, payload: Buffer): Buffer {
  const name = Buffer.from(sectionName, 'utf8');
  const content = Buffer.concat([encodeLeb128(name.length), name, payload]);
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, Buffer.from([0x00]), encodeLeb128(content.length), content]);
}

/** A WASM module whose `contractspecv0` section holds the given spec entries. */
export function specWasm(entries: xdr.ScSpecEntry[]): Buffer {
  return wasmWithCustomSection('contractspecv0', Buffer.concat(entries.map((e) => e.toXDR())));
}

/** A WASM module whose `contractenvmetav0` section holds the given env entries. */
export function envMetaWasm(entries: xdr.ScEnvMetaEntry[]): Buffer {
  return wasmWithCustomSection('contractenvmetav0', Buffer.concat(entries.map((e) => e.toXDR())));
}

/** A `scSpecEntryFunctionV0` declaring one zero-argument function. */
export function specFunction(name: string): xdr.ScSpecEntry {
  return xdr.ScSpecEntry.scSpecEntryFunctionV0(
    new xdr.ScSpecFunctionV0({ doc: '', name, inputs: [], outputs: [] }),
  );
}

function specType(typeName: string): xdr.ScSpecTypeDef {
  switch (typeName) {
    case 'scSpecTypeString':
      return xdr.ScSpecTypeDef.scSpecTypeString();
    case 'scSpecTypeU32':
      return xdr.ScSpecTypeDef.scSpecTypeU32();
    default:
      return xdr.ScSpecTypeDef.scSpecTypeI128();
  }
}

/**
 * A `scSpecEntryEventV0` named `name`, with `topicParams` in the topic list and
 * a single data parameter of `dataType`. `prefix` defaults to `[name]`.
 */
export function specEvent(
  name: string,
  topicParams: string[],
  dataType = 'scSpecTypeI128',
  prefix: string[] = [name],
): xdr.ScSpecEntry {
  const params = [
    ...topicParams.map(
      (topic) =>
        new xdr.ScSpecEventParamV0({
          doc: '',
          name: topic,
          type: xdr.ScSpecTypeDef.scSpecTypeAddress(),
          location: xdr.ScSpecEventParamLocationV0.scSpecEventParamLocationTopicList(),
        }),
    ),
    new xdr.ScSpecEventParamV0({
      doc: '',
      name: 'amount',
      type: specType(dataType),
      location: xdr.ScSpecEventParamLocationV0.scSpecEventParamLocationData(),
    }),
  ];
  return xdr.ScSpecEntry.scSpecEntryEventV0(
    new xdr.ScSpecEventV0({
      doc: '',
      lib: '',
      name,
      prefixTopics: prefix,
      params,
      dataFormat: xdr.ScSpecEventDataFormat.scSpecEventDataFormatSingleValue(),
    }),
  );
}

/** A contract instance ledger entry XDR, optionally carrying admin storage. */
export function instanceEntryXdr(options: {
  contractId: string;
  wasmHash?: Buffer;
  storage?: xdr.ScMapEntry[];
  stellarAsset?: boolean;
}): string {
  const executable = options.stellarAsset
    ? xdr.ContractExecutable.contractExecutableStellarAsset()
    : xdr.ContractExecutable.contractExecutableWasm(options.wasmHash ?? Buffer.alloc(32));
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(options.contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({ executable, storage: options.storage ?? [] }),
      ),
    }),
  );
  return entry.toXDR('base64');
}

/** A contract-code ledger entry XDR carrying the given WASM bytes. */
export function codeEntryXdr(wasm: Buffer, hash: Buffer = Buffer.alloc(32)): string {
  const entry = xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash,
      code: wasm,
    }),
  );
  return entry.toXDR('base64');
}

/**
 * A `fetch` stub that answers `getLedgerEntries` for a contract instance and
 * its code entry, dispatching on the ledger key the request carries.
 */
export function rpcFetch(
  instanceXdr: string,
  codeXdr: string,
): { fetchImpl: typeof fetch; calls: () => number } {
  let calls = 0;
  const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
    calls++;
    const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = body.params.keys[0] as string;
    const kind = xdr.LedgerKey.fromXDR(key, 'base64').switch().name;
    const entryXdr = kind === 'contractCode' ? codeXdr : instanceXdr;
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { latestLedger: 1000, entries: [{ xdr: entryXdr, liveUntilLedgerSeq: 2000 }] },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
  return { fetchImpl, calls: () => calls };
}

/** An instance storage entry mapping `admin`/`owner` to an account address. */
export function adminStorage(key: 'admin' | 'owner', address: string): xdr.ScMapEntry {
  return new xdr.ScMapEntry({
    key: xdr.ScVal.scvSymbol(key),
    val: new Address(address).toScVal(),
  });
}
