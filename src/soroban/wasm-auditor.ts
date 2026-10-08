/**
 * Soroban contract WASM bytecode disassembler and SEP-41 spec conformance auditor.
 *
 * Runs under opt-in --check-network for contracts declared under [[CURRENCIES]],
 * [[CONTRACTS]], or WEB_AUTH_CONTRACT_ID.
 *
 * Fetches contract code from Soroban RPC, decompresses and disassembles WebAssembly
 * custom section `contractspecv0`, parses the Soroban Contract Spec (SCS) XDR stream,
 * and verifies conformance with the SEP-41 Token Interface:
 * - Functions: initialize, balance, spendable_balance, authorized, transfer,
 *              transfer_from, burn, burn_from, decimals, name, symbol.
 * - Validates parameter counts and argument types.
 * - Validates return types.
 */

import { Address, cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';

export const WASM_NOT_FOUND_RULE = 'soroban/wasm-not-found';
export const MISSING_CONTRACT_SPEC_RULE = 'soroban/missing-contract-spec';
export const MISSING_SEP41_FUNCTION_RULE = 'soroban/missing-sep41-function';
export const INVALID_SEP41_SIGNATURE_RULE = 'soroban/invalid-sep41-signature';

export const SEP41_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md';

const CONTRACT_SPEC_SECTION = 'contractspecv0';
const RPC_TIMEOUT_MS = 10_000;

export interface Sep41FunctionExpected {
  name: string;
  inputs: { name?: string; type: string }[];
  output: string; // 'void' | 'scSpecTypeI128' | 'scSpecTypeBool' | 'scSpecTypeU32' | 'scSpecTypeString'
}

export const SEP41_MANDATORY_FUNCTIONS: Record<string, Sep41FunctionExpected> = {
  initialize: {
    name: 'initialize',
    inputs: [
      { name: 'admin', type: 'scSpecTypeAddress' },
      { name: 'decimal', type: 'scSpecTypeU32' },
      { name: 'name', type: 'scSpecTypeString' },
      { name: 'symbol', type: 'scSpecTypeString' },
    ],
    output: 'void',
  },
  balance: {
    name: 'balance',
    inputs: [{ name: 'id', type: 'scSpecTypeAddress' }],
    output: 'scSpecTypeI128',
  },
  spendable_balance: {
    name: 'spendable_balance',
    inputs: [{ name: 'id', type: 'scSpecTypeAddress' }],
    output: 'scSpecTypeI128',
  },
  authorized: {
    name: 'authorized',
    inputs: [{ name: 'id', type: 'scSpecTypeAddress' }],
    output: 'scSpecTypeBool',
  },
  transfer: {
    name: 'transfer',
    inputs: [
      { name: 'from', type: 'scSpecTypeAddress' },
      { name: 'to', type: 'scSpecTypeAddress' },
      { name: 'amount', type: 'scSpecTypeI128' },
    ],
    output: 'void',
  },
  transfer_from: {
    name: 'transfer_from',
    inputs: [
      { name: 'spender', type: 'scSpecTypeAddress' },
      { name: 'from', type: 'scSpecTypeAddress' },
      { name: 'to', type: 'scSpecTypeAddress' },
      { name: 'amount', type: 'scSpecTypeI128' },
    ],
    output: 'void',
  },
  burn: {
    name: 'burn',
    inputs: [
      { name: 'from', type: 'scSpecTypeAddress' },
      { name: 'amount', type: 'scSpecTypeI128' },
    ],
    output: 'void',
  },
  burn_from: {
    name: 'burn_from',
    inputs: [
      { name: 'spender', type: 'scSpecTypeAddress' },
      { name: 'from', type: 'scSpecTypeAddress' },
      { name: 'amount', type: 'scSpecTypeI128' },
    ],
    output: 'void',
  },
  decimals: {
    name: 'decimals',
    inputs: [],
    output: 'scSpecTypeU32',
  },
  name: {
    name: 'name',
    inputs: [],
    output: 'scSpecTypeString',
  },
  symbol: {
    name: 'symbol',
    inputs: [],
    output: 'scSpecTypeString',
  },
};

export interface WasmAuditorOptions {
  rules?: RuleOverrides;
  path?: string;
  rpcUrl?: string;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

interface ZlibModule {
  gunzipSync: (buf: Buffer) => Buffer;
  unzipSync: (buf: Buffer) => Buffer;
  inflateSync: (buf: Buffer) => Buffer;
}

function getZlibSync(): ZlibModule | null {
  try {
    const proc = (
      globalThis as unknown as {
        process?: { getBuiltinModule?: (mod: string) => ZlibModule };
      }
    ).process;
    return proc?.getBuiltinModule ? proc.getBuiltinModule('node:zlib') : null;
  } catch {
    return null;
  }
}

/**
 * Decompresses WebAssembly bytecode if it is gzip or zlib compressed,
 * or returns raw buffer if already uncompressed WebAssembly.
 */
export function decompressWasm(bytes: Buffer | Uint8Array): Buffer {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length >= 4 && buf.readUInt32BE(0) === 0x0061736d) {
    return buf;
  }
  const zlib = getZlibSync();
  if (zlib) {
    if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
      try {
        return zlib.gunzipSync(buf);
      } catch {
        // ignore
      }
    }
    try {
      return zlib.unzipSync(buf);
    } catch {
      try {
        return zlib.inflateSync(buf);
      } catch {
        return buf;
      }
    }
  }
  return buf;
}

/**
 * Reads unsigned LEB128 integer from buffer.
 */
function readLeb128(wasm: Buffer, offset: number): { value: number; next: number } | undefined {
  let value = 0;
  let shift = 0;
  let pos = offset;
  while (pos < wasm.length) {
    const byte = wasm[pos] as number;
    value |= (byte & 0x7f) << shift;
    pos++;
    if ((byte & 0x80) === 0) return { value: value >>> 0, next: pos };
    shift += 7;
    if (shift > 28) return undefined;
  }
  return undefined;
}

/**
 * Extracts the raw bytes of a named custom WebAssembly section.
 */
export function getWasmCustomSection(wasm: Buffer, sectionName: string): Buffer | undefined {
  const decompressed = decompressWasm(wasm);
  if (decompressed.length < 8 || decompressed.readUInt32BE(0) !== 0x0061736d) return undefined;

  let pos = 8;
  while (pos < decompressed.length) {
    const id = decompressed[pos] as number;
    const size = readLeb128(decompressed, pos + 1);
    if (size === undefined) return undefined;

    const start = size.next;
    const end = start + size.value;
    if (end > decompressed.length) return undefined;

    if (id === 0) {
      const nameLength = readLeb128(decompressed, start);
      if (nameLength !== undefined) {
        const nameStart = nameLength.next;
        const nameEnd = nameStart + nameLength.value;
        if (nameEnd <= end && decompressed.toString('utf8', nameStart, nameEnd) === sectionName) {
          return decompressed.subarray(nameEnd, end);
        }
      }
    }

    pos = end;
  }
  return undefined;
}

/**
 * Decodes all ScSpecEntry objects from the contractspecv0 custom section.
 */
export function extractContractSpecEntries(wasm: Buffer): xdr.ScSpecEntry[] | undefined {
  const section = getWasmCustomSection(wasm, CONTRACT_SPEC_SECTION);
  if (section === undefined) return undefined;

  try {
    const reader = new cereal.XdrReader(section);
    const entries: xdr.ScSpecEntry[] = [];
    while (!reader.eof) {
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      entries.push(entry);
    }
    return entries;
  } catch {
    return undefined;
  }
}

/**
 * Checks whether an ScSpecTypeDef matches the expected type name.
 */
function typeDefMatches(typeDef: xdr.ScSpecTypeDef | undefined, expectedType: string): boolean {
  if (expectedType === 'void') {
    return typeDef === undefined || typeDef.switch().name === 'scSpecTypeVoid';
  }
  if (!typeDef) return false;
  return typeDef.switch().name === expectedType;
}

/**
 * Verifies SEP-41 conformance of decompressed WASM bytecode.
 */
export function verifySep41Wasm(
  wasm: Buffer,
  contractId: string,
  options: WasmAuditorOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const decompressed = decompressWasm(wasm);

  // 1. Verify custom section exists
  const section = getWasmCustomSection(decompressed, CONTRACT_SPEC_SECTION);
  if (section === undefined) {
    const sev = severityFor(MISSING_CONTRACT_SPEC_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: MISSING_CONTRACT_SPEC_RULE,
        severity: sev,
        category: 'network',
        message: `Contract ${contractId} WASM is missing custom section "${CONTRACT_SPEC_SECTION}"`,
        ...(options.path ? { path: options.path } : {}),
        helpUri: SEP41_SPEC_URL,
        suggestion:
          'Compile the Soroban smart contract with contract specs enabled so interface metadata is exported.',
      });
    }
    return diagnostics;
  }

  // 2. Extract spec entries
  const entries = extractContractSpecEntries(decompressed);
  if (entries === undefined) {
    const sev = severityFor(MISSING_CONTRACT_SPEC_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: MISSING_CONTRACT_SPEC_RULE,
        severity: sev,
        category: 'network',
        message: `Contract ${contractId} has malformed or unparseable "${CONTRACT_SPEC_SECTION}" section`,
        ...(options.path ? { path: options.path } : {}),
        helpUri: SEP41_SPEC_URL,
        suggestion:
          'Ensure the contractspecv0 custom section contains valid XDR-encoded ScSpecEntry elements.',
      });
    }
    return diagnostics;
  }

  const specFunctions = new Map<string, xdr.ScSpecFunctionV0>();
  for (const entry of entries) {
    if (entry.switch().name === 'scSpecEntryFunctionV0') {
      const fn = entry.functionV0();
      specFunctions.set(fn.name().toString(), fn);
    }
  }

  // 3. Verify all 11 mandatory SEP-41 functions
  for (const [fnName, expected] of Object.entries(SEP41_MANDATORY_FUNCTIONS)) {
    const fn = specFunctions.get(fnName);
    if (!fn) {
      const sev = severityFor(MISSING_SEP41_FUNCTION_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: MISSING_SEP41_FUNCTION_RULE,
          severity: sev,
          category: 'network',
          message: `Contract ${contractId} does not export mandatory SEP-41 function "${fnName}"`,
          ...(options.path ? { path: options.path } : {}),
          helpUri: SEP41_SPEC_URL,
          suggestion: `Implement the "${fnName}" function conforming to the SEP-41 Token Interface.`,
        });
      }
      continue;
    }

    // 4. Validate parameter counts and argument types
    const inputs = fn.inputs();
    let signatureValid = true;
    let signatureErrorReason = '';

    if (inputs.length !== expected.inputs.length) {
      signatureValid = false;
      signatureErrorReason = `expected ${expected.inputs.length} parameter(s) but found ${inputs.length}`;
    } else {
      for (let i = 0; i < expected.inputs.length; i++) {
        const input = inputs[i]!;
        const expInput = expected.inputs[i]!;
        if (!typeDefMatches(input.type(), expInput.type)) {
          signatureValid = false;
          signatureErrorReason = `parameter ${i + 1} ("${input.name().toString()}") is type "${input.type().switch().name}", expected "${expInput.type}"`;
          break;
        }
      }
    }

    // 5. Validate return type
    if (signatureValid) {
      const outputs = fn.outputs();
      const outputType = outputs.length > 0 ? outputs[0] : undefined;
      if (!typeDefMatches(outputType, expected.output)) {
        signatureValid = false;
        signatureErrorReason = `return type is "${outputType ? outputType.switch().name : 'void'}", expected "${expected.output}"`;
      }
    }

    if (!signatureValid) {
      const sev = severityFor(INVALID_SEP41_SIGNATURE_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_SEP41_SIGNATURE_RULE,
          severity: sev,
          category: 'network',
          message: `Contract ${contractId} function "${fnName}" has invalid SEP-41 signature: ${signatureErrorReason}`,
          ...(options.path ? { path: options.path } : {}),
          helpUri: SEP41_SPEC_URL,
          suggestion: `Align the signature of "${fnName}" with the SEP-41 specification.`,
        });
      }
    }
  }

  return diagnostics;
}

/**
 * Builds ledger key for contract instance.
 */
function contractDataInstanceKey(contractId: string): string {
  const key = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  return key.toXDR('base64');
}

/**
 * Builds ledger key for contract code WASM blob.
 */
function contractCodeKey(wasmHash: Buffer): string {
  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: wasmHash }));
  return key.toXDR('base64');
}

/**
 * Queries one ledger entry from Soroban RPC.
 */
async function queryLedgerEntry(
  rpcUrl: string,
  key: string,
  fetchImpl: typeof fetch,
): Promise<string | undefined> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getLedgerEntries',
        params: { keys: [key] },
      }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) return undefined;

    const body = (await response.json()) as {
      result?: { entries?: Array<{ xdr?: string }> };
    };
    const entry = body.result?.entries?.[0];
    return typeof entry?.xdr === 'string' ? entry.xdr : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Audits a single contract by ID on the Soroban RPC for SEP-41 token conformance.
 */
export async function auditContractWasm(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: WasmAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  let instanceEntryXdr: string | undefined;
  try {
    instanceEntryXdr = await queryLedgerEntry(
      rpcUrl,
      contractDataInstanceKey(contractId),
      fetchImpl,
    );
  } catch {
    // network failure handled below
  }

  if (!instanceEntryXdr) {
    const sev = severityFor(WASM_NOT_FOUND_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: WASM_NOT_FOUND_RULE,
        severity: sev,
        category: 'network',
        message: `Contract ${contractId} instance could not be found on Soroban network`,
        ...(options.path ? { path: options.path } : {}),
        helpUri: SEP41_SPEC_URL,
        suggestion: 'Verify that the contract is deployed on the target Soroban network.',
      });
    }
    return diagnostics;
  }

  let wasmHash: Buffer | undefined;
  let isStellarAsset = false;
  try {
    const data = xdr.LedgerEntryData.fromXDR(instanceEntryXdr, 'base64');
    const val = data.contractData().val();
    if (val.switch().name === 'scvContractInstance') {
      const exec = val.instance().executable();
      if (exec.switch().name === 'contractExecutableWasm') {
        wasmHash = Buffer.from(exec.wasmHash());
      } else if (exec.switch().name === 'contractExecutableStellarAsset') {
        isStellarAsset = true;
      }
    }
  } catch {
    // Malformed ledger entry
  }

  // Stellar Asset Contracts (SAC) implement SEP-41 natively on-chain
  if (isStellarAsset) {
    return [];
  }

  if (!wasmHash) {
    const sev = severityFor(WASM_NOT_FOUND_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: WASM_NOT_FOUND_RULE,
        severity: sev,
        category: 'network',
        message: `Contract ${contractId} does not reference a valid WASM executable`,
        ...(options.path ? { path: options.path } : {}),
        helpUri: SEP41_SPEC_URL,
        suggestion: 'Ensure the contract is deployed with valid WebAssembly bytecode.',
      });
    }
    return diagnostics;
  }

  const codeEntryXdr = await queryLedgerEntry(rpcUrl, contractCodeKey(wasmHash), fetchImpl);
  if (!codeEntryXdr) {
    const sev = severityFor(WASM_NOT_FOUND_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: WASM_NOT_FOUND_RULE,
        severity: sev,
        category: 'network',
        message: `WASM bytecode for contract ${contractId} could not be retrieved from Soroban RPC`,
        ...(options.path ? { path: options.path } : {}),
        helpUri: SEP41_SPEC_URL,
        suggestion:
          'Restore the contract code on the network or verify the contract WASM is not archived.',
      });
    }
    return diagnostics;
  }

  let wasmBytes: Buffer | undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(codeEntryXdr, 'base64');
    if (data.switch().name === 'contractCode') {
      wasmBytes = Buffer.from(data.contractCode().code());
    }
  } catch {
    // Malformed code entry
  }

  if (!wasmBytes) {
    const sev = severityFor(WASM_NOT_FOUND_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: WASM_NOT_FOUND_RULE,
        severity: sev,
        category: 'network',
        message: `Could not parse WASM bytecode for contract ${contractId}`,
        ...(options.path ? { path: options.path } : {}),
        helpUri: SEP41_SPEC_URL,
        suggestion: 'Verify that the contract WASM entry on the ledger contains valid binary code.',
      });
    }
    return diagnostics;
  }

  return verifySep41Wasm(wasmBytes, contractId, options);
}

/**
 * Audits all Soroban smart contract tokens declared in stellar.toml for SEP-41 conformance.
 */
export async function auditTomlContractWasm(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: WasmAuditorOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (!rpcUrl) return [];

  const currencies = contractCurrenciesOf(doc);
  const diagnostics: Diagnostic[] = [];

  // Check currency contracts for SEP-41 Token interface conformance
  for (const currency of currencies) {
    diagnostics.push(
      ...(await auditContractWasm(currency.id, rpcUrl, fetchImpl, {
        ...options,
        path: currency.path,
      })),
    );
  }

  // Also check [[CONTRACTS]] if present in the document
  if (Array.isArray(doc.CONTRACTS)) {
    for (const [index, contractEntry] of doc.CONTRACTS.entries()) {
      if (typeof contractEntry === 'object' && contractEntry !== null) {
        const entry = contractEntry as Record<string, unknown>;
        const id =
          typeof entry.id === 'string'
            ? entry.id
            : typeof entry.contract === 'string'
              ? entry.contract
              : undefined;
        if (id && isString(id) && id.startsWith('C') && id.length === 56) {
          if (!currencies.some((c) => c.id === id)) {
            diagnostics.push(
              ...(await auditContractWasm(id, rpcUrl, fetchImpl, {
                ...options,
                path: `CONTRACTS[${index}]`,
              })),
            );
          }
        }
      }
    }
  }

  return diagnostics;
}

/** Registered rules for Soroban WASM auditor */
export const wasmAuditorRules: Rule[] = [
  {
    id: WASM_NOT_FOUND_RULE,
    category: 'network',
    severity: 'error',
    description: 'Soroban contract WASM bytecode could not be found or retrieved from the network',
    run() {},
  },
  {
    id: MISSING_CONTRACT_SPEC_RULE,
    category: 'network',
    severity: 'error',
    description: 'Soroban contract WASM bytecode is missing the contractspecv0 custom section',
    run() {},
  },
  {
    id: MISSING_SEP41_FUNCTION_RULE,
    category: 'network',
    severity: 'error',
    description: 'Soroban token contract is missing a mandatory SEP-41 interface function',
    run() {},
  },
  {
    id: INVALID_SEP41_SIGNATURE_RULE,
    category: 'network',
    severity: 'error',
    description:
      'Soroban token contract has an invalid parameter count, type, or return type for a SEP-41 function',
    run() {},
  },
];

export const wasmAuditorRuleIds: readonly string[] = wasmAuditorRules.map((rule) => rule.id);
