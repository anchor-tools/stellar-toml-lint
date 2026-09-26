/**
 * Opt-in on-chain verification of the Soroban contracts a file declares.
 *
 * A well-formed `C...` address says nothing about whether a contract was ever
 * deployed there. This audit queries the Soroban RPC's `getLedgerEntries` for
 * each contract instance and the WASM it points at: a missing instance means
 * the contract does not exist, a missing WASM means its code was archived or
 * evicted. Both live on the ledger only until their TTL expires, so each
 * `liveUntilLedgerSeq` is also compared against the network's `latestLedger`
 * and a renewal that is due is reported. For currency contracts, the SEP-41
 * metadata in the instance storage is compared against the currency entry. Like the other network-bound checks it only runs under an
 * explicit flag (`--check-contracts`), never fails the run on an RPC outage,
 * and registers rule objects so `--list-rules` and `--off` know its ids.
 */
import { Address, cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from './types.js';
import { isString } from './predicates.js';
import { rpcUrlFor } from './rules/display-decimals-audit.js';
import {
  contractCurrenciesOf,
  sep41MetadataDiagnostics,
  type Sep41Metadata,
} from './rules/currencies.js';
import { webAuthContractIdOf } from './rules/general.js';

/** Roughly a day of ledgers at ~5 seconds per ledger. */
const EXPIRING_WINDOW_LEDGERS = 17_280;

const TTL_EXPIRING_RULE = 'soroban/contract-ttl-expiring-soon';
const CONTRACT_EXPIRED_RULE = 'soroban/contract-expired';
const TTL_UNAVAILABLE_RULE = 'soroban/contract-ttl-unavailable';
const NOT_FOUND_RULE = 'soroban/contract-not-found';
const EVICTED_RULE = 'soroban/contract-evicted';
const AUTH_CONTRACT_INTERFACE_RULE = 'soroban/invalid-auth-contract-interface';

/**
 * The function every SEP-45 web auth contract must export. SEP-45 requires the
 * contract at `WEB_AUTH_CONTRACT_ID` to implement `web_auth_verify`, which calls
 * `require_auth` on the client and server accounts; a contract that lacks it
 * cannot complete a single challenge.
 */
const SEP45_AUTH_FUNCTION = 'web_auth_verify';

/** The WASM custom section Soroban stores a contract's spec entries in. */
const CONTRACT_SPEC_SECTION = 'contractspecv0';

/**
 * How long one RPC request may take. A hung endpoint must not stall the lint
 * run; a request that times out is treated like any other outage.
 */
const RPC_TIMEOUT_MS = 10_000;

interface ContractTtlOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
}

interface ContractAuditOptions extends ContractTtlOptions {
  rpcUrl?: string;
}

/** A contract to audit, with the file path that named it. */
interface ContractTarget {
  id: string;
  path: string;
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

/**
 * The ledger key of a contract's instance entry. A contract instance is a
 * single key in the `ContractData` table with the special
 * `ledgerKeyContractInstance` scval as its key.
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

/** The ledger key of the WASM blob a contract instance points at. */
function contractCodeKey(wasmHash: Buffer): string {
  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: wasmHash }));
  return key.toXDR('base64');
}

/**
 * The WASM hash referenced by a contract's instance entry, or `undefined`
 * when the entry does not describe a contract executable as WASM.
 */
function wasmHashOf(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const contractData = data.contractData();
    const val = contractData.val();
    if (val.switch().name !== 'scvContractInstance') return undefined;
    const executable = val.instance().executable();
    if (executable.switch().name !== 'contractExecutableWasm') return undefined;
    return Buffer.from(executable.wasmHash());
  } catch {
    return undefined;
  }
}

/**
 * The WASM bytes carried by a contract-code entry, or `undefined` when the
 * entry is not the contract code at all.
 */
function wasmBytesOf(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    if (data.switch().name !== 'contractCode') return undefined;
    return Buffer.from(data.contractCode().code());
  } catch {
    return undefined;
  }
}

/**
 * Reads an unsigned LEB128 integer, the encoding WASM uses for section ids,
 * sizes, and name lengths. `undefined` means the bytes ran out or the value
 * was not a well-formed 32-bit integer.
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
 * The payload of the named WASM custom section, or `undefined` when the module
 * is malformed or the section is absent.
 *
 * A WASM module is a fixed header followed by length-prefixed sections; a
 * custom section (id 0) carries its name before the payload. Soroban stores a
 * contract's interface in the `contractspecv0` custom section, so this is how
 * the exported functions are read without executing anything.
 */
export function wasmCustomSection(wasm: Buffer, name: string): Buffer | undefined {
  // Magic `\0asm` plus a 4-byte version. Anything shorter is not a module.
  if (wasm.length < 8 || wasm.readUInt32BE(0) !== 0x0061736d) return undefined;

  let pos = 8;
  while (pos < wasm.length) {
    const id = wasm[pos] as number;
    const size = readLeb128(wasm, pos + 1);
    if (size === undefined) return undefined;

    const start = size.next;
    const end = start + size.value;
    if (end > wasm.length) return undefined;

    if (id === 0) {
      const nameLength = readLeb128(wasm, start);
      if (nameLength !== undefined) {
        const nameStart = nameLength.next;
        const nameEnd = nameStart + nameLength.value;
        if (nameEnd <= end && wasm.toString('utf8', nameStart, nameEnd) === name) {
          return wasm.subarray(nameEnd, end);
        }
      }
    }

    pos = end;
  }
  return undefined;
}

/**
 * The function names a contract's spec declares, or `undefined` when the module
 * has no readable spec section. The section holds a stream of `ScSpecEntry`
 * XDR values, one per exported function, struct, enum, or event.
 */
export function specFunctionNames(wasm: Buffer): string[] | undefined {
  const section = wasmCustomSection(wasm, CONTRACT_SPEC_SECTION);
  if (section === undefined) return undefined;

  try {
    const reader = new cereal.XdrReader(section);
    const names: string[] = [];
    while (!reader.eof) {
      // The published types still describe `read` as taking a Buffer, but the
      // runtime consumes the same cursor `fromXDR` builds internally.
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      if (entry.switch().name !== 'scSpecEntryFunctionV0') continue;
      names.push(entry.functionV0().name().toString());
    }
    return names;
  } catch {
    return undefined;
  }
}

interface LedgerEntryResult {
  /** The network's current ledger when the RPC answered. */
  latestLedger: number;
  /** `liveUntilLedgerSeq` of the looked-up entry, or `undefined` when absent. */
  liveUntil: number | undefined;
  /** The entry's raw `xdr`, so callers can inspect what it is. */
  entryXdr: unknown;
}

/**
 * GETs one entry by ledger key. `undefined` means the RPC could not answer
 * (unreachable, non-200, malformed JSON) — never throws. An empty `entries`
 * result is a valid answer that simply has no entry, and surfaces as
 * `liveUntil === undefined`.
 */
async function queryLedgerEntry(
  rpcUrl: string,
  key: string,
  fetchImpl: typeof fetch,
): Promise<LedgerEntryResult | undefined> {
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
      result?: { latestLedger?: unknown; entries?: unknown };
    };
    const result = body.result;
    if (typeof result !== 'object' || result === null) return undefined;

    const latestLedger = Number(result.latestLedger);
    if (!Number.isInteger(latestLedger)) return undefined;

    const entries = Array.isArray(result.entries) ? result.entries : [];
    const entry = entries.find(
      (e): e is Record<string, unknown> => typeof e === 'object' && e !== null,
    );
    const liveUntil = Number(entry?.liveUntilLedgerSeq);
    return {
      latestLedger,
      liveUntil: Number.isInteger(liveUntil) ? liveUntil : undefined,
      entryXdr: entry?.xdr,
    };
  } catch {
    return undefined;
  }
}

/**
 * What the ledger holds for one contract. `unavailable` means the RPC could
 * not answer; `not-found` and `evicted` are answers, and bad ones.
 */
type ContractLookup =
  | { kind: 'unavailable'; detail: string }
  | { kind: 'not-found' }
  | { kind: 'evicted' }
  | { kind: 'live'; instance: LedgerEntryResult; code: LedgerEntryResult | undefined };

/**
 * Reads a contract's instance entry and, when it runs WASM, the code entry the
 * instance points at. A Stellar Asset Contract has no WASM, so `code` is
 * `undefined` for it.
 */
async function lookupContract(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch,
): Promise<ContractLookup> {
  const instance = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  if (instance === undefined) {
    return { kind: 'unavailable', detail: 'could not be verified against the Soroban RPC' };
  }
  if (instance.liveUntil === undefined) return { kind: 'not-found' };

  const wasmHash = wasmHashOf(instance.entryXdr);
  if (wasmHash === undefined) return { kind: 'live', instance, code: undefined };

  const code = await queryLedgerEntry(rpcUrl, contractCodeKey(wasmHash), fetchImpl);
  if (code === undefined) {
    return { kind: 'unavailable', detail: 'WASM could not be verified against the Soroban RPC' };
  }
  if (code.liveUntil === undefined) return { kind: 'evicted' };
  return { kind: 'live', instance, code };
}

/** A diagnostic factory bound to one contract and the caller's overrides. */
function contractFinding(
  contractId: string,
  options: ContractTtlOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  suggestion?: string,
) => Diagnostic[] {
  return (rule, fallback, detail, suggestion) => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${detail}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/** The diagnostics for a lookup that did not find a live contract. */
function lookupFindings(
  contractId: string,
  lookup: Exclude<ContractLookup, { kind: 'live' }>,
  options: ContractTtlOptions,
): Diagnostic[] {
  const finding = contractFinding(contractId, options);
  switch (lookup.kind) {
    case 'unavailable':
      return finding(TTL_UNAVAILABLE_RULE, 'warning', lookup.detail);
    case 'not-found':
      return finding(
        NOT_FOUND_RULE,
        'error',
        'has no instance entry on the ledger, so it was never deployed or has been archived',
        'Deploy the contract to this network, or correct the contract ID.',
      );
    case 'evicted':
      return finding(
        EVICTED_RULE,
        'error',
        'points at WASM that has been archived or evicted from the ledger',
        'Restore the contract code with a RestoreFootprint operation, then extend its TTL.',
      );
  }
}

/**
 * Verifies that one contract is deployed and invocable: its instance entry
 * exists (`soroban/contract-not-found` otherwise) and, for a WASM contract,
 * the code it points at is still on the ledger (`soroban/contract-evicted`
 * otherwise). An RPC outage or timeout is a warning, never a thrown error.
 */
export async function verifyContractOnChain(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: ContractTtlOptions = {},
): Promise<Diagnostic[]> {
  const lookup = await lookupContract(contractId, rpcUrl, fetchImpl);
  return lookup.kind === 'live' ? [] : lookupFindings(contractId, lookup, options);
}

/**
 * Verifies that one contract exists on chain and that its TTL, and its
 * WASM's, is not about to run out.
 *
 * The effective expiry is the earlier of the instance's and the WASM's,
 * compared against `latestLedger`. Diagnoses nothing while the TTL is
 * comfortably ahead, warns as renewal nears (~24h), and errors once expired.
 */
export async function checkContractTtl(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: ContractTtlOptions = {},
): Promise<Diagnostic[]> {
  const lookup = await lookupContract(contractId, rpcUrl, fetchImpl);
  if (lookup.kind !== 'live') return lookupFindings(contractId, lookup, options);

  const finding = contractFinding(contractId, options);
  const { instance, code } = lookup;
  const liveUntil = Math.min(
    instance.liveUntil as number,
    code?.liveUntil ?? Number.POSITIVE_INFINITY,
  );

  const remaining = liveUntil - instance.latestLedger;
  if (remaining <= 0) {
    return finding(
      CONTRACT_EXPIRED_RULE,
      'error',
      `has expired ${-remaining} ledgers ago and may have been archived`,
    );
  }
  if (remaining <= EXPIRING_WINDOW_LEDGERS) {
    return finding(
      TTL_EXPIRING_RULE,
      'warning',
      `expires in ${remaining} ledgers; renew the TTL before it does`,
    );
  }
  return [];
}

/** The instance storage key the SEP-41 token SDK keeps metadata under. */
const METADATA_KEY = 'METADATA';

/** A string-like ScVal as a JS string, or `undefined` for anything else. */
function scString(val: xdr.ScVal): string | undefined {
  switch (val.switch().name) {
    case 'scvString':
    case 'scvSymbol':
      return val.value()!.toString();
    default:
      return undefined;
  }
}

/** Reads `decimal`, `name`, and `symbol` out of an ScMap's entries. */
function metadataFields(entries: xdr.ScMapEntry[]): Omit<Sep41Metadata, 'stellarAsset'> {
  const fields: Omit<Sep41Metadata, 'stellarAsset'> = {};
  for (const entry of entries) {
    const key = scString(entry.key());
    const val = entry.val();
    if (key === 'decimal' && val.switch().name === 'scvU32') fields.decimal = val.u32();
    if (key === 'name') fields.name = scString(val);
    if (key === 'symbol') fields.symbol = scString(val);
  }
  return fields;
}

/**
 * The SEP-41 metadata stored in a contract instance entry, or `undefined`
 * when the entry is not a contract instance or stores no metadata.
 *
 * The token SDK (and so the reference token and the Stellar Asset Contract)
 * keeps a `METADATA` map of `{ decimal, name, symbol }` in instance storage;
 * a contract that stores the three fields at the top level is read too.
 */
export function sep41MetadataOf(entryXdr: unknown): Sep41Metadata | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    if (data.switch().name !== 'contractData') return undefined;
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return undefined;

    const instance = val.instance();
    const storage = instance.storage() ?? [];
    const nested = storage.find(
      (entry) => scString(entry.key()) === METADATA_KEY && entry.val().switch().name === 'scvMap',
    );
    const fields = metadataFields(nested ? (nested.val().map() ?? []) : storage);
    if (Object.keys(fields).length === 0) return undefined;

    const stellarAsset = instance.executable().switch().name === 'contractExecutableStellarAsset';
    return { ...fields, stellarAsset };
  } catch {
    return undefined;
  }
}

/**
 * Reads the SEP-41 `symbol`, `name`, and `decimal` a token contract stores in
 * its instance storage. `undefined` means the metadata could not be read — the
 * RPC was unreachable, the contract is absent, or it stores no metadata — and
 * is never an error by itself.
 */
export async function fetchSep41Metadata(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Sep41Metadata | undefined> {
  const instance = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  return sep41MetadataOf(instance?.entryXdr);
}

/**
 * Verifies that the contract at `WEB_AUTH_CONTRACT_ID` exports the SEP-45
 * `web_auth_verify` function.
 *
 * SEP-45 needs more than a well-formed `C...` address: the deployed contract
 * has to implement one specific interface. The contract instance names its
 * WASM, the WASM carries the interface in its custom section, and a contract
 * whose spec has functions but not `web_auth_verify` cannot complete a SEP-45
 * challenge — so a wallet that trusts the file would fail at authentication.
 *
 * Stays silent whenever the answer cannot be read: an RPC outage, a missing or
 * archived entry, a native-asset executable, or an unparseable spec is not a
 * finding, and a false error on a healthy contract is worse than a missed one.
 * Only a spec that parses, declares functions, and omits `web_auth_verify`
 * earns the diagnostic.
 */
export async function verifySep45ContractInterface(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: ContractTtlOptions = {},
): Promise<Diagnostic[]> {
  const severity = severityFor(AUTH_CONTRACT_INTERFACE_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  const lookup = await lookupContract(contractId, rpcUrl, fetchImpl);
  if (lookup.kind !== 'live' || lookup.code === undefined) return [];

  const wasm = wasmBytesOf(lookup.code.entryXdr);
  if (wasm === undefined) return [];

  const functions = specFunctionNames(wasm);
  if (functions === undefined || functions.length === 0) return [];
  if (functions.includes(SEP45_AUTH_FUNCTION)) return [];

  return [
    {
      rule: AUTH_CONTRACT_INTERFACE_RULE,
      severity,
      category: 'network',
      message: `Contract ${contractId} does not export the SEP-45 ${SEP45_AUTH_FUNCTION} function`,
      path: 'WEB_AUTH_CONTRACT_ID',
      helpUri:
        'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md#web-authentication-contract',
      suggestion: `Deploy a SEP-45 web auth contract that exports ${SEP45_AUTH_FUNCTION}, or remove WEB_AUTH_CONTRACT_ID.`,
    },
  ];
}

/**
 * Audits every contract the file declares — `[[CURRENCIES]].contract` and
 * `WEB_AUTH_CONTRACT_ID` — against Soroban. Silent when the network is
 * unknown (no RPC URL can be derived) unless `options.rpcUrl` is given.
 */
export async function checkContracts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ContractAuditOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (!rpcUrl) return [];

  const authContract = webAuthContractIdOf(doc);
  const currencies = contractCurrenciesOf(doc);
  const targets: ContractTarget[] = [
    ...currencies.map(({ id, path }) => ({ id, path })),
    ...(authContract !== undefined ? [authContract] : []),
  ];
  if (targets.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  for (const target of targets) {
    diagnostics.push(
      ...(await checkContractTtl(target.id, rpcUrl, fetchImpl, { ...options, path: target.path })),
    );
  }

  // A token contract's SEP-41 metadata is what wallets display and compute
  // with, so the currency entry describing it has to agree.
  for (const currency of currencies) {
    const metadata = await fetchSep41Metadata(currency.id, rpcUrl, fetchImpl);
    if (metadata !== undefined) {
      diagnostics.push(...sep41MetadataDiagnostics(currency, metadata, options.rules));
    }
  }

  // The auth contract has one extra obligation beyond liveliness: the SEP-45
  // interface. Checked once for the single WEB_AUTH_CONTRACT_ID.
  if (authContract !== undefined) {
    diagnostics.push(
      ...(await verifySep45ContractInterface(authContract.id, rpcUrl, fetchImpl, options)),
    );
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sorobanRules: Rule[] = [
  {
    id: TTL_EXPIRING_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract or its WASM is within ~a day of its TTL expiring',
    run() {},
  },
  {
    id: CONTRACT_EXPIRED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract or its WASM has expired or been archived on the network',
    run() {},
  },
  {
    id: TTL_UNAVAILABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract TTL could not be verified against the Soroban RPC',
    run() {},
  },
  {
    id: NOT_FOUND_RULE,
    category: 'network',
    severity: 'error',
    description: 'A declared Soroban contract has no instance entry on the ledger',
    run() {},
  },
  {
    id: EVICTED_RULE,
    category: 'network',
    severity: 'error',
    description: "A declared Soroban contract's WASM has been archived or evicted",
    run() {},
  },
  {
    id: AUTH_CONTRACT_INTERFACE_RULE,
    category: 'network',
    severity: 'error',
    description: 'WEB_AUTH_CONTRACT_ID must export the SEP-45 web_auth_verify function',
    run() {},
  },
];

/** Rule ids emitted by {@link checkContracts}. */
export const sorobanRuleIds: readonly string[] = sorobanRules.map((rule) => rule.id);
