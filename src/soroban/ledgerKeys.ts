/**
 * Ledger-key helpers shared by the Soroban contract audits.
 *
 * These live in their own module so a validator can build keys without
 * importing the aggregate `soroban.ts` registry, which itself imports the
 * validators. That import cycle is harmless at call time but breaks when a
 * consumer loads a validator before the registry.
 */
import { Address, xdr } from '@stellar/stellar-base';
import { isString } from '../predicates.js';

/**
 * The ledger key of a contract's instance entry. A contract instance is a
 * single key in the `ContractData` table with the special
 * `ledgerKeyContractInstance` scval as its key.
 */
export function contractDataInstanceKey(contractId: string): string {
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
export function contractCodeKey(wasmHash: Buffer): string {
  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: wasmHash }));
  return key.toXDR('base64');
}

/**
 * The WASM hash referenced by a contract's instance entry, or `undefined`
 * when the entry does not describe a contract executable as WASM.
 */
export function wasmHashOf(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const contractData = data.contractData();
    const val = contractData.val();
    if (val.switch().name !== 'scvContractInstance') return undefined;
    const instance = val.instance();
    if (instance === null) return undefined;
    const executable = instance.executable();
    if (executable.switch().name !== 'contractExecutableWasm') return undefined;
    return Buffer.from(executable.wasmHash());
  } catch {
    return undefined;
  }
}
