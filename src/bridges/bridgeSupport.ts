/**
 * Shared parsing for `[[BRIDGES]]` tables used by the bridge auditors.
 */

import { isContractId } from '../predicates.js';
import { isRecord } from '../protocols/verifierSupport.js';

export type BridgeChain = 'soroban' | 'evm' | 'solana';

export interface BridgeDecl {
  index: number;
  name: string;
  chain: BridgeChain | undefined;
  contract: unknown;
  raw: Record<string, unknown>;
}

export function bridgesOf(doc: Record<string, unknown>): BridgeDecl[] {
  const list = doc.BRIDGES;
  if (!Array.isArray(list)) return [];
  const out: BridgeDecl[] = [];
  list.forEach((raw, index) => {
    if (!isRecord(raw)) return;
    const chain = typeof raw.CHAIN === 'string' ? raw.CHAIN.toLowerCase() : '';
    out.push({
      index,
      name: typeof raw.NAME === 'string' && raw.NAME !== '' ? raw.NAME : `bridge #${index + 1}`,
      chain: chain === 'soroban' || chain === 'evm' || chain === 'solana' ? chain : undefined,
      contract: raw.CONTRACT,
      raw,
    });
  });
  return out;
}

/** Address format check per chain: C... strkey, 0x + 40 hex, or a base58 public key. */
export function isValidBridgeContract(chain: BridgeChain, contract: unknown): boolean {
  if (typeof contract !== 'string') return false;
  if (chain === 'soroban') return isContractId(contract);
  if (chain === 'evm') return /^0x[0-9a-fA-F]{40}$/.test(contract);
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contract);
}
