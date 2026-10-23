import type { Diagnostic, Rule } from '../types.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { webAuthContractIdOf } from '../rules/general.js';
import { fetchContractWasm } from './rpc.js';
import {
  DEFAULT_PROTOCOL_VERSION,
  DEPRECATED_COMPILER_RULE,
  ENV_META_SECTION,
  MALFORMED_ENVMETA_RULE,
  MISSING_ENV_META_RULE,
  extractEnvMeta,
  extractEnvMetaEntries,
  verifyEnvMeta,
  type ContractEnvMeta,
  type EnvMetaExtraction,
  type EnvMetaOptions,
} from './envmeta-extractor.js';

export {
  DEFAULT_PROTOCOL_VERSION,
  DEPRECATED_COMPILER_RULE,
  ENV_META_SECTION,
  MALFORMED_ENVMETA_RULE,
  MISSING_ENV_META_RULE,
  extractEnvMeta,
  extractEnvMetaEntries,
  verifyEnvMeta,
};
export type { ContractEnvMeta, EnvMetaExtraction, EnvMetaOptions };

export const DEPRECATED_PROTOCOL_RULE = DEPRECATED_COMPILER_RULE;

export async function auditContractEnvMeta(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: EnvMetaOptions = {},
): Promise<Diagnostic[]> {
  const wasm = await fetchContractWasm(contractId, rpcUrl, fetchImpl);
  if (wasm === undefined) return [];
  return verifyEnvMeta(wasm, contractId, options);
}

export async function auditTomlContractEnvMeta(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: EnvMetaOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (!rpcUrl) return [];

  const targets = new Map<string, string>();
  for (const currency of contractCurrenciesOf(doc)) targets.set(currency.id, currency.path);
  const auth = webAuthContractIdOf(doc);
  if (auth !== undefined) targets.set(auth.id, auth.path);

  const diagnostics: Diagnostic[] = [];
  for (const [id, path] of targets) {
    diagnostics.push(...(await auditContractEnvMeta(id, rpcUrl, fetchImpl, { ...options, path })));
  }
  return diagnostics;
}

export const envMetaRules: Rule[] = [
  {
    id: MISSING_ENV_META_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract does not embed contractenvmetav0 environment metadata',
    run() {},
  },
  {
    id: DEPRECATED_COMPILER_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract was compiled against a deprecated protocol version',
    run() {},
  },
  {
    id: MALFORMED_ENVMETA_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract has a malformed contractenvmetav0 XDR section',
    run() {},
  },
];

export const envMetaRuleIds: readonly string[] = envMetaRules.map((rule) => rule.id);
