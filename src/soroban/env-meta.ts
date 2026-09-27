/**
 * Soroban contract metadata (`contractenvmetav0`) extractor and validator.
 *
 * Contracts compiled with the official Rust SDK embed a
 * `contractenvmetav0` WebAssembly custom section describing the environment
 * they were built against: the Soroban protocol version, the SDK version, and
 * the interface version. A contract compiled against an old protocol can be
 * deployed and invoked successfully while missing newer host functions and
 * diagnostics — the failure surfaces later, at run time, instead of at review.
 *
 * This audit reads the section, decodes the `SCEnvMetaEntry` XDR stream, and
 * compares the declared interface (`protocol`) version against the version the
 * target network is running. It runs under the opt-in `--check-network` flag
 * like the other on-chain audits, never throws on an RPC outage, and registers
 * rule objects so `--list-rules` and `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/missing-env-meta` (warning)
 * - `soroban/deprecated-protocol-version` (error)
 */
import { cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { getWasmCustomSection } from './wasm-auditor.js';
import { fetchContractWasm, severityFor } from './rpc.js';

/** The WASM custom section the Soroban Rust SDK embeds environment metadata in. */
export const ENV_META_SECTION = 'contractenvmetav0';

export const MISSING_ENV_META_RULE = 'soroban/missing-env-meta';
export const DEPRECATED_PROTOCOL_RULE = 'soroban/deprecated-protocol-version';

/**
 * The protocol version this linter treats as the active network default when
 * the caller does not supply one. Soroban's own protocol versioning moves with
 * each network upgrade; pass {@link EnvMetaOptions.protocolVersion} to pin the
 * comparison to a specific release.
 */
export const DEFAULT_PROTOCOL_VERSION = 22;

export interface EnvMetaOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** The network protocol version to compare against. */
  protocolVersion?: number;
}

/** The protocol and pre-release versions a contract was compiled against. */
export interface ContractEnvMeta {
  protocol: number;
  preRelease: number;
}

/**
 * Decodes the `SCEnvMetaEntry` XDR stream from the `contractenvmetav0` custom
 * section, or `undefined` when the module is malformed or the section is
 * absent. Only the `interfaceVersion` entry is meaningful today; anything else
 * is ignored.
 */
export function extractEnvMeta(wasm: Buffer): ContractEnvMeta | undefined {
  const section = getWasmCustomSection(wasm, ENV_META_SECTION);
  if (section === undefined) return undefined;

  try {
    const reader = new cereal.XdrReader(section);
    while (!reader.eof) {
      // Published types describe `read` as taking a Buffer, but the runtime
      // consumes the cursor a cereal reader already is.
      const entry = xdr.ScEnvMetaEntry.read(reader as unknown as Buffer);
      if (entry.switch().name === 'scEnvMetaKindInterfaceVersion') {
        const version = entry.interfaceVersion();
        return { protocol: version.protocol(), preRelease: version.preRelease() };
      }
    }
    return undefined;
  } catch {
    return undefined;
  }
}

function envMetaFinding(
  contractId: string,
  options: EnvMetaOptions,
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

/**
 * Verifies the environment metadata a contract's WASM declares.
 *
 * A module with no `contractenvmetav0` section warns (`missing-env-meta`): the
 * contract cannot be matched to a protocol version, so its compatibility is
 * unknown. A contract declaring an interface older than the network's protocol
 * errors (`deprecated-protocol-version`) — it was compiled against host
 * functions that may no longer behave the same way.
 */
export function verifyEnvMeta(
  wasm: Buffer,
  contractId: string,
  options: EnvMetaOptions = {},
): Diagnostic[] {
  const finding = envMetaFinding(contractId, options);
  const meta = extractEnvMeta(wasm);
  if (meta === undefined) {
    return finding(
      MISSING_ENV_META_RULE,
      'warning',
      `WASM has no "${ENV_META_SECTION}" custom section, so its protocol version is unknown`,
      'Build the contract with the official Soroban Rust SDK so environment metadata is embedded.',
    );
  }

  const active = options.protocolVersion ?? DEFAULT_PROTOCOL_VERSION;
  if (meta.protocol < active) {
    return finding(
      DEPRECATED_PROTOCOL_RULE,
      'error',
      `was compiled against Soroban protocol ${meta.protocol}, but the network runs protocol ${active}`,
      `Rebuild and redeploy the contract with an SDK targeting protocol ${active}.`,
    );
  }
  return [];
}

/**
 * Fetches one contract's WASM and verifies its environment metadata. Stays
 * silent when the contract or its WASM cannot be read, so an RPC outage or an
 * archived contract is not misreported as a metadata fault.
 */
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

/**
 * Audits the environment metadata of every contract the file declares under
 * `[[CURRENCIES]]`. Silent when the network is unknown (no RPC URL can be
 * derived) unless `options.rpcUrl` is given.
 */
export async function auditTomlContractEnvMeta(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: EnvMetaOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await auditContractEnvMeta(currency.id, rpcUrl, fetchImpl, {
        ...options,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const envMetaRules: Rule[] = [
  {
    id: MISSING_ENV_META_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract does not embed contractenvmetav0 environment metadata',
    run() {},
  },
  {
    id: DEPRECATED_PROTOCOL_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract was compiled against a deprecated protocol version',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlContractEnvMeta}. */
export const envMetaRuleIds: readonly string[] = envMetaRules.map((rule) => rule.id);
