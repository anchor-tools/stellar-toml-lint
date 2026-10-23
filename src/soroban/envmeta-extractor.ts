import { cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, RuleOverrides } from '../types.js';
import { severityFor } from './rpc.js';
import { getWasmCustomSection } from './wasm-auditor.js';

export const ENV_META_SECTION = 'contractenvmetav0';

export const MISSING_ENV_META_RULE = 'soroban/missing-env-meta';
export const DEPRECATED_COMPILER_RULE = 'soroban/deprecated-compiler-version';
export const MALFORMED_ENVMETA_RULE = 'soroban/malformed-envmeta-xdr';

export const DEFAULT_PROTOCOL_VERSION = 22;

export interface ContractEnvMeta {
  protocol: number;
  preRelease: number;
}

export interface EnvMetaExtraction {
  entries: ContractEnvMeta[];
  malformed: boolean;
  error?: string;
}

export interface EnvMetaOptions {
  rules?: RuleOverrides;
  path?: string;
  rpcUrl?: string;
  protocolVersion?: number;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function extractEnvMetaEntries(wasm: Buffer): EnvMetaExtraction {
  const section = getWasmCustomSection(wasm, ENV_META_SECTION);
  if (section === undefined) return { entries: [], malformed: false };

  try {
    const reader = new cereal.XdrReader(section);
    const entries: ContractEnvMeta[] = [];
    while (!reader.eof) {
      const entry = xdr.ScEnvMetaEntry.read(reader as unknown as Buffer);
      if (entry.switch().name !== 'scEnvMetaKindInterfaceVersion') continue;
      const version = entry.interfaceVersion();
      entries.push({ protocol: version.protocol(), preRelease: version.preRelease() });
    }
    return { entries, malformed: false };
  } catch (error) {
    return { entries: [], malformed: true, error: errorMessage(error) };
  }
}

export function extractEnvMeta(wasm: Buffer): ContractEnvMeta | undefined {
  const extraction = extractEnvMetaEntries(wasm);
  return extraction.malformed ? undefined : extraction.entries[0];
}

function finding(
  contractId: string,
  options: EnvMetaOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  suggestion: string,
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
        suggestion,
      },
    ];
  };
}

export function verifyEnvMeta(
  wasm: Buffer,
  contractId: string,
  options: EnvMetaOptions = {},
): Diagnostic[] {
  const report = finding(contractId, options);
  const extraction = extractEnvMetaEntries(wasm);

  if (extraction.malformed) {
    return report(
      MALFORMED_ENVMETA_RULE,
      'error',
      `has a malformed "${ENV_META_SECTION}" custom section${
        extraction.error === undefined ? '' : `: ${extraction.error}`
      }`,
      'Rebuild the contract with the official Soroban Rust SDK so the environment metadata is valid XDR.',
    );
  }

  const meta = extraction.entries[0];
  if (meta === undefined) {
    return report(
      MISSING_ENV_META_RULE,
      'warning',
      `WASM has no "${ENV_META_SECTION}" custom section, so its protocol version is unknown`,
      'Build the contract with the official Soroban Rust SDK so environment metadata is embedded.',
    );
  }

  const active = options.protocolVersion ?? DEFAULT_PROTOCOL_VERSION;
  if (meta.protocol >= active) return [];

  return report(
    DEPRECATED_COMPILER_RULE,
    'warning',
    `was compiled against Soroban protocol ${meta.protocol}, but the active protocol is ${active}`,
    `Rebuild and redeploy the contract with a Soroban SDK targeting protocol ${active}.`,
  );
}
