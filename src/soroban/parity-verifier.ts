import { cereal, hash as sha256, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { webAuthContractIdOf } from '../rules/general.js';
import { fetchContractWasm, severityFor } from './rpc.js';
import { NETWORK_TARGETS } from './multi-network.js';
import { getWasmCustomSection } from './wasm-auditor.js';

export const BYTE_MISMATCH_RULE = 'soroban/multi-network-byte-mismatch';
export const SPEC_DRIFT_RULE = 'soroban/spec-interface-drift';
export const SPEC_SECTION = 'contractspecv0';

export interface ParityNetwork {
  name: string;
  rpcUrl: string;
}

export const PARITY_NETWORKS: readonly ParityNetwork[] = NETWORK_TARGETS.map(
  ({ name, rpcUrl }) => ({ name, rpcUrl }),
);

export interface SpecFunction {
  name: string;
  signature: string;
}

export interface SpecSummary {
  functions: SpecFunction[];
  malformed: boolean;
}

export interface NetworkDeployment {
  network: string;
  wasm: Buffer;
}

export interface ParityOptions {
  rules?: RuleOverrides;
  path?: string;
  targets?: readonly ParityNetwork[];
}

function textual(value: string | Buffer): string {
  return typeof value === 'string' ? value : value.toString('utf8');
}

function typeSignature(type: xdr.ScSpecTypeDef): string {
  return type.toXDR('base64');
}

export function extractSpecFunctions(wasm: Buffer): SpecSummary {
  const section = getWasmCustomSection(wasm, SPEC_SECTION);
  if (section === undefined) return { functions: [], malformed: false };

  try {
    const reader = new cereal.XdrReader(section);
    const functions: SpecFunction[] = [];
    while (!reader.eof) {
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      if (entry.switch().name !== 'scSpecEntryFunctionV0') continue;

      const callable = entry.functionV0();
      const inputs = callable
        .inputs()
        .map((input) => `${textual(input.name())}:${typeSignature(input.type())}`)
        .join(',');
      const outputs = callable.outputs().map(typeSignature).join(',');
      functions.push({ name: textual(callable.name()), signature: `${inputs}->${outputs}` });
    }

    return { functions, malformed: false };
  } catch {
    return { functions: [], malformed: true };
  }
}

function canonicalFunctions(functions: readonly SpecFunction[]): Map<string, string[]> {
  const byName = new Map<string, string[]>();
  for (const fn of functions) {
    const signatures = byName.get(fn.name) ?? [];
    signatures.push(fn.signature);
    byName.set(fn.name, signatures);
  }
  for (const signatures of byName.values()) signatures.sort();
  return byName;
}

function sameInterface(left: SpecSummary, right: SpecSummary): boolean {
  if (left.malformed || right.malformed) return left.malformed === right.malformed;

  const expected = canonicalFunctions(left.functions);
  const actual = canonicalFunctions(right.functions);
  if (expected.size !== actual.size) return false;

  for (const [name, signatures] of expected) {
    const other = actual.get(name);
    if (other === undefined || other.length !== signatures.length) return false;
    if (other.some((signature, index) => signature !== signatures[index])) return false;
  }
  return true;
}

function byteHash(wasm: Uint8Array): string {
  return sha256(Buffer.from(wasm)).toString('hex');
}

function formatNetworks(names: readonly string[]): string {
  const last = names.at(-1) ?? '';
  if (names.length <= 1) return last;
  if (names.length === 2) return names.join(' and ');
  return `${names.slice(0, -1).join(', ')}, and ${last}`;
}

function finding(
  contractId: string,
  options: ParityOptions,
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

export function verifyParity(
  contractId: string,
  deployments: readonly NetworkDeployment[],
  options: ParityOptions = {},
): Diagnostic[] {
  const [reference, ...others] = deployments;
  if (reference === undefined || others.length === 0) return [];

  const report = finding(contractId, options);
  const referenceHash = byteHash(reference.wasm);
  const referenceSpec = extractSpecFunctions(reference.wasm);

  const byteMismatches = others.filter((deployment) => byteHash(deployment.wasm) !== referenceHash);
  const specMismatches = others.filter(
    (deployment) => !sameInterface(referenceSpec, extractSpecFunctions(deployment.wasm)),
  );

  const diagnostics: Diagnostic[] = [];
  if (byteMismatches.length > 0) {
    diagnostics.push(
      ...report(
        BYTE_MISMATCH_RULE,
        'warning',
        `has different bytecode on ${formatNetworks(
          byteMismatches.map((deployment) => deployment.network),
        )} than on ${reference.network}`,
        'Deploy the same audited WASM build to every network, or document the intentional divergence.',
      ),
    );
  }
  if (specMismatches.length > 0) {
    diagnostics.push(
      ...report(
        SPEC_DRIFT_RULE,
        'error',
        `exports different functions on ${formatNetworks(
          specMismatches.map((deployment) => deployment.network),
        )} than on ${reference.network}`,
        'Align the exported function names, inputs, and outputs before promoting the build between networks.',
      ),
    );
  }
  return diagnostics;
}

export async function auditContractParity(
  contractId: string,
  fetchImpl: typeof fetch = fetch,
  options: ParityOptions = {},
): Promise<Diagnostic[]> {
  const targets = options.targets ?? PARITY_NETWORKS;
  if (targets.length < 2) return [];

  const deployments = (
    await Promise.all(
      targets.map(async (target): Promise<NetworkDeployment | undefined> => {
        const wasm = await fetchContractWasm(contractId, target.rpcUrl, fetchImpl);
        return wasm === undefined ? undefined : { network: target.name, wasm };
      }),
    )
  ).filter((deployment): deployment is NetworkDeployment => deployment !== undefined);

  return verifyParity(contractId, deployments, options);
}

export async function auditTomlContractParity(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ParityOptions = {},
): Promise<Diagnostic[]> {
  const targets = new Map<string, string>();
  for (const currency of contractCurrenciesOf(doc)) targets.set(currency.id, currency.path);
  const auth = webAuthContractIdOf(doc);
  if (auth !== undefined) targets.set(auth.id, auth.path);

  const diagnostics: Diagnostic[] = [];
  for (const [id, path] of targets) {
    diagnostics.push(...(await auditContractParity(id, fetchImpl, { ...options, path })));
  }
  return diagnostics;
}

export const parityRules: Rule[] = [
  {
    id: BYTE_MISMATCH_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A contract has different WASM bytecode on two networks',
    run() {},
  },
  {
    id: SPEC_DRIFT_RULE,
    category: 'network',
    severity: 'error',
    description: 'A contract exports a different function interface on two networks',
    run() {},
  },
];

export const parityRuleIds: readonly string[] = parityRules.map((rule) => rule.id);
