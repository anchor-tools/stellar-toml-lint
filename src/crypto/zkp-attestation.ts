import { sha256 } from '@noble/hashes/sha2';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const MALFORMED_ZKP_PROOF_RULE = 'crypto/malformed-zkp-proof-data';
export const MALFORMED_ZKP_PROOF_DATA_RULE = MALFORMED_ZKP_PROOF_RULE;
export const ZKP_SUPPLY_COMMITMENT_MISMATCH_RULE = 'crypto/zkp-supply-commitment-mismatch';

const CURRENCY_DOC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';
const ATTESTATION_FIELDS = [
  'zkp_attestation',
  'zkp_attestations',
  'zkp_proof',
  'zkp_proofs',
  'zkp',
  'reserve_proof',
  'reserves_proof',
  'reserve_attestation',
  'zkp_proof_metadata',
  'proof',
] as const;
const COMMITMENT_FIELDS = [
  'supply_commitment',
  'public_input_hash',
  'publicInputHash',
  'supply_hash',
  'reserve_commitment',
  'commitment',
] as const;

const CURVES = new Map<string, string>([
  ['bls12-381', 'BLS12-381'],
  ['bls12381', 'BLS12-381'],
  ['bls12_381', 'BLS12-381'],
  ['bls12', 'BLS12-381'],
  ['bn254', 'BN254'],
  ['bn128', 'BN254'],
  ['alt_bn128', 'BN254'],
  ['altbn128', 'BN254'],
]);

export interface ZkpAttestationOptions {
  rules?: RuleOverrides;
}

type RecordValue = Record<string, unknown>;

function isRecord(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  message: string,
  path: string,
  suggestion: string,
  options: ZkpAttestationOptions,
): void {
  const severity = severityFor(rule, 'error', options.rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'currencies',
    message,
    path,
    helpUri: CURRENCY_DOC_URL,
    suggestion,
  });
}

function firstDefined(record: RecordValue, fields: readonly string[]): unknown {
  for (const field of fields) {
    if (record[field] !== undefined) return record[field];
  }
  return undefined;
}

function scalar(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return value.toString();
  return undefined;
}

function normalizeCurve(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  return CURVES.get(value.trim().toLowerCase().replace(/\s+/g, ''));
}

function normalizeProtocol(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

function validatePoint(
  value: unknown,
  dimensions: number,
): { ok: true } | { ok: false; detail: string } {
  if (!Array.isArray(value)) return { ok: false, detail: 'is not an array' };
  if (value.length < dimensions || value.length > dimensions + 1) {
    return {
      ok: false,
      detail: `has ${value.length} elements; a G${dimensions} point needs ${dimensions}`,
    };
  }
  for (let i = 0; i < dimensions; i++) {
    if (scalar(value[i]) === undefined) {
      return { ok: false, detail: `element ${i} is not a scalar` };
    }
  }
  return { ok: true };
}

function validateG2(value: unknown): { ok: true } | { ok: false; detail: string } {
  if (!Array.isArray(value)) return { ok: false, detail: 'is not an array' };
  if (value.length >= 4 && value.every((part) => scalar(part) !== undefined)) {
    if (value.length !== 4 && value.length !== 6) {
      return { ok: false, detail: `has ${value.length} flat elements; a G2 point needs 4 or 6` };
    }
    return { ok: true };
  }
  if (value.length < 2 || value.length > 3) {
    return { ok: false, detail: `has ${value.length} coordinate arrays; a G2 point needs 2` };
  }
  for (let i = 0; i < value.length; i++) {
    const point = validatePoint(value[i], 2);
    if (!point.ok) return { ok: false, detail: `coordinate ${i} ${point.detail}` };
  }
  return { ok: true };
}

function proofElements(attestation: RecordValue): { a: unknown; b: unknown; c: unknown } {
  const nested = isRecord(attestation.proof) ? attestation.proof : attestation;
  return {
    a: firstDefined(nested, ['pi_a', 'piA', 'pi_A', 'a']),
    b: firstDefined(nested, ['pi_b', 'piB', 'pi_B', 'b']),
    c: firstDefined(nested, ['pi_c', 'piC', 'pi_C', 'c']),
  };
}

function publicInputsOf(attestation: RecordValue): unknown {
  return firstDefined(attestation, ['public_inputs', 'publicInputs', 'public_input', 'inputs']);
}

function normalizeSupply(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return String(value);
  if (typeof value === 'bigint' && value >= 0n) return value.toString();
  if (typeof value === 'string') {
    const trimmed = value.trim().replace(/,/g, '');
    if (/^\d+$/.test(trimmed)) return BigInt(trimmed).toString();
  }
  return undefined;
}

function supplyOf(entry: RecordValue, attestation: RecordValue): string | undefined {
  for (const field of ['fixed_number', 'max_number', 'circulating_supply', 'total_supply']) {
    const supply = normalizeSupply(entry[field]);
    if (supply !== undefined) return supply;
  }
  for (const field of ['circulating_supply', 'supply', 'total_supply']) {
    const supply = normalizeSupply(attestation[field]);
    if (supply !== undefined) return supply;
  }
  return undefined;
}

function hexBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function bigintBytes(value: string): Uint8Array | undefined {
  try {
    let hex = BigInt(value).toString(16);
    if (hex.length % 2 === 1) hex = `0${hex}`;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  } catch {
    return undefined;
  }
}

function normalizedHash(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/^0x/, '')
    .replace(/[\s:-]/g, '');
}

function commitmentMatches(commitment: string, supply: string, inputs: readonly string[]): boolean {
  const normalized = normalizedHash(commitment);
  if (normalizeSupply(commitment) === supply) return true;

  const candidates = new Set<string>();
  candidates.add(hexBytes(sha256(new TextEncoder().encode(supply))));
  const supplyBytes = bigintBytes(supply);
  if (supplyBytes !== undefined) candidates.add(hexBytes(sha256(supplyBytes)));
  if (inputs.length > 0) {
    candidates.add(hexBytes(sha256(new TextEncoder().encode(JSON.stringify(inputs)))));
  }
  return candidates.has(normalized);
}

function commitmentValues(attestation: RecordValue, inputs: readonly string[]): string[] {
  const values: string[] = [];
  const container = isRecord(attestation.proof) ? attestation.proof : attestation;
  const declared = firstDefined(container, COMMITMENT_FIELDS);
  if (Array.isArray(declared)) {
    for (const item of declared) {
      const value = scalar(item);
      if (value !== undefined) values.push(value);
    }
  } else {
    const value = scalar(declared);
    if (value !== undefined) values.push(value);
  }
  if (values.length === 0) {
    for (const input of inputs) {
      if (/^(?:0x)?[0-9a-fA-F]{64}$/.test(input)) values.push(input);
    }
  }
  return values;
}

function auditAttestation(
  attestation: unknown,
  basePath: string,
  entry: RecordValue,
  options: ZkpAttestationOptions,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  if (!isRecord(attestation)) {
    report(
      diagnostics,
      MALFORMED_ZKP_PROOF_RULE,
      `${basePath} must be a table describing a ZKP reserve attestation`,
      basePath,
      'Publish a Groth16 proof with curve, pi_a, pi_b, pi_c, and public_inputs fields.',
      options,
    );
    return diagnostics;
  }

  const protocol = firstDefined(attestation, ['protocol', 'proof_type', 'proofType', 'type']);
  if (protocol !== undefined && normalizeProtocol(protocol) !== 'groth16') {
    report(
      diagnostics,
      MALFORMED_ZKP_PROOF_RULE,
      `${basePath} uses unsupported proof system ${JSON.stringify(protocol)}; only Groth16 is understood`,
      basePath,
      'Set protocol to "groth16" and publish the pi_a, pi_b, and pi_c proof elements.',
      options,
    );
  }

  const curveValue = firstDefined(attestation, ['curve', 'curve_type', 'curveType']);
  if (curveValue !== undefined && normalizeCurve(curveValue) === undefined) {
    report(
      diagnostics,
      MALFORMED_ZKP_PROOF_RULE,
      `${basePath} declares unsupported curve ${JSON.stringify(curveValue)}; use BLS12-381 or BN254`,
      `${basePath}.curve`,
      'Use a pairing-friendly curve supported by Groth16, such as BLS12-381 or BN254.',
      options,
    );
  }

  const { a, b, c } = proofElements(attestation);
  const aResult = validatePoint(a, 2);
  const bResult = validateG2(b);
  const cResult = validatePoint(c, 2);
  for (const [label, result] of [
    ['pi_a', aResult],
    ['pi_b', bResult],
    ['pi_c', cResult],
  ] as const) {
    if (!result.ok) {
      const path = `${basePath}.${label}`;
      report(
        diagnostics,
        MALFORMED_ZKP_PROOF_RULE,
        `${path} ${result.detail}`,
        path,
        'Publish Groth16 proof points as coordinate arrays: pi_a and pi_c are G1 pairs, pi_b is a pair of G2 coordinate arrays.',
        options,
      );
    }
  }

  const rawInputs = publicInputsOf(attestation);
  const inputs: string[] = [];
  if (rawInputs !== undefined) {
    if (!Array.isArray(rawInputs) || rawInputs.length === 0) {
      report(
        diagnostics,
        MALFORMED_ZKP_PROOF_RULE,
        `${basePath}.public_inputs must be a non-empty array of field elements`,
        `${basePath}.public_inputs`,
        'Publish the Groth16 public inputs in the order the circuit expects them.',
        options,
      );
    } else {
      rawInputs.forEach((input, index) => {
        const value = scalar(input);
        if (value === undefined) {
          report(
            diagnostics,
            MALFORMED_ZKP_PROOF_RULE,
            `${basePath}.public_inputs[${index}] is not a scalar field element`,
            `${basePath}.public_inputs[${index}]`,
            'Encode each public input as a decimal or hexadecimal string.',
            options,
          );
        } else {
          inputs.push(value);
        }
      });
    }
  }

  const supply = supplyOf(entry, attestation);
  const commitments = commitmentValues(attestation, inputs);
  if (supply !== undefined && commitments.length > 0) {
    const matches = commitments.some((commitment) => commitmentMatches(commitment, supply, inputs));
    if (!matches) {
      const commitmentContainer = isRecord(attestation.proof) ? attestation.proof : attestation;
      const commitmentField = COMMITMENT_FIELDS.find(
        (field) => commitmentContainer[field] !== undefined,
      );
      report(
        diagnostics,
        ZKP_SUPPLY_COMMITMENT_MISMATCH_RULE,
        `${basePath} public input commitment does not match the declared supply ${supply}`,
        commitmentField === undefined
          ? `${basePath}.public_inputs`
          : `${basePath}.${commitmentField}`,
        'Recompute the supply commitment from the issued supply, or update fixed_number/max_number to the committed supply.',
        options,
      );
    }
  }

  return diagnostics;
}

function attestationsOf(
  entry: RecordValue,
  field: string,
  currencyIndex: number,
): { value: unknown; path: string }[] {
  const raw = entry[field];
  if (raw === undefined) return [];
  const items = Array.isArray(raw) ? raw : [raw];
  return items.map((value, index) => ({
    value,
    path: Array.isArray(raw)
      ? `CURRENCIES[${currencyIndex}].${field}[${index}]`
      : `CURRENCIES[${currencyIndex}].${field}`,
  }));
}

/**
 * Validates every ZKP reserve attestation attached to a `[[CURRENCIES]]` entry.
 *
 * The validator is offline: it checks the Groth16 proof shape, the named
 * pairing curve, the public-input array, and whether the declared supply
 * commitment agrees with the entry's issued supply.
 */
export function auditZkpAttestations(
  doc: Record<string, unknown>,
  options: ZkpAttestationOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];

  currencies.forEach((rawEntry, index) => {
    if (!isRecord(rawEntry)) return;
    for (const field of ATTESTATION_FIELDS) {
      if (rawEntry[field] === undefined) continue;
      for (const { value, path } of attestationsOf(rawEntry, field, index)) {
        diagnostics.push(...auditAttestation(value, path, rawEntry, options));
      }
    }
  });

  return diagnostics;
}

export const validateZkpAttestations = auditZkpAttestations;
export const checkZkpAttestations = auditZkpAttestations;

export const zkpAttestationRules: Rule[] = [
  {
    id: MALFORMED_ZKP_PROOF_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'ZKP reserve attestations must carry well-formed Groth16 proof data',
    run() {},
  },
  {
    id: ZKP_SUPPLY_COMMITMENT_MISMATCH_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'A ZKP supply commitment must match the declared asset supply',
    run() {},
  },
];

export const zkpAttestationRuleIds: readonly string[] = zkpAttestationRules.map((rule) => rule.id);
