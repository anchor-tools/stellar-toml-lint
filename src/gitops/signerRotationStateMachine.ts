/**
 * Multisig signer rotation planner.
 *
 * Rotating signers on an anchor root account is one of the few operations that
 * can permanently brick a treasury. Adding a signer before raising a threshold
 * is harmless; removing the last signer that can meet it is not. The state
 * machine below ingests the live account from Horizon, compares it with the
 * desired topology, emits a safe sequence of `SetOptions` operations, and
 * validates every intermediate state before anything is signed.
 */
import {
  Account,
  BASE_FEE,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
} from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import { isString } from '../predicates.js';

/** Stellar allows at most 20 signers, including the master key. */
export const MAX_ACCOUNT_SIGNERS = 20;

/** Stellar's default master weight. */
export const DEFAULT_MASTER_WEIGHT = 1;

export type SignerType =
  'ed25519_public_key' | 'sha256_hash' | 'pre_auth_tx' | 'ed25519_signed_payload';

export interface SignerDefinition {
  key: string;
  weight: number;
  type: SignerType;
}

export interface SignerThresholds {
  low: number;
  medium: number;
  high: number;
  masterWeight: number;
}

export interface AccountSignerState {
  accountId: string;
  thresholds: SignerThresholds;
  /** Additional signers. The master key is represented by `masterWeight`. */
  signers: SignerDefinition[];
}

export interface DesiredSignerState {
  accountId?: string;
  thresholds: {
    low?: number;
    medium?: number;
    high?: number;
    masterWeight?: number;
  };
  signers: SignerDefinition[];
}

/** One operation in the planned transition. Mirrors Stellar's SetOptionsOp. */
export interface SetOptionsOperation {
  type: 'setOptions';
  masterWeight?: number;
  lowThreshold?: number;
  medThreshold?: number;
  highThreshold?: number;
  signer?: SignerDefinition;
}

export interface IntermediateRotationState {
  /** 1-based operation number this state was recorded after. */
  afterOperation: number;
  description: string;
  state: AccountSignerState;
  totalWeight: number;
  signerCount: number;
}

export interface RotationPlan {
  accountId: string;
  current: AccountSignerState;
  desired: AccountSignerState;
  operations: SetOptionsOperation[];
  intermediateStates: IntermediateRotationState[];
  warnings: string[];
  errors: string[];
  valid: boolean;
}

export interface RotationSimulationResult {
  success: boolean;
  envelopeXdr?: string;
  error?: string;
  /** Raw RPC response, when a remote simulator was used. */
  result?: unknown;
}

export interface RotationSimulationOptions {
  sourceAccount?: string;
  sequence?: string;
  networkPassphrase?: string;
  fee?: string;
  sorobanRpcUrl?: string;
  fetchImpl?: typeof fetch;
  /** Override the transport; useful for Horizon/Soroban RPC adapters in tests. */
  simulate?: (envelopeXdr: string, plan: RotationPlan) => Promise<RotationSimulationResult>;
}

export interface EnvelopeOptions {
  sourceAccount?: string;
  sequence?: string;
  networkPassphrase?: string;
  fee?: string;
  timeoutSeconds?: number;
}

interface WorkingState {
  accountId: string;
  thresholds: SignerThresholds;
  signers: Map<string, SignerDefinition>;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toWeight(value: unknown, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (isString(value) && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function isWeight(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 255;
}

function inferSignerType(key: string): SignerType {
  switch (key.charAt(0)) {
    case 'T':
      return 'pre_auth_tx';
    case 'X':
      return 'sha256_hash';
    case 'P':
      return 'ed25519_signed_payload';
    default:
      return 'ed25519_public_key';
  }
}

function normalizeSignerType(value: unknown, key: string): SignerType {
  if (
    value === 'ed25519_public_key' ||
    value === 'sha256_hash' ||
    value === 'pre_auth_tx' ||
    value === 'ed25519_signed_payload'
  ) {
    return value;
  }
  return inferSignerType(key);
}

function normalizeSigner(value: unknown, path: string): SignerDefinition {
  if (isString(value)) {
    if (value.trim() === '') throw new Error(`${path} is an empty signer key`);
    return { key: value.trim(), weight: 1, type: inferSignerType(value.trim()) };
  }

  const record = asRecord(value);
  if (!record) throw new Error(`${path} is not a signer object or key string`);

  const key =
    record.key ??
    record.public_key ??
    record.PUBLIC_KEY ??
    record.ed25519PublicKey ??
    record.ed25519_public_key ??
    record.sha256_hash ??
    record.pre_auth_tx ??
    record.ed25519_signed_payload;
  if (!isString(key) || key.trim() === '') {
    throw new Error(`${path} is missing a signer key`);
  }

  const weight = toWeight(record.weight ?? record.WEIGHT, 1);
  const type = normalizeSignerType(record.type ?? record.TYPE, key.trim());
  return { key: key.trim(), weight, type };
}

function signerListOf(record: Record<string, unknown>): unknown[] {
  const candidates = [
    record.signers,
    record.SIGNERS,
    record.new_signers,
    record.NEW_SIGNERS,
    record['new-signers'],
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
  }
  return [];
}

function thresholdsOf(record: Record<string, unknown>): {
  low?: number;
  medium?: number;
  high?: number;
  masterWeight?: number;
} {
  const nested = asRecord(record.thresholds ?? record.THRESHOLDS);
  const source = nested ?? record;
  const result: {
    low?: number;
    medium?: number;
    high?: number;
    masterWeight?: number;
  } = {};

  const low = source.low ?? source.low_threshold ?? source.LOW_THRESHOLD;
  const medium =
    source.medium ??
    source.med ??
    source.med_threshold ??
    source.medium_threshold ??
    source.MED_THRESHOLD;
  const high = source.high ?? source.high_threshold ?? source.HIGH_THRESHOLD;
  const masterWeight =
    source.masterWeight ??
    source.master_weight ??
    source.MASTER_WEIGHT ??
    record.masterWeight ??
    record.master_weight;

  if (low !== undefined) result.low = toWeight(low, Number.NaN);
  if (medium !== undefined) result.medium = toWeight(medium, Number.NaN);
  if (high !== undefined) result.high = toWeight(high, Number.NaN);
  if (masterWeight !== undefined) result.masterWeight = toWeight(masterWeight, Number.NaN);
  return result;
}

/** Parses the signers/thresholds portion of a Horizon account document. */
export function parseHorizonSignerState(
  body: unknown,
  expectedAccountId?: string,
): AccountSignerState {
  const record = asRecord(body);
  if (!record) throw new Error('Horizon account response was not a JSON object');

  const accountId =
    (isString(record.account_id) ? record.account_id : undefined) ??
    (isString(record.id) ? record.id : undefined) ??
    expectedAccountId;
  if (accountId === undefined || accountId === '') {
    throw new Error('Horizon account response is missing an account id');
  }

  const thresholdFields = thresholdsOf(record);
  const signersValue = record.signers;
  const signerValues = Array.isArray(signersValue) ? signersValue : [];
  const signers: SignerDefinition[] = [];
  let masterWeight: number | undefined;

  for (const [index, value] of signerValues.entries()) {
    const signer = normalizeSigner(value, `signers[${index}]`);
    if (signer.key === accountId) {
      masterWeight = signer.weight;
      continue;
    }
    signers.push(signer);
  }

  const fallbackMaster =
    thresholdFields.masterWeight ?? (Array.isArray(signersValue) ? 0 : DEFAULT_MASTER_WEIGHT);
  const thresholds: SignerThresholds = {
    low: thresholdFields.low ?? 0,
    medium: thresholdFields.medium ?? 0,
    high: thresholdFields.high ?? 0,
    masterWeight: masterWeight ?? fallbackMaster,
  };

  return { accountId, thresholds, signers };
}

/** Normalizes a JSON/TOML signer-rotation file into a desired state. */
export function parseDesiredSignerState(
  value: unknown,
  options: { accountId?: string } = {},
): DesiredSignerState {
  const record = asRecord(value);
  if (!record) throw new Error('Desired signer state must be an object');

  const accountId =
    (isString(record.account) ? record.account : undefined) ??
    (isString(record.account_id) ? record.account_id : undefined) ??
    (isString(record.ACCOUNT) ? record.ACCOUNT : undefined) ??
    options.accountId;

  const parsedSigners = signerListOf(record).map((entry, index) =>
    normalizeSigner(entry, `signers[${index}]`),
  );
  const thresholds = thresholdsOf(record);

  let masterWeight = thresholds.masterWeight;
  const regular: SignerDefinition[] = [];
  for (const signer of parsedSigners) {
    if (accountId !== undefined && signer.key === accountId) {
      if (masterWeight === undefined) masterWeight = signer.weight;
      continue;
    }
    regular.push(signer);
  }

  return {
    ...(accountId !== undefined ? { accountId } : {}),
    thresholds: {
      ...(thresholds.low !== undefined ? { low: thresholds.low } : {}),
      ...(thresholds.medium !== undefined ? { medium: thresholds.medium } : {}),
      ...(thresholds.high !== undefined ? { high: thresholds.high } : {}),
      ...(masterWeight !== undefined ? { masterWeight } : {}),
    },
    signers: regular,
  };
}

/** Parses a signer-rotation file. JSON is preferred; `.toml` uses smol-toml. */
export function parseSignerStateFile(source: string, path = ''): DesiredSignerState {
  const trimmed = source.trim();
  if (trimmed === '') throw new Error('Signer rotation file is empty');

  if (trimmed.startsWith('{') || path.toLowerCase().endsWith('.json')) {
    try {
      return parseDesiredSignerState(JSON.parse(trimmed));
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(`Invalid JSON in signer rotation file: ${error.message}`, { cause: error });
      }
      throw error;
    }
  }

  try {
    return parseDesiredSignerState(parse(source));
  } catch (error) {
    throw new Error(`Invalid signer rotation file: ${errorMessage(error)}`, { cause: error });
  }
}

function cloneThresholds(thresholds: SignerThresholds): SignerThresholds {
  return { ...thresholds };
}

function normalizeCurrent(state: AccountSignerState): WorkingState {
  const signers = new Map<string, SignerDefinition>();
  for (const signer of state.signers) {
    const key = signer.key.trim();
    if (key === '') throw new Error('Current state contains an empty signer key');
    if (signers.has(key)) throw new Error(`Current state declares signer ${key} more than once`);
    signers.set(key, { ...signer, key });
  }
  return {
    accountId: state.accountId,
    thresholds: cloneThresholds(state.thresholds),
    signers,
  };
}

function finalizeDesired(
  current: AccountSignerState,
  desired: DesiredSignerState,
): { accountId: string; thresholds: SignerThresholds; signers: Map<string, SignerDefinition> } {
  const accountId = desired.accountId ?? current.accountId;
  const thresholds: SignerThresholds = {
    low: desired.thresholds.low ?? current.thresholds.low,
    medium: desired.thresholds.medium ?? current.thresholds.medium,
    high: desired.thresholds.high ?? current.thresholds.high,
    masterWeight: desired.thresholds.masterWeight ?? current.thresholds.masterWeight,
  };

  const signers = new Map<string, SignerDefinition>();
  for (const signer of desired.signers) {
    const key = signer.key.trim();
    if (key === accountId) {
      thresholds.masterWeight = desired.thresholds.masterWeight ?? signer.weight;
      continue;
    }
    if (signers.has(key)) {
      throw new Error(`Desired state declares signer ${key} more than once`);
    }
    signers.set(key, { ...signer, key });
  }

  return { accountId, thresholds, signers };
}

function snapshot(
  state: WorkingState,
  afterOperation: number,
  description: string,
): IntermediateRotationState {
  const signers = [...state.signers.values()].sort((a, b) => a.key.localeCompare(b.key));
  const thresholds = cloneThresholds(state.thresholds);
  const regularWeight = signers.reduce((sum, signer) => sum + signer.weight, 0);
  return {
    afterOperation,
    description,
    state: {
      accountId: state.accountId,
      thresholds,
      signers: signers.map((signer) => ({ ...signer })),
    },
    totalWeight: regularWeight + thresholds.masterWeight,
    signerCount: signers.length + (thresholds.masterWeight > 0 ? 1 : 0),
  };
}

function validateThresholds(thresholds: SignerThresholds, label: string): string[] {
  const errors: string[] = [];
  if (!isWeight(thresholds.low))
    errors.push(`${label} low threshold must be an integer from 0 to 255`);
  if (!isWeight(thresholds.medium)) {
    errors.push(`${label} medium threshold must be an integer from 0 to 255`);
  }
  if (!isWeight(thresholds.high))
    errors.push(`${label} high threshold must be an integer from 0 to 255`);
  if (!isWeight(thresholds.masterWeight)) {
    errors.push(`${label} master weight must be an integer from 0 to 255`);
  }
  if (thresholds.low > thresholds.medium || thresholds.medium > thresholds.high) {
    errors.push(`${label} thresholds must satisfy low <= medium <= high`);
  }
  return errors;
}

function validateSafety(state: WorkingState, maxSigners: number, label: string): string[] {
  const errors: string[] = [];
  const signers = [...state.signers.values()];
  const regularWeight = signers.reduce((sum, signer) => sum + signer.weight, 0);
  const masterWeight = state.thresholds.masterWeight;
  const total = regularWeight + masterWeight;
  const count = signers.length + (masterWeight > 0 ? 1 : 0);

  if (count > maxSigners) {
    errors.push(`${label} has ${count} signers, above the Stellar maximum of ${maxSigners}`);
  }
  for (const signer of signers) {
    if (!isWeight(signer.weight)) {
      errors.push(`${label} signer ${signer.key} has invalid weight ${signer.weight}`);
    }
  }
  if (total < state.thresholds.high) {
    errors.push(
      `${label} total signing weight ${total} is below the high threshold ${state.thresholds.high}, which would lock the account`,
    );
  }
  if (masterWeight === 0 && regularWeight < state.thresholds.high) {
    errors.push(
      `${label} disables the master key while remaining signers only hold weight ${regularWeight}, below the high threshold ${state.thresholds.high}`,
    );
  }
  return errors;
}

function signerOperation(signer: SignerDefinition, weight = signer.weight): SetOptionsOperation {
  return {
    type: 'setOptions',
    signer: { key: signer.key, weight, type: signer.type },
  };
}

function thresholdOperation(
  low: number | undefined,
  medium: number | undefined,
  high: number | undefined,
): SetOptionsOperation {
  return {
    type: 'setOptions',
    ...(low !== undefined ? { lowThreshold: low } : {}),
    ...(medium !== undefined ? { medThreshold: medium } : {}),
    ...(high !== undefined ? { highThreshold: high } : {}),
  };
}

function applyOperation(state: WorkingState, operation: SetOptionsOperation): void {
  if (operation.masterWeight !== undefined) state.thresholds.masterWeight = operation.masterWeight;
  if (operation.lowThreshold !== undefined) state.thresholds.low = operation.lowThreshold;
  if (operation.medThreshold !== undefined) state.thresholds.medium = operation.medThreshold;
  if (operation.highThreshold !== undefined) state.thresholds.high = operation.highThreshold;
  if (operation.signer !== undefined) {
    if (operation.signer.weight === 0) state.signers.delete(operation.signer.key);
    else state.signers.set(operation.signer.key, { ...operation.signer });
  }
}

function describeOperation(operation: SetOptionsOperation): string {
  const parts: string[] = [];
  if (operation.masterWeight !== undefined) parts.push(`masterWeight=${operation.masterWeight}`);
  if (operation.lowThreshold !== undefined) parts.push(`lowThreshold=${operation.lowThreshold}`);
  if (operation.medThreshold !== undefined) parts.push(`medThreshold=${operation.medThreshold}`);
  if (operation.highThreshold !== undefined) parts.push(`highThreshold=${operation.highThreshold}`);
  if (operation.signer !== undefined) {
    parts.push(
      operation.signer.weight === 0
        ? `remove signer ${operation.signer.key}`
        : `set signer ${operation.signer.key} weight ${operation.signer.weight}`,
    );
  }
  return parts.join(' ');
}

/**
 * Plans the transition from the live account state to the desired topology.
 *
 * Ordering is deliberate: thresholds move down first (always safe), then
 * signers and weights move up, then thresholds move up, and only after all of
 * that are signers and the master key allowed to move down. The resulting
 * operation list can be placed in a single transaction.
 */
function invalidRotationPlan(
  current: AccountSignerState,
  desired: DesiredSignerState,
  errors: string[],
): RotationPlan {
  const accountId = desired.accountId ?? current.accountId;
  return {
    accountId,
    current: {
      accountId: current.accountId,
      thresholds: cloneThresholds(current.thresholds),
      signers: current.signers.map((signer) => ({ ...signer })),
    },
    desired: {
      accountId,
      thresholds: {
        low: desired.thresholds.low ?? current.thresholds.low,
        medium: desired.thresholds.medium ?? current.thresholds.medium,
        high: desired.thresholds.high ?? current.thresholds.high,
        masterWeight: desired.thresholds.masterWeight ?? current.thresholds.masterWeight,
      },
      signers: desired.signers.map((signer) => ({ ...signer })),
    },
    operations: [],
    intermediateStates: [],
    warnings: [],
    errors,
    valid: false,
  };
}

export function planSignerRotation(
  current: AccountSignerState,
  desired: DesiredSignerState,
  options: { maxSigners?: number } = {},
): RotationPlan {
  const maxSigners = options.maxSigners ?? MAX_ACCOUNT_SIGNERS;
  const errors: string[] = [];
  const warnings: string[] = [];
  const operations: SetOptionsOperation[] = [];
  const intermediateStates: IntermediateRotationState[] = [];

  let working: WorkingState;
  try {
    working = normalizeCurrent(current);
  } catch (error) {
    return invalidRotationPlan(current, desired, [errorMessage(error)]);
  }

  let target: ReturnType<typeof finalizeDesired>;
  try {
    target = finalizeDesired(current, desired);
  } catch (error) {
    return invalidRotationPlan(current, desired, [errorMessage(error)]);
  }
  const targetThresholds = target.thresholds;

  errors.push(...validateThresholds(working.thresholds, 'Current state'));
  errors.push(...validateThresholds(targetThresholds, 'Desired state'));
  errors.push(...validateSafety(working, maxSigners, 'Current state'));

  const desiredMap = new Map(target.signers);
  const desiredActive = new Map(
    [...desiredMap].filter(([, signer]) => signer.weight > 0) as [string, SignerDefinition][],
  );
  if (desiredActive.size + (targetThresholds.masterWeight > 0 ? 1 : 0) > maxSigners) {
    errors.push(
      `Desired state declares ${desiredActive.size + (targetThresholds.masterWeight > 0 ? 1 : 0)} signers, above the Stellar maximum of ${maxSigners}`,
    );
  }

  const record = (operation: SetOptionsOperation): void => {
    operations.push(operation);
    applyOperation(working, operation);
    const next = snapshot(working, operations.length, describeOperation(operation));
    intermediateStates.push(next);
    errors.push(
      ...validateSafety(working, maxSigners, `State after operation ${operations.length}`),
    );
  };

  // 1. Lower thresholds before removing or reducing anything.
  const lowered = {
    low: targetThresholds.low < working.thresholds.low ? targetThresholds.low : undefined,
    medium:
      targetThresholds.medium < working.thresholds.medium ? targetThresholds.medium : undefined,
    high: targetThresholds.high < working.thresholds.high ? targetThresholds.high : undefined,
  };
  if (lowered.low !== undefined || lowered.medium !== undefined || lowered.high !== undefined) {
    record(thresholdOperation(lowered.low, lowered.medium, lowered.high));
  }

  // 2. If adding signers would exceed the cap, remove obsolete signers first —
  //    but only while the account can still meet its current quorum.
  const needsRoom = (): number => {
    const workingCount = working.signers.size + (working.thresholds.masterWeight > 0 ? 1 : 0);
    const additions = [...desiredActive.values()].filter(
      (signer) => !working.signers.has(signer.key),
    ).length;
    return workingCount + additions - maxSigners;
  };

  if (needsRoom() > 0) {
    const obsolete = [...working.signers.values()]
      .filter((signer) => {
        const targetSigner = desiredMap.get(signer.key);
        return targetSigner === undefined || targetSigner.weight === 0;
      })
      .sort((a, b) => a.weight - b.weight);

    for (const signer of obsolete) {
      if (needsRoom() <= 0) break;
      const candidate: WorkingState = {
        accountId: working.accountId,
        thresholds: cloneThresholds(working.thresholds),
        signers: new Map(working.signers),
      };
      applyOperation(candidate, signerOperation(signer, 0));
      if (validateSafety(candidate, maxSigners, 'Temporary removal').length === 0) {
        record(signerOperation(signer, 0));
      }
    }

    if (needsRoom() > 0) {
      errors.push(
        `Cannot safely make room for the desired signers: ${needsRoom()} more signer slot(s) are needed but removing another obsolete signer would drop below the current high threshold`,
      );
    }
  }

  // 3. Add new signers and raise existing weights, all moves that only add
  //    signing capability.
  for (const signer of desiredActive.values()) {
    const existing = working.signers.get(signer.key);
    if (existing === undefined || signer.weight > existing.weight) {
      record(signerOperation(signer));
    }
  }

  if (targetThresholds.masterWeight > working.thresholds.masterWeight) {
    record({ type: 'setOptions', masterWeight: targetThresholds.masterWeight });
  }

  // 4. Raise thresholds only after the new quorum can meet them.
  const raised = {
    low: targetThresholds.low > working.thresholds.low ? targetThresholds.low : undefined,
    medium:
      targetThresholds.medium > working.thresholds.medium ? targetThresholds.medium : undefined,
    high: targetThresholds.high > working.thresholds.high ? targetThresholds.high : undefined,
  };
  if (raised.low !== undefined || raised.medium !== undefined || raised.high !== undefined) {
    record(thresholdOperation(raised.low, raised.medium, raised.high));
  }

  // 5. Remove obsolete signers and lower retained weights. The final desired
  //    state has already been validated, so every intermediate after this
  //    point is at least as strong as that state.
  for (const signer of [...working.signers.values()]) {
    const targetSigner = desiredMap.get(signer.key);
    if (targetSigner === undefined || targetSigner.weight === 0) {
      record(signerOperation(signer, 0));
    } else if (targetSigner.weight < signer.weight) {
      record({ ...signerOperation(signer, targetSigner.weight) });
    }
  }

  // 6. Disable or reduce the master key last, after the new signers can carry
  //    the quorum on their own.
  if (targetThresholds.masterWeight < working.thresholds.masterWeight) {
    record({ type: 'setOptions', masterWeight: targetThresholds.masterWeight });
  }

  errors.push(...validateThresholds(working.thresholds, 'Final state'));
  errors.push(...validateSafety(working, maxSigners, 'Final state'));

  const finalSigners = new Map(
    [...working.signers.values()].map((signer) => [signer.key, signer] as const),
  );
  if (finalSigners.size !== desiredActive.size) {
    errors.push(
      `Final state has ${finalSigners.size} signers but the desired state declares ${desiredActive.size}`,
    );
  }
  for (const [key, signer] of desiredActive) {
    const actual = finalSigners.get(key);
    if (actual === undefined || actual.weight !== signer.weight || actual.type !== signer.type) {
      errors.push(`Final signer ${key} does not match the desired weight and type`);
    }
  }
  if (working.thresholds.masterWeight !== targetThresholds.masterWeight) {
    errors.push('Final master weight does not match the desired state');
  }
  if (
    working.thresholds.low !== targetThresholds.low ||
    working.thresholds.medium !== targetThresholds.medium ||
    working.thresholds.high !== targetThresholds.high
  ) {
    errors.push('Final thresholds do not match the desired state');
  }

  if (targetThresholds.masterWeight === 0 && targetThresholds.high === 0) {
    warnings.push(
      'The desired high threshold is 0, so any single signer can exercise every account operation',
    );
  }
  if (targetThresholds.masterWeight === 0) {
    warnings.push(
      'The master key will be disabled; confirm the desired signers and recovery procedure before submitting',
    );
  }
  if (current.thresholds.masterWeight !== 0 && targetThresholds.masterWeight === 0) {
    warnings.push('This plan permanently reduces the master key weight to 0');
  }
  if (operations.length === 0) {
    warnings.push('The account already matches the desired signer state; no operations are needed');
  }

  return {
    accountId: target.accountId,
    current: {
      accountId: current.accountId,
      thresholds: cloneThresholds(current.thresholds),
      signers: current.signers.map((signer) => ({ ...signer })),
    },
    desired: {
      accountId: target.accountId,
      thresholds: cloneThresholds(targetThresholds),
      signers: [...desiredActive.values()].map((signer) => ({ ...signer })),
    },
    operations,
    intermediateStates,
    warnings,
    errors,
    valid: errors.length === 0,
  };
}

type StellarSignerOption =
  | { ed25519PublicKey: string; weight: number }
  | { sha256Hash: string; weight: number }
  | { preAuthTx: string; weight: number }
  | { ed25519SignedPayload: string; weight: number };

function signerForOperation(signer: SignerDefinition): StellarSignerOption {
  switch (signer.type) {
    case 'pre_auth_tx':
      return {
        preAuthTx: Buffer.from(StrKey.decodePreAuthTx(signer.key)).toString('hex'),
        weight: signer.weight,
      };
    case 'sha256_hash':
      return {
        sha256Hash: Buffer.from(StrKey.decodeSha256Hash(signer.key)).toString('hex'),
        weight: signer.weight,
      };
    case 'ed25519_signed_payload':
      return { ed25519SignedPayload: signer.key, weight: signer.weight };
    case 'ed25519_public_key':
    default:
      return { ed25519PublicKey: signer.key, weight: signer.weight };
  }
}

/** Converts one planner operation into a stellar-base SetOptions operation. */
function toStellarOperation(
  operation: SetOptionsOperation,
): ReturnType<typeof Operation.setOptions> {
  const signer = operation.signer ? signerForOperation(operation.signer) : undefined;
  return Operation.setOptions({
    ...(operation.masterWeight !== undefined ? { masterWeight: operation.masterWeight } : {}),
    ...(operation.lowThreshold !== undefined ? { lowThreshold: operation.lowThreshold } : {}),
    ...(operation.medThreshold !== undefined ? { medThreshold: operation.medThreshold } : {}),
    ...(operation.highThreshold !== undefined ? { highThreshold: operation.highThreshold } : {}),
    ...(signer !== undefined ? { signer } : {}),
  });
}

/** Builds the base64 transaction envelope for a valid rotation plan. */
export function buildRotationEnvelope(plan: RotationPlan, options: EnvelopeOptions = {}): string {
  if (!plan.valid) {
    throw new Error(`Cannot build an envelope for an unsafe rotation: ${plan.errors.join('; ')}`);
  }
  const sourceAccount = options.sourceAccount ?? plan.accountId;
  const sequence = options.sequence ?? '0';
  const account = new Account(sourceAccount, sequence);
  const builder = new TransactionBuilder(account, {
    fee: options.fee ?? BASE_FEE,
    networkPassphrase: options.networkPassphrase ?? Networks.PUBLIC,
  });
  for (const operation of plan.operations) builder.addOperation(toStellarOperation(operation));
  builder.setTimeout(options.timeoutSeconds ?? 0);
  return builder.build().toEnvelope().toXDR('base64');
}

/**
 * Simulates the rotation before signing.
 *
 * Without a remote endpoint this performs a structural dry run: the plan must
 * be valid and every intermediate state must have been recorded. With a
 * Soroban RPC URL it builds the envelope and calls `simulateTransaction`,
 * which is the same RPC flow anchor tooling uses before submitting contract
 * interactions.
 */
export async function simulateRotationPlan(
  plan: RotationPlan,
  options: RotationSimulationOptions = {},
): Promise<RotationSimulationResult> {
  if (!plan.valid) {
    return {
      success: false,
      error: `Rotation plan is unsafe: ${plan.errors.join('; ')}`,
    };
  }
  if (plan.intermediateStates.length !== plan.operations.length) {
    return {
      success: false,
      error: 'Rotation plan is missing intermediate state verification',
    };
  }
  if (plan.operations.length === 0) {
    return { success: true };
  }

  let envelopeXdr: string;
  try {
    envelopeXdr = buildRotationEnvelope(plan, {
      ...(options.sourceAccount !== undefined ? { sourceAccount: options.sourceAccount } : {}),
      ...(options.sequence !== undefined ? { sequence: options.sequence } : {}),
      ...(options.networkPassphrase !== undefined
        ? { networkPassphrase: options.networkPassphrase }
        : {}),
      ...(options.fee !== undefined ? { fee: options.fee } : {}),
    });
  } catch (error) {
    return { success: false, error: errorMessage(error) };
  }

  if (options.simulate) {
    try {
      return await options.simulate(envelopeXdr, plan);
    } catch (error) {
      return { success: false, envelopeXdr, error: errorMessage(error) };
    }
  }

  if (options.sorobanRpcUrl === undefined) {
    return { success: true, envelopeXdr };
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  try {
    const response = await fetchImpl(options.sorobanRpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: envelopeXdr },
      }),
    });
    if (!response.ok) {
      return {
        success: false,
        envelopeXdr,
        error: `Soroban RPC returned HTTP ${response.status}`,
      };
    }
    const body = (await response.json()) as Record<string, unknown>;
    const rpcError = asRecord(body.error);
    if (rpcError) {
      const message = isString(rpcError.message) ? rpcError.message : 'unknown RPC error';
      return { success: false, envelopeXdr, error: message, result: body };
    }
    const result = asRecord(body.result);
    if (result && result.error !== undefined) {
      return {
        success: false,
        envelopeXdr,
        error: isString(result.error) ? result.error : 'simulation failed',
        result: body,
      };
    }
    return { success: true, envelopeXdr, result: body };
  } catch (error) {
    return { success: false, envelopeXdr, error: errorMessage(error) };
  }
}

/** Formats a human-readable, safety-first transaction preview. */
export function formatRotationPreview(plan: RotationPlan): string {
  const lines: string[] = [];
  lines.push(`Signer rotation preview for ${plan.accountId}`);
  lines.push(
    `Current: low=${plan.current.thresholds.low} med=${plan.current.thresholds.medium} high=${plan.current.thresholds.high} master=${plan.current.thresholds.masterWeight}, ${plan.current.signers.length} additional signer(s)`,
  );
  lines.push(
    `Desired: low=${plan.desired.thresholds.low} med=${plan.desired.thresholds.medium} high=${plan.desired.thresholds.high} master=${plan.desired.thresholds.masterWeight}, ${plan.desired.signers.length} additional signer(s)`,
  );
  lines.push('');
  lines.push(`Operations (${plan.operations.length}):`);
  if (plan.operations.length === 0) lines.push('  (none)');
  plan.operations.forEach((operation, index) => {
    lines.push(`  ${index + 1}. ${describeOperation(operation)}`);
  });

  if (plan.warnings.length > 0) {
    lines.push('');
    lines.push('Safety warnings:');
    for (const warning of plan.warnings) lines.push(`  WARNING: ${warning}`);
  }

  if (plan.errors.length > 0) {
    lines.push('');
    lines.push('UNSAFE — do not sign this plan:');
    for (const error of plan.errors) lines.push(`  ERROR: ${error}`);
  } else {
    lines.push('');
    lines.push('All intermediate states satisfy the required quorum. Simulate before signing.');
  }

  return `${lines.join('\n')}\n`;
}

/** State-machine facade used by the CLI and by embedders. */
export class SignerRotationStateMachine {
  private readonly maxSigners: number;

  constructor(options: { maxSigners?: number } = {}) {
    this.maxSigners = options.maxSigners ?? MAX_ACCOUNT_SIGNERS;
  }

  ingestHorizonAccount(body: unknown, expectedAccountId?: string): AccountSignerState {
    return parseHorizonSignerState(body, expectedAccountId);
  }

  parseDesiredState(value: unknown, options: { accountId?: string } = {}): DesiredSignerState {
    return parseDesiredSignerState(value, options);
  }

  parseStateFile(source: string, path = ''): DesiredSignerState {
    return parseSignerStateFile(source, path);
  }

  plan(current: AccountSignerState, desired: DesiredSignerState): RotationPlan {
    return planSignerRotation(current, desired, { maxSigners: this.maxSigners });
  }

  buildEnvelope(plan: RotationPlan, options: EnvelopeOptions = {}): string {
    return buildRotationEnvelope(plan, options);
  }

  simulate(
    plan: RotationPlan,
    options: RotationSimulationOptions = {},
  ): Promise<RotationSimulationResult> {
    return simulateRotationPlan(plan, options);
  }

  preview(plan: RotationPlan): string {
    return formatRotationPreview(plan);
  }
}
