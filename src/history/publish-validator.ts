import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const HISTORY_MISSING_CATEGORY_ARCHIVE = 'history/missing-category-archive';
export const HISTORY_BROKEN_CHECKPOINT_CHAIN = 'history/broken-checkpoint-chain';
export const MISSING_CATEGORY_ARCHIVE_RULE = HISTORY_MISSING_CATEGORY_ARCHIVE;
export const BROKEN_CHECKPOINT_CHAIN_RULE = HISTORY_BROKEN_CHECKPOINT_CHAIN;

const CATEGORY_NAMES = ['ledger', 'transactions', 'results'] as const;
export type HistoryArchiveCategory = (typeof CATEGORY_NAMES)[number];
type ArchiveCategory = HistoryArchiveCategory;

export interface HistoryCheckpoint {
  sequence: number;
  hash?: string;
  ledgerHash?: string;
  previousLedgerHash?: string;
  previousHash?: string;
  previousLedger?: number;
  previousSequence?: number;
  files?: Partial<Record<ArchiveCategory, string | boolean>>;
}

export interface HistoryPublishOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  checkpoints?: readonly (HistoryCheckpoint | number | string)[];
  checkpointSequences?: readonly (HistoryCheckpoint | number | string)[];
  archiveUrl?: string;
  checkpointCount?: number;
  checkpointInterval?: number;
  requireGzip?: boolean;
  validatePayload?: (bytes: Uint8Array, response: Response) => boolean | Promise<boolean>;
  validateXdr?: (bytes: Uint8Array, response: Response) => boolean | Promise<boolean>;
  discovery?: (
    archiveUrl: string,
    fetchImpl: typeof fetch,
  ) =>
    | Promise<readonly (HistoryCheckpoint | number | string)[]>
    | readonly (HistoryCheckpoint | number | string)[];
}

interface ParsedCheckpoint {
  sequence: number;
  hash?: string;
  ledgerHash?: string;
  previousLedgerHash?: string;
  previousHash?: string;
  previousLedger?: number;
  previousSequence?: number;
  files?: Partial<Record<ArchiveCategory, string | boolean>>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function archiveBase(history: string): string | undefined {
  try {
    const url = new URL(history.replace(/\{[^}]*\}/g, ''));
    url.search = '';
    url.hash = '';
    url.pathname = `${url.pathname.replace(/\/+$/, '')}/`;
    return url.toString();
  } catch {
    return undefined;
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim());
  return undefined;
}

function sequenceFromString(value: string): number | undefined {
  const direct = numberValue(value);
  if (direct !== undefined) return direct;
  const match = /(?:^|[/_-])(\d+)(?:\.[a-z0-9]+)*$/i.exec(value);
  return match?.[1] === undefined ? undefined : Number(match[1]);
}

function filesFrom(value: unknown): ParsedCheckpoint['files'] {
  if (!isRecord(value)) return undefined;
  const files: Partial<Record<ArchiveCategory, string | boolean>> = {};
  for (const category of CATEGORY_NAMES) {
    const candidate = value[category] ?? value[`${category}File`];
    if (typeof candidate === 'string' || typeof candidate === 'boolean')
      files[category] = candidate;
  }
  return Object.keys(files).length > 0 ? files : undefined;
}

function checkpointFrom(value: unknown): ParsedCheckpoint | undefined {
  if (typeof value === 'number' || typeof value === 'string') {
    const sequence = sequenceFromString(String(value));
    return sequence === undefined ? undefined : { sequence };
  }
  if (!isRecord(value)) return undefined;
  const sequence =
    numberValue(value.sequence) ??
    numberValue(value.ledger) ??
    numberValue(value.ledgerSequence) ??
    numberValue(value.ledger_sequence) ??
    numberValue(value.ledger_seq) ??
    numberValue(value.number);
  if (sequence === undefined) return undefined;
  const hash =
    stringValue(value.hash) ??
    stringValue(value.ledgerHash) ??
    stringValue(value.ledger_hash) ??
    stringValue(value.rootHash);
  const previousLedgerHash =
    stringValue(value.previousLedgerHash) ??
    stringValue(value.previousHash) ??
    stringValue(value.parentHash) ??
    stringValue(value.previous_ledger_hash) ??
    stringValue(value.previous_ledger);
  const previousLedger =
    numberValue(value.previousLedger) ??
    numberValue(value.previousSequence) ??
    numberValue(value.previous_ledger);
  return {
    sequence,
    ...(hash === undefined ? {} : { hash }),
    ...(value.ledgerHash === undefined ? {} : { ledgerHash: stringValue(value.ledgerHash) }),
    ...(previousLedgerHash === undefined ? {} : { previousLedgerHash }),
    ...(previousLedger === undefined ? {} : { previousLedger }),
    ...(filesFrom(value.files) === undefined ? {} : { files: filesFrom(value.files) }),
  };
}

function collectCheckpoints(value: unknown, limit: number): ParsedCheckpoint[] {
  const found: ParsedCheckpoint[] = [];
  const visit = (candidate: unknown, depth = 0): void => {
    if (depth > 4 || found.length >= 10000) return;
    if (Array.isArray(candidate)) {
      for (const item of candidate) visit(item, depth + 1);
      return;
    }
    if (typeof candidate === 'string' || typeof candidate === 'number') {
      const checkpoint = checkpointFrom(candidate);
      if (checkpoint !== undefined) found.push(checkpoint);
      return;
    }
    if (!isRecord(candidate)) return;
    const direct = checkpointFrom(candidate);
    if (direct !== undefined) {
      found.push(direct);
      return;
    }
    for (const key of [
      'checkpoints',
      'checkpoint_sequences',
      'checkpointSequences',
      'sequences',
      'ledger_sequences',
      'ledgerSequences',
      'ledgers',
      'history',
    ]) {
      if (candidate[key] !== undefined) visit(candidate[key], depth + 1);
    }
  };
  visit(value);
  const unique = new Map<number, ParsedCheckpoint>();
  for (const checkpoint of found) unique.set(checkpoint.sequence, checkpoint);
  return [...unique.values()].sort((left, right) => left.sequence - right.sequence).slice(-limit);
}

function latestSequence(value: unknown): number | undefined {
  if (!isRecord(value)) return undefined;
  for (const key of [
    'latest_ledger',
    'latestLedger',
    'ledger_sequence',
    'ledgerSequence',
    'latest_sequence',
    'latestSequence',
    'ledger',
  ]) {
    const sequence = numberValue(value[key]);
    if (sequence !== undefined) return sequence;
  }
  return undefined;
}

async function readJson(url: string, fetchImpl: typeof fetch): Promise<unknown> {
  try {
    const response = await fetchImpl(url);
    if (!response.ok) return undefined;
    return (await response.json()) as unknown;
  } catch {
    return undefined;
  }
}

async function discoverCheckpoints(
  baseUrl: string,
  fetchImpl: typeof fetch,
  limit: number,
  discovery: HistoryPublishOptions['discovery'],
): Promise<ParsedCheckpoint[]> {
  if (discovery !== undefined) {
    return collectCheckpoints(await discovery(baseUrl, fetchImpl), limit);
  }

  const metadata = new URL('.well-known/stellar-history.json', baseUrl).toString();
  const metadataBody = await readJson(metadata, fetchImpl);
  const fromMetadata = collectCheckpoints(metadataBody, limit);
  if (fromMetadata.length > 0) return fromMetadata;

  const latest = latestSequence(metadataBody);
  if (latest !== undefined) {
    const first = latest - (limit - 1) * 64;
    return Array.from({ length: limit }, (_, index) => ({
      sequence: first + index * 64,
    })).filter((checkpoint) => checkpoint.sequence > 0);
  }

  const indexUrl = new URL('checkpoints.json', baseUrl).toString();
  const indexBody = await readJson(indexUrl, fetchImpl);
  const fromIndex = collectCheckpoints(indexBody, limit);
  if (fromIndex.length > 0) return fromIndex;

  try {
    const response = await fetchImpl(baseUrl);
    if (response.ok) {
      const text = await response.text();
      const links = [...text.matchAll(/(?:ledger|checkpoint)[-_/]?\d+[^\s"'<>]*/gi)].map(
        (match) => match[0],
      );
      return collectCheckpoints(links, limit);
    }
  } catch {
    return [];
  }
  return [];
}

function checkpointFiles(
  baseUrl: string,
  checkpoint: ParsedCheckpoint,
  category: ArchiveCategory,
): string[] {
  const explicit = checkpoint.files?.[category];
  if (typeof explicit === 'string') {
    return [new URL(explicit, baseUrl).toString()];
  }
  const filename = `${category}-${checkpoint.sequence}.xdr.gz`;
  const padded = `${category}-${String(checkpoint.sequence).padStart(12, '0')}.xdr.gz`;
  return [filename, padded, `${category}/${filename}`, `${category}/${padded}`].map((candidate) =>
    new URL(candidate, baseUrl).toString(),
  );
}

async function validPayload(
  bytes: Uint8Array,
  response: Response,
  options: HistoryPublishOptions,
): Promise<boolean> {
  if (bytes.length === 0) return false;
  const validator = options.validatePayload ?? options.validateXdr;
  if (validator !== undefined) {
    return validator(bytes, response);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('json')) {
    try {
      const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
      if (isRecord(value) && (value.valid === false || value.empty === true)) return false;
      return true;
    } catch {
      return false;
    }
  }
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  if (options.requireGzip && !gzip) return false;
  if (gzip) return bytes.length >= 10;
  return true;
}

async function archiveFileExists(
  baseUrl: string,
  checkpoint: ParsedCheckpoint,
  category: ArchiveCategory,
  fetchImpl: typeof fetch,
  options: HistoryPublishOptions,
): Promise<boolean> {
  const explicit = checkpoint.files?.[category];
  if (explicit === true) return true;
  for (const url of checkpointFiles(baseUrl, checkpoint, category)) {
    try {
      const response = await fetchImpl(url);
      if (!response.ok) continue;
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (await validPayload(bytes, response, options)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

function hashOf(checkpoint: ParsedCheckpoint): string | undefined {
  return checkpoint.hash ?? checkpoint.ledgerHash;
}

function previousHashOf(checkpoint: ParsedCheckpoint): string | undefined {
  return checkpoint.previousLedgerHash ?? checkpoint.previousHash;
}

function chainProblem(
  checkpoints: ParsedCheckpoint[],
  interval: number | undefined,
): string | undefined {
  if (checkpoints.length < 2) return undefined;
  const chainDataPresent = checkpoints.some(
    (checkpoint) =>
      hashOf(checkpoint) !== undefined ||
      previousHashOf(checkpoint) !== undefined ||
      checkpoint.previousLedger !== undefined,
  );
  if (!chainDataPresent) return undefined;

  for (let index = 1; index < checkpoints.length; index++) {
    const previous = checkpoints[index - 1];
    const current = checkpoints[index];
    if (previous === undefined || current === undefined) continue;
    const previousHash = hashOf(previous);
    const currentHash = previousHashOf(current);
    if (previousHash !== undefined && currentHash !== undefined && previousHash !== currentHash) {
      return `checkpoint ${current.sequence} points to ${currentHash}, expected ${previousHash}`;
    }
    if (previousHash !== undefined && currentHash === undefined) {
      return `checkpoint ${current.sequence} is missing its previous-ledger hash`;
    }
    if (current.previousLedger !== undefined && current.previousLedger !== previous.sequence) {
      return `checkpoint ${current.sequence} points to ledger ${current.previousLedger}, expected ${previous.sequence}`;
    }
    if (interval !== undefined && current.sequence - previous.sequence !== interval) {
      return `checkpoint ${current.sequence} is ${current.sequence - previous.sequence} ledgers after ${previous.sequence}, expected ${interval}`;
    }
  }
  return undefined;
}

function missingDiagnostic(
  path: string,
  message: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(HISTORY_MISSING_CATEGORY_ARCHIVE, 'error', rules);
  if (severity === undefined) return [];
  return [
    {
      rule: HISTORY_MISSING_CATEGORY_ARCHIVE,
      severity,
      category: 'validators',
      message: `${path} ${message}`,
      path,
      suggestion:
        'Publish complete ledger, transactions, and results archives for the latest three checkpoints.',
    },
  ];
}

function chainDiagnostic(
  path: string,
  message: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(HISTORY_BROKEN_CHECKPOINT_CHAIN, 'error', rules);
  if (severity === undefined) return [];
  return [
    {
      rule: HISTORY_BROKEN_CHECKPOINT_CHAIN,
      severity,
      category: 'validators',
      message: `${path} ${message}`,
      path,
      suggestion:
        'Rebuild the recent history checkpoints and preserve each previous-ledger pointer.',
    },
  ];
}

type HistoryFetchOrOptions =
  typeof fetch | HistoryPublishOptions | readonly (HistoryCheckpoint | number | string)[];

function isCheckpointArray(
  value: HistoryFetchOrOptions,
): value is readonly (HistoryCheckpoint | number | string)[] {
  return Array.isArray(value);
}

function normalizeOptions(
  fetchOrOptions: HistoryFetchOrOptions,
  options: HistoryPublishOptions,
): { fetchImpl: typeof fetch; options: HistoryPublishOptions } {
  if (typeof fetchOrOptions === 'function') {
    return { fetchImpl: fetchOrOptions, options };
  }
  if (isCheckpointArray(fetchOrOptions)) {
    return {
      fetchImpl: options.fetchImpl ?? fetch,
      options: { ...options, checkpoints: fetchOrOptions },
    };
  }
  return {
    fetchImpl: fetchOrOptions.fetchImpl ?? fetch,
    options: fetchOrOptions,
  };
}

export async function validateHistoryPublish(
  checkpointsInput: readonly (HistoryCheckpoint | number | string)[],
  options: HistoryPublishOptions = {},
): Promise<Diagnostic[]> {
  const limit = Math.max(1, options.checkpointCount ?? 3);
  const checkpoints = collectCheckpoints(checkpointsInput, limit);
  const baseUrl = options.archiveUrl === undefined ? undefined : archiveBase(options.archiveUrl);
  const fetchImpl = options.fetchImpl ?? fetch;
  const path = 'HISTORY';

  if (checkpoints.length < limit) {
    return missingDiagnostic(
      path,
      `contains only ${checkpoints.length} of the ${limit} recent checkpoints`,
      options.rules,
    );
  }
  if (baseUrl === undefined) {
    const explicitArchives = checkpoints.every((checkpoint) =>
      CATEGORY_NAMES.every((category) => checkpoint.files?.[category] === true),
    );
    if (!explicitArchives) {
      return missingDiagnostic(
        path,
        'does not provide a reachable archive base URL',
        options.rules,
      );
    }
  }

  const missing = new Set<ArchiveCategory>();
  for (const checkpoint of checkpoints) {
    for (const category of CATEGORY_NAMES) {
      if (baseUrl === undefined) continue;
      if (!(await archiveFileExists(baseUrl, checkpoint, category, fetchImpl, options))) {
        missing.add(category);
      }
    }
  }
  const diagnostics: Diagnostic[] = [];
  if (missing.size > 0) {
    diagnostics.push(
      ...missingDiagnostic(
        path,
        `is missing ${[...missing].join(', ')} category archive data`,
        options.rules,
      ),
    );
  }
  const chain = chainProblem(checkpoints, options.checkpointInterval);
  if (chain !== undefined) diagnostics.push(...chainDiagnostic(path, chain, options.rules));
  return diagnostics;
}

export function checkHistoryPublish(
  doc: Record<string, unknown>,
  fetchImpl?: typeof fetch,
  options?: HistoryPublishOptions,
): Promise<Diagnostic[]>;
export function checkHistoryPublish(
  doc: Record<string, unknown>,
  options?: HistoryPublishOptions,
): Promise<Diagnostic[]>;
export function checkHistoryPublish(
  doc: Record<string, unknown>,
  checkpoints: readonly (HistoryCheckpoint | number | string)[],
  options?: HistoryPublishOptions,
): Promise<Diagnostic[]>;
export function checkHistoryPublish(
  archiveUrl: string,
  fetchImpl?: typeof fetch,
  options?: HistoryPublishOptions,
): Promise<Diagnostic[]>;
export function checkHistoryPublish(
  archiveUrl: string,
  options?: HistoryPublishOptions,
): Promise<Diagnostic[]>;
export function checkHistoryPublish(
  archiveUrl: string,
  checkpoints: readonly (HistoryCheckpoint | number | string)[],
  options?: HistoryPublishOptions,
): Promise<Diagnostic[]>;
export async function checkHistoryPublish(
  input: Record<string, unknown> | string,
  fetchOrOptions: HistoryFetchOrOptions = fetch,
  options: HistoryPublishOptions = {},
): Promise<Diagnostic[]> {
  const { fetchImpl, options: effectiveOptions } = normalizeOptions(fetchOrOptions, options);
  if (typeof input === 'string') {
    const baseUrl = archiveBase(input);
    if (baseUrl === undefined) return [];
    const configuredCheckpoints =
      effectiveOptions.checkpoints ?? effectiveOptions.checkpointSequences;
    const found =
      configuredCheckpoints === undefined
        ? await discoverCheckpoints(
            baseUrl,
            fetchImpl,
            Math.max(1, effectiveOptions.checkpointCount ?? 3),
            effectiveOptions.discovery,
          )
        : collectCheckpoints(
            configuredCheckpoints,
            Math.max(1, effectiveOptions.checkpointCount ?? 3),
          );
    const result = await validateHistoryPublish(found, {
      ...effectiveOptions,
      fetchImpl,
      archiveUrl: baseUrl,
    });
    return result.map((diagnostic) => ({ ...diagnostic, path: diagnostic.path ?? 'HISTORY' }));
  }

  const validators = Array.isArray(input.VALIDATORS)
    ? input.VALIDATORS.filter((value): value is Record<string, unknown> => isRecord(value))
    : [];
  const diagnostics: Diagnostic[] = [];
  for (const [index, validator] of validators.entries()) {
    const history = stringValue(validator.HISTORY);
    const baseUrl = archiveBase(history ?? '');
    if (baseUrl === undefined) continue;
    const checkpoints = effectiveOptions.checkpoints ?? effectiveOptions.checkpointSequences;
    const archiveOptions: HistoryPublishOptions = {
      ...effectiveOptions,
      fetchImpl,
      archiveUrl: baseUrl,
      ...(checkpoints === undefined ? {} : { checkpoints }),
    };
    const found =
      checkpoints === undefined
        ? await discoverCheckpoints(
            baseUrl,
            fetchImpl,
            Math.max(1, effectiveOptions.checkpointCount ?? 3),
            effectiveOptions.discovery,
          )
        : collectCheckpoints(checkpoints, Math.max(1, effectiveOptions.checkpointCount ?? 3));
    const path = `VALIDATORS[${index}].HISTORY`;
    const result = await validateHistoryPublish(found, archiveOptions);
    diagnostics.push(
      ...result.map((diagnostic) => ({
        ...diagnostic,
        path,
      })),
    );
  }
  return diagnostics;
}

export const checkHistoryPublishValidator = checkHistoryPublish;
export const checkHistoryPublishState = checkHistoryPublish;
export const validateHistoryArchive = checkHistoryPublish;

export const historyPublishRules: Rule[] = [
  {
    id: HISTORY_MISSING_CATEGORY_ARCHIVE,
    category: 'validators',
    severity: 'error',
    description:
      'History archives must publish complete category data for the latest three checkpoints',
    run() {},
  },
  {
    id: HISTORY_BROKEN_CHECKPOINT_CHAIN,
    category: 'validators',
    severity: 'error',
    description: 'History checkpoint hashes must form an unbroken previous-ledger chain',
    run() {},
  },
];

export const historyPublishRuleIds: readonly string[] = historyPublishRules.map((rule) => rule.id);
