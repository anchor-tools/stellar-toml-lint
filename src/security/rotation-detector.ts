/**
 * Cold-storage signing-key rotation and stellar.toml desynchronization detector.
 *
 * Anchors rotate cold-storage keys periodically. Horizon records each
 * `set_options` operation that changes the master weight or a signer, but
 * stellar.toml has no timestamp of its own. If the file is not republished
 * within 24 hours of an on-chain rotation, wallets keep advertising and
 * trusting the old key and reject transactions signed with the new one.
 *
 * This auditor reconstructs the rotation timeline for `SIGNING_KEY` and each
 * declared issuer account from Horizon `/operations` over the last 90 days,
 * then compares the newest rotation with the time stellar.toml was last
 * updated. A missing update time degrades to silence; only an actual
 * desynchronization is reported.
 */
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { horizonUrlFor } from '../network-checks.js';
import { isAccountId, isString } from '../predicates.js';

export const STALE_SIGNING_KEY_POST_ROTATION_RULE = 'security/stale-signing-key-post-rotation';
export const UNRECORDED_SIGNER_ADDITION_RULE = 'security/unrecorded-signer-addition';
export const SECURITY_STALE_SIGNING_KEY_POST_ROTATION = STALE_SIGNING_KEY_POST_ROTATION_RULE;
export const SECURITY_UNRECORDED_SIGNER_ADDITION = UNRECORDED_SIGNER_ADDITION_RULE;
export const STALE_SIGNING_KEY_RULE = STALE_SIGNING_KEY_POST_ROTATION_RULE;

/** Rotations older than this are outside the audit window. */
export const ROTATION_WINDOW_DAYS = 90;
/** stellar.toml must be republished within this long after a rotation. */
export const ROTATION_SYNC_GRACE_MS = 24 * 60 * 60 * 1000;

export interface HorizonOperation {
  type?: unknown;
  created_at?: unknown;
  source_account?: unknown;
  signer_key?: unknown;
  signer_weight?: unknown;
  master_key_weight?: unknown;
  low_threshold?: unknown;
  med_threshold?: unknown;
  high_threshold?: unknown;
  [key: string]: unknown;
}

export interface KeyRotationEvent {
  account: string;
  /** Dotted path to the account declaration in stellar.toml. */
  path: string;
  occurredAt: Date;
  /** New or removed signer key, when the operation names one. */
  signerKey?: string;
  /** Signer weight after the operation; 0 means removal. */
  signerWeight?: number;
  /** Master key weight after the operation. */
  masterKeyWeight?: number;
}

export interface AccountOperations {
  account: string;
  path: string;
  operations: readonly HorizonOperation[];
}

export interface RotationDetectorOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  horizonUrl?: string;
  /** "Now" for deterministic tests. */
  now?: Date | number | string;
  /** How far back to scan Horizon operations. Defaults to 90 days. */
  windowDays?: number;
  /** When stellar.toml was last published. */
  tomlUpdatedAt?: Date | number | string;
  /** Alias for {@link tomlUpdatedAt}, named after the HTTP header. */
  lastModified?: Date | number | string;
  /** Domain whose /.well-known/stellar.toml supplies Last-Modified. */
  domain?: string;
  /** Explicit stellar.toml URL to HEAD when no timestamp was supplied. */
  tomlUrl?: string;
}

function parseDate(value: unknown): Date | undefined {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? undefined : value;
  if (typeof value === 'number') {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function timeOf(value: unknown): Date | undefined {
  return parseDate(value);
}

/** True for a `set_options` operation that actually changed a key or weight. */
function isKeyRotationOperation(operation: HorizonOperation): boolean {
  if (operation.type !== 'set_options') return false;
  const hasSigner = isString(operation.signer_key);
  const hasMaster = typeof operation.master_key_weight === 'number';
  return hasSigner || hasMaster;
}

/** Converts Horizon operations into a normalized rotation timeline. */
export function rotationEventsFromOperations(
  accountOrOperations: string | readonly HorizonOperation[],
  operationsOrAccount?: readonly HorizonOperation[] | string,
  maybePath?: string,
): KeyRotationEvent[] {
  const account =
    typeof accountOrOperations === 'string'
      ? accountOrOperations
      : typeof operationsOrAccount === 'string'
        ? operationsOrAccount
        : 'SIGNING_KEY';
  const operations = Array.isArray(accountOrOperations)
    ? accountOrOperations
    : ((operationsOrAccount as readonly HorizonOperation[] | undefined) ?? []);
  const path =
    typeof operationsOrAccount === 'string' ? (maybePath ?? account) : (maybePath ?? account);
  const events: KeyRotationEvent[] = [];
  for (const operation of operations) {
    if (!isKeyRotationOperation(operation)) continue;
    const occurredAt = timeOf(operation.created_at);
    if (occurredAt === undefined) continue;
    events.push({
      account,
      path,
      occurredAt,
      ...(isString(operation.signer_key) ? { signerKey: operation.signer_key } : {}),
      ...(typeof operation.signer_weight === 'number'
        ? { signerWeight: operation.signer_weight }
        : {}),
      ...(typeof operation.master_key_weight === 'number'
        ? { masterKeyWeight: operation.master_key_weight }
        : {}),
    });
  }
  return events.sort((a, b) => a.occurredAt.getTime() - b.occurredAt.getTime());
}

export interface RotationAnalysisInput {
  signingKey?: string;
  /** Accounts declared as issuers in `[[CURRENCIES]]`. */
  issuers?: { account: string; path: string }[];
  /** Signer keys explicitly declared by the document (SIGNING_KEY, ACCOUNTS). */
  declaredSigners?: readonly string[];
  /** Operations keyed by account, or a flat list for a single account. */
  accounts?: readonly AccountOperations[];
  operations?: readonly HorizonOperation[];
  tomlUpdatedAt?: Date | number | string;
  now?: Date | number | string;
  windowDays?: number;
}

function accountRotationEvents(
  input: RotationAnalysisInput,
  now: Date,
  windowDays: number,
): KeyRotationEvent[] {
  const cutoff = now.getTime() - windowDays * 24 * 60 * 60 * 1000;
  const events: KeyRotationEvent[] = [];

  if (input.accounts !== undefined) {
    for (const account of input.accounts) {
      events.push(
        ...rotationEventsFromOperations(account.account, account.operations, account.path),
      );
    }
  } else if (input.operations !== undefined) {
    const account = input.signingKey ?? input.issuers?.[0]?.account ?? 'SIGNING_KEY';
    const path =
      input.signingKey !== undefined ? 'SIGNING_KEY' : (input.issuers?.[0]?.path ?? 'SIGNING_KEY');
    events.push(...rotationEventsFromOperations(account, input.operations, path));
  }

  return events.filter((event) => event.occurredAt.getTime() >= cutoff);
}

function diagnostic(
  rule: string,
  severity: Severity,
  message: string,
  path: string,
  suggestion: string,
): Diagnostic {
  return { rule, severity, category: 'network', message, path, suggestion };
}

/**
 * Pure rotation-timeline analysis. Exposed so callers and tests can evaluate
 * recorded Horizon operations without making a request.
 *
 * A stale-key error is emitted when the newest rotation in the window is not
 * followed by a stellar.toml update within {@link ROTATION_SYNC_GRACE_MS}.
 * Signer additions that do not appear in the document emit the unrecorded
 * warning.
 */
export function analyzeKeyRotations(
  input: RotationAnalysisInput | readonly HorizonOperation[],
  options: RotationDetectorOptions = {},
): Diagnostic[] {
  if (Array.isArray(input)) {
    return analyzeKeyRotations({ operations: input as readonly HorizonOperation[] }, options);
  }
  const request = input as RotationAnalysisInput;
  const diagnostics: Diagnostic[] = [];
  const now = parseDate(request.now ?? options.now) ?? new Date();
  const windowDays = request.windowDays ?? options.windowDays ?? ROTATION_WINDOW_DAYS;
  const events = accountRotationEvents(request, now, windowDays);
  if (events.length === 0) return diagnostics;

  const tomlUpdatedAt = parseDate(
    request.tomlUpdatedAt ?? options.tomlUpdatedAt ?? options.lastModified,
  );
  const latest = events[events.length - 1] as KeyRotationEvent;

  let staleReported = false;
  if (tomlUpdatedAt !== undefined) {
    const delay = tomlUpdatedAt.getTime() - latest.occurredAt.getTime();
    if (delay < 0 || delay > ROTATION_SYNC_GRACE_MS) {
      const severity = severityFor(STALE_SIGNING_KEY_POST_ROTATION_RULE, 'error', options.rules);
      if (severity !== undefined) {
        const when = latest.occurredAt.toISOString();
        const update =
          delay < 0
            ? `stellar.toml was last updated ${tomlUpdatedAt.toISOString()}, before the rotation`
            : `stellar.toml was not updated until ${(delay / 3_600_000).toFixed(1)} hours after the rotation`;
        diagnostics.push(
          diagnostic(
            STALE_SIGNING_KEY_POST_ROTATION_RULE,
            severity,
            `${latest.path} had an on-chain key rotation at ${when}, but ${update}`,
            latest.path,
            'Republish stellar.toml with the rotated key immediately, then purge caches and CDNs so wallets see it.',
          ),
        );
        staleReported = true;
      }
    }
  }

  // Without an HTTP timestamp, a signer change on the SIGNING_KEY account is
  // still enough to see that the advertised key no longer matches the chain.
  if (
    !staleReported &&
    tomlUpdatedAt === undefined &&
    request.signingKey !== undefined &&
    latest.account === request.signingKey
  ) {
    const replacedSigner =
      latest.signerKey !== undefined &&
      latest.signerKey !== request.signingKey &&
      (latest.signerWeight ?? 0) > 0;
    const disabledMaster = latest.masterKeyWeight === 0;
    if (replacedSigner || disabledMaster) {
      const severity = severityFor(STALE_SIGNING_KEY_POST_ROTATION_RULE, 'error', options.rules);
      if (severity !== undefined) {
        const detail = replacedSigner
          ? `a different on-chain signer (${latest.signerKey}) than SIGNING_KEY (${request.signingKey})`
          : 'a disabled master key that SIGNING_KEY still advertises';
        diagnostics.push(
          diagnostic(
            STALE_SIGNING_KEY_POST_ROTATION_RULE,
            severity,
            `${latest.path} has ${detail} as of ${latest.occurredAt.toISOString()}`,
            latest.path,
            'Publish the current signing key in stellar.toml; the file is stale relative to the on-chain rotation.',
          ),
        );
      }
    }
  }

  const declared = new Set<string>();
  if (request.signingKey !== undefined) declared.add(request.signingKey);
  for (const issuer of request.issuers ?? []) declared.add(issuer.account);
  for (const signer of request.declaredSigners ?? []) declared.add(signer);

  if (declared.size > 0) {
    for (const event of events) {
      if (event.signerKey === undefined || event.signerWeight === undefined) continue;
      if (event.signerWeight <= 0) continue;
      if (declared.has(event.signerKey)) continue;
      const severity = severityFor(UNRECORDED_SIGNER_ADDITION_RULE, 'warning', options.rules);
      if (severity === undefined) continue;
      diagnostics.push(
        diagnostic(
          UNRECORDED_SIGNER_ADDITION_RULE,
          severity,
          `${event.path} added signer ${event.signerKey} on-chain at ${event.occurredAt.toISOString()}, but stellar.toml does not advertise it`,
          event.path,
          'Publish the new signer once it is an intended operational key, or remove it on-chain if the addition was unauthorized.',
        ),
      );
    }
  }

  return diagnostics;
}

export const analyzeRotationTimeline = analyzeKeyRotations;
export const detectKeyRotation = analyzeKeyRotations;

function issuerAccountsOf(doc: Record<string, unknown>): { account: string; path: string }[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  const accounts: { account: string; path: string }[] = [];
  currencies.forEach((raw, index) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return;
    const entry = raw as Record<string, unknown>;
    if (isString(entry.issuer) && isAccountId(entry.issuer)) {
      accounts.push({ account: entry.issuer, path: `CURRENCIES[${index}].issuer` });
    }
  });
  return accounts;
}

function declaredSignersOf(doc: Record<string, unknown>): string[] {
  const signers: string[] = [];
  if (isString(doc.SIGNING_KEY)) signers.push(doc.SIGNING_KEY);
  if (Array.isArray(doc.ACCOUNTS)) {
    for (const account of doc.ACCOUNTS) {
      if (isString(account)) signers.push(account);
    }
  }
  return signers;
}

async function fetchOperations(
  account: string,
  horizonUrl: string,
  fetchImpl: typeof fetch,
  cutoff: Date,
  maxPages = 10,
): Promise<HorizonOperation[]> {
  const base = horizonUrl.replace(/\/+$/, '');
  let url: string | undefined =
    `${base}/accounts/${encodeURIComponent(account)}/operations?order=desc&limit=200`;
  const operations: HorizonOperation[] = [];

  for (let page = 0; page < maxPages && url !== undefined; page++) {
    let response: Response;
    try {
      response = await fetchImpl(url);
    } catch {
      return operations;
    }
    if (!response.ok) return operations;

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return operations;
    }

    const records = Array.isArray(body)
      ? body
      : ((body as { _embedded?: { records?: unknown[] } })._embedded?.records ?? []);
    if (!Array.isArray(records) || records.length === 0) break;

    let reachedOlder = false;
    for (const record of records) {
      if (typeof record !== 'object' || record === null || Array.isArray(record)) continue;
      const operation = record as HorizonOperation;
      operations.push(operation);
      const createdAt = timeOf(operation.created_at);
      if (createdAt !== undefined && createdAt.getTime() < cutoff.getTime()) reachedOlder = true;
    }

    const next =
      typeof body === 'object' && body !== null && !Array.isArray(body)
        ? (body as { _links?: { next?: { href?: unknown } } })._links?.next?.href
        : undefined;
    if (reachedOlder || records.length < 200 || !isString(next)) break;
    url = next;
  }

  return operations;
}

async function fetchTomlLastModified(
  options: RotationDetectorOptions,
  fetchImpl: typeof fetch,
): Promise<Date | undefined> {
  const explicit = parseDate(options.tomlUpdatedAt ?? options.lastModified);
  if (explicit !== undefined) return explicit;
  if (options.tomlUrl === undefined && options.domain === undefined) return undefined;

  const url =
    options.tomlUrl ??
    `https://${(options.domain as string).replace(/^https?:\/\//, '').replace(/\/+$/, '')}/.well-known/stellar.toml`;
  try {
    const response = await fetchImpl(url, { method: 'HEAD' });
    if (!response.ok) return undefined;
    return parseDate(response.headers.get('last-modified'));
  } catch {
    return undefined;
  }
}

/**
 * Fetches the account operation history from Horizon and audits rotation
 * synchronization. Network failures degrade to no findings, never a crash.
 */
export async function checkKeyRotation(
  doc: Record<string, unknown>,
  fetchImplOrOptions: typeof fetch | RotationDetectorOptions = fetch,
  maybeOptions: RotationDetectorOptions = {},
): Promise<Diagnostic[]> {
  const options = typeof fetchImplOrOptions === 'function' ? maybeOptions : fetchImplOrOptions;
  const fetchImpl =
    typeof fetchImplOrOptions === 'function'
      ? fetchImplOrOptions
      : (fetchImplOrOptions.fetchImpl ?? fetch);
  const signingKey = isString(doc.SIGNING_KEY) ? doc.SIGNING_KEY : undefined;
  const issuers = issuerAccountsOf(doc);

  const accounts: { account: string; path: string }[] = [];
  if (signingKey !== undefined) accounts.push({ account: signingKey, path: 'SIGNING_KEY' });
  for (const issuer of issuers) accounts.push(issuer);

  if (accounts.length === 0) return [];

  const now = parseDate(options.now) ?? new Date();
  const windowDays = options.windowDays ?? ROTATION_WINDOW_DAYS;
  const cutoff = new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);
  const passphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);

  const histories: AccountOperations[] = [];
  for (const account of accounts) {
    const operations = await fetchOperations(account.account, horizonUrl, fetchImpl, cutoff);
    if (operations.length > 0) histories.push({ ...account, operations });
  }

  if (histories.length === 0) return [];

  const tomlUpdatedAt = await fetchTomlLastModified(options, fetchImpl);

  return analyzeKeyRotations(
    {
      ...(signingKey === undefined ? {} : { signingKey }),
      issuers,
      declaredSigners: declaredSignersOf(doc),
      accounts: histories,
      ...(tomlUpdatedAt === undefined ? {} : { tomlUpdatedAt }),
      now,
      windowDays,
    },
    options,
  );
}

export const checkKeyRotationSynchronization = checkKeyRotation;
export const checkSigningKeyRotation = checkKeyRotation;
export const detectKeyRotationHistory = checkKeyRotation;
export const checkRotation = checkKeyRotation;
export const rotationDetector = checkKeyRotation;
export const checkRotationDetector = checkKeyRotation;
export const checkRotationSynchronization = checkKeyRotation;

/** Rule objects registered for `--list-rules` and severity overrides. */
export const rotationDetectorRules: Rule[] = [
  {
    id: STALE_SIGNING_KEY_POST_ROTATION_RULE,
    category: 'network',
    severity: 'error',
    description: 'stellar.toml must be updated within 24 hours of an on-chain signing-key rotation',
    run() {},
  },
  {
    id: UNRECORDED_SIGNER_ADDITION_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Signers added on-chain should be reflected in stellar.toml',
    run() {},
  },
];

export const keyRotationRules = rotationDetectorRules;
export const rotationRules = rotationDetectorRules;
export const keyRotationDetectorRules = rotationDetectorRules;
export const rotationDetectorRuleIds: readonly string[] = rotationDetectorRules.map(
  (rule) => rule.id,
);
