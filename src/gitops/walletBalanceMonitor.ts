/**
 * Operational hot wallet balance monitoring for anchors.
 *
 * Anchors move money continuously: withdrawals, fee payments, and sponsored
 * reserves all draw down the same handful of hot wallets. When one of those
 * wallets crosses the Stellar minimum reserve the next operation fails with
 * `op_underfunded`, which often surfaces to end users as a stalled withdrawal
 * rather than as an infrastructure error.
 *
 * This module polls Horizon, computes the *spendable* balance (the native
 * balance minus the reserves the account is required to hold), projects a burn
 * rate from recent activity, and raises a low-watermark alert before the
 * account becomes unusable.
 */
import { isInteger, isString } from '../predicates.js';

/** Seven decimal places, the smallest unit of a classic Stellar asset. */
export const STROOPS_PER_XLM = 10_000_000;

/** Stellar's base reserve, in XLM. Governance can change this on-chain. */
export const DEFAULT_BASE_RESERVE_XLM = 0.5;

/** How far back activity is sampled when estimating burn rate. */
export const DEFAULT_LOOKBACK_HOURS = 24 * 7;

/** Default polling cadence for the daemon. */
export const DEFAULT_POLL_INTERVAL_MS = 60_000;

export type WalletRole = 'hot-wallet' | 'distribution' | 'signing-key' | 'account';

/** An account discovered in `stellar.toml`, with the path it came from. */
export interface WalletDeclaration {
  account: string;
  role: WalletRole;
  path: string;
}

export interface HorizonBalance {
  asset_type: string;
  balance: string;
  limit?: string;
  buying_liabilities?: string;
  selling_liabilities?: string;
  asset_code?: string;
  asset_issuer?: string;
  is_authorized?: boolean;
}

/** The subset of a Horizon account record this monitor needs. */
export interface HorizonAccountRecord {
  id?: string;
  account_id?: string;
  subentry_count?: number;
  num_sponsoring?: number;
  num_sponsored?: number;
  balances: HorizonBalance[];
}

/** A payment or transaction record from Horizon's account history. */
export interface HorizonActivityRecord {
  id?: string;
  type?: string;
  created_at?: string;
  amount?: string;
  asset_type?: string;
  source_amount?: string;
  source_asset_type?: string;
  from?: string;
  to?: string;
  source_account?: string;
  fee_charged?: string;
}

export interface TrustlineBalance {
  assetType: string;
  code?: string;
  issuer?: string;
  balance: number;
  limit: number | null;
  available: number;
  authorized: boolean;
}

export interface ReserveBreakdown {
  baseReserveXlm: number;
  reserveUnits: number;
  baseReserves: number;
  subentryReserves: number;
  sponsorshipCredits: number;
  trustlineCount: number;
  minimumXlm: number;
}

export interface BurnRateEstimate {
  lookbackHours: number;
  spentXlm: number;
  outgoingCount: number;
  activityCount: number;
  burnRatePerHour: number;
  burnRatePerDay: number;
}

export type WalletStatus = 'ok' | 'warning' | 'critical' | 'depleted';

export type WalletAlertCode =
  'wallet/depleted' | 'wallet/below-minimum' | 'wallet/low-watermark' | 'wallet/low-runway';

export interface WalletAlert {
  code: WalletAlertCode;
  level: 'warning' | 'critical';
  message: string;
}

export interface WalletBalanceReport {
  account: string;
  checkedAt: string;
  nativeBalance: number;
  minimumReserve: number;
  availableXlm: number;
  sellingLiabilities: number;
  reserves: ReserveBreakdown;
  trustlines: TrustlineBalance[];
  burnRate: BurnRateEstimate;
  /** `null` means no measurable spend, so the wallet will never run out. */
  runwayHours: number | null;
  runwayDays: number | null;
  status: WalletStatus;
  alerts: WalletAlert[];
}

export interface WalletThresholds {
  /** Spendable XLM below which the wallet is critical. */
  minXlm: number;
  /** Spendable XLM below which the wallet is a warning. Defaults to `minXlm`. */
  warnXlm?: number;
  /** Alert when the projected runway falls below this. */
  minRunwayHours?: number;
  /** Stellar base reserve in XLM. */
  baseReserveXlm?: number;
}

export interface HotWalletMonitorOptions extends WalletThresholds {
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
  lookbackHours?: number;
  pollIntervalMs?: number;
  webhookUrl?: string;
  /** Receives human-readable alert lines. Defaults to silence. */
  logger?: (line: string) => void;
  now?: () => Date;
  maxIterations?: number;
}

export interface MonitorRunOptions {
  once?: boolean;
  intervalMs?: number;
  signal?: AbortSignal;
  onReport?: (report: WalletBalanceReport) => void;
  maxIterations?: number;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function numberFrom(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (!isString(value) || value.trim() === '') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function nonNegativeInteger(value: unknown): number {
  const parsed = numberFrom(value);
  if (parsed === undefined || parsed < 0) return 0;
  return Math.floor(parsed);
}

function normalizeHorizonUrl(value: string | undefined): string {
  return (value ?? 'https://horizon.stellar.org').replace(/\/+$/, '');
}

function accountIdOf(record: HorizonAccountRecord): string {
  return record.account_id ?? record.id ?? 'unknown';
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Extracts accounts the operator has declared in `stellar.toml`.
 *
 * SEP-1 itself only standardises `SIGNING_KEY` and `ACCOUNTS`; anchors commonly
 * add `HOT_WALLETS`, `OPERATIONAL_WALLETS`, `DISTRIBUTION_ACCOUNTS`, or a
 * `distribution_account` on each `[[CURRENCIES]]` entry, so all are recognised.
 * Duplicate declarations keep the first, most specific role.
 */
export function parseWalletDeclarations(doc: Record<string, unknown>): WalletDeclaration[] {
  const declarations = new Map<string, WalletDeclaration>();

  const add = (account: unknown, role: WalletRole, path: string): void => {
    if (!isString(account) || account.trim() === '') return;
    const trimmed = account.trim();
    if (!declarations.has(trimmed)) declarations.set(trimmed, { account: trimmed, role, path });
  };

  const addList = (value: unknown, role: WalletRole, field: string): void => {
    if (!Array.isArray(value)) return;
    value.forEach((entry, index) => {
      if (isString(entry)) {
        add(entry, role, `${field}[${index}]`);
        return;
      }
      const table = asRecord(entry);
      if (!table) return;
      const account =
        table.account ?? table.ACCOUNT ?? table.public_key ?? table.PUBLIC_KEY ?? table.address;
      add(account, role, `${field}[${index}]`);
    });
  };

  add(doc.SIGNING_KEY, 'signing-key', 'SIGNING_KEY');
  addList(doc.ACCOUNTS, 'account', 'ACCOUNTS');
  addList(doc.HOT_WALLETS, 'hot-wallet', 'HOT_WALLETS');
  addList(doc.OPERATIONAL_WALLETS, 'hot-wallet', 'OPERATIONAL_WALLETS');
  addList(doc.DISTRIBUTION_ACCOUNTS, 'distribution', 'DISTRIBUTION_ACCOUNTS');
  addList(doc.WALLETS, 'hot-wallet', 'WALLETS');

  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      const currency = asRecord(entry);
      if (!currency) return;
      add(
        currency.distribution_account ?? currency.DISTRIBUTION_ACCOUNT,
        'distribution',
        `CURRENCIES[${index}].distribution_account`,
      );
    });
  }

  return [...declarations.values()];
}

function trustlinesOf(record: HorizonAccountRecord): TrustlineBalance[] {
  const trustlines: TrustlineBalance[] = [];
  for (const balance of record.balances) {
    if (balance.asset_type === 'native') continue;
    const amount = numberFrom(balance.balance) ?? 0;
    const limit = numberFrom(balance.limit);
    const selling = numberFrom(balance.selling_liabilities) ?? 0;
    trustlines.push({
      assetType: balance.asset_type,
      ...(balance.asset_code ? { code: balance.asset_code } : {}),
      ...(balance.asset_issuer ? { issuer: balance.asset_issuer } : {}),
      balance: amount,
      limit: limit ?? null,
      available: limit === undefined ? 0 : Math.max(0, limit - amount - selling),
      authorized: balance.is_authorized !== false,
    });
  }
  return trustlines;
}

/**
 * Computes the minimum native balance Horizon enforces for an account.
 *
 * Stellar reserves two base reserves for the account itself, one per
 * subentry (trustlines, offers, data entries, additional signers), and net
 * sponsorship units. Trustlines are already included in `subentry_count`; they
 * are counted separately only for reporting.
 */
export function calculateMinimumReserve(
  record: HorizonAccountRecord,
  baseReserveXlm: number = DEFAULT_BASE_RESERVE_XLM,
): ReserveBreakdown {
  const baseReserve = Number.isFinite(baseReserveXlm) && baseReserveXlm >= 0 ? baseReserveXlm : 0.5;
  const subentries = nonNegativeInteger(record.subentry_count);
  const sponsoring = nonNegativeInteger(record.num_sponsoring);
  const sponsored = nonNegativeInteger(record.num_sponsored);
  const trustlines = trustlinesOf(record);
  const reserveUnits = Math.max(0, 2 + subentries + sponsoring - sponsored);

  return {
    baseReserveXlm: baseReserve,
    reserveUnits,
    baseReserves: 2,
    subentryReserves: subentries,
    sponsorshipCredits: sponsored - sponsoring,
    trustlineCount: trustlines.length,
    minimumXlm: reserveUnits * baseReserve,
  };
}

/** Native balance, selling liabilities, and the amount that can actually be spent. */
export function nativeBalanceOf(record: HorizonAccountRecord): {
  balance: number;
  sellingLiabilities: number;
} {
  const native = record.balances.find((entry) => entry.asset_type === 'native');
  return {
    balance: numberFrom(native?.balance) ?? 0,
    sellingLiabilities: numberFrom(native?.selling_liabilities) ?? 0,
  };
}

function outgoingNativeAmount(record: HorizonActivityRecord, account: string): number | undefined {
  const source = record.from ?? record.source_account;
  if (source !== account) return undefined;

  const type = record.type ?? '';
  const isPathPayment = type.startsWith('path_payment');
  if (isPathPayment) {
    if (record.source_asset_type === 'native') return numberFrom(record.source_amount);
    return undefined;
  }

  if (record.asset_type === 'native' || type === 'create_account' || type === 'account_merge') {
    return numberFrom(record.amount);
  }
  return undefined;
}

/**
 * Estimates spend from outbound native payments in the lookback window.
 *
 * Horizon's payment history does not include a transaction's fee, but activity
 * records that do carry `fee_charged` are included so callers can pass
 * transaction records instead of payments without understating the burn.
 */
export function calculateBurnRate(
  records: readonly HorizonActivityRecord[],
  account: string,
  options: { now?: Date; lookbackHours?: number } = {},
): BurnRateEstimate {
  const lookbackHours =
    options.lookbackHours !== undefined &&
    Number.isFinite(options.lookbackHours) &&
    options.lookbackHours > 0
      ? options.lookbackHours
      : DEFAULT_LOOKBACK_HOURS;
  const now = options.now ?? new Date();
  const cutoff = now.getTime() - lookbackHours * 60 * 60 * 1000;

  let spentXlm = 0;
  let outgoingCount = 0;
  let activityCount = 0;
  const seenFees = new Set<string>();

  for (const record of records) {
    const createdAt = record.created_at ? Date.parse(record.created_at) : Number.NaN;
    if (!Number.isFinite(createdAt) || createdAt < cutoff || createdAt > now.getTime()) continue;
    activityCount += 1;

    const amount = outgoingNativeAmount(record, account);
    if (amount !== undefined) {
      spentXlm += Math.max(0, amount);
      outgoingCount += 1;
    }

    if ((record.source_account ?? record.from) === account && record.fee_charged !== undefined) {
      // A transaction can appear once in Horizon, but guard against callers
      // concatenating overlapping result pages so fees are not double-counted.
      const key = record.id ?? `${createdAt}:${record.fee_charged}`;
      if (!seenFees.has(key)) {
        seenFees.add(key);
        spentXlm += Math.max(0, numberFrom(record.fee_charged) ?? 0) / STROOPS_PER_XLM;
      }
    }
  }

  const burnRatePerHour = spentXlm / lookbackHours;
  return {
    lookbackHours,
    spentXlm,
    outgoingCount,
    activityCount,
    burnRatePerHour,
    burnRatePerDay: burnRatePerHour * 24,
  };
}

/**
 * Assesses a Horizon account snapshot against the configured thresholds.
 *
 * The comparison uses spendable XLM, not the headline balance: an account
 * holding 5 XLM with a 5 XLM reserve cannot pay a single withdrawal.
 */
export function assessWalletBalance(
  record: HorizonAccountRecord,
  activity: readonly HorizonActivityRecord[] = [],
  options: WalletThresholds & { now?: Date; lookbackHours?: number } = { minXlm: 0 },
): WalletBalanceReport {
  const account = accountIdOf(record);
  const now = options.now ?? new Date();
  const reserves = calculateMinimumReserve(record, options.baseReserveXlm);
  const native = nativeBalanceOf(record);
  const availableXlm = Math.max(
    0,
    native.balance - reserves.minimumXlm - native.sellingLiabilities,
  );
  const burnRate = calculateBurnRate(activity, account, {
    now,
    ...(options.lookbackHours !== undefined ? { lookbackHours: options.lookbackHours } : {}),
  });
  const runwayHours =
    availableXlm <= 0
      ? 0
      : burnRate.burnRatePerHour > 0
        ? availableXlm / burnRate.burnRatePerHour
        : null;
  const runwayDays = runwayHours === null ? null : runwayHours / 24;

  const minXlm = Number.isFinite(options.minXlm) ? Math.max(0, options.minXlm) : 0;
  const warnXlm =
    options.warnXlm !== undefined && Number.isFinite(options.warnXlm)
      ? Math.max(minXlm, options.warnXlm)
      : minXlm;

  const alerts: WalletAlert[] = [];
  if (native.balance <= 0 || availableXlm <= 0) {
    alerts.push({
      code: 'wallet/depleted',
      level: 'critical',
      message: `Account ${account} has no spendable XLM (${native.balance.toFixed(7)} XLM total, ${reserves.minimumXlm.toFixed(7)} XLM reserved)`,
    });
  } else if (availableXlm < minXlm) {
    alerts.push({
      code: 'wallet/below-minimum',
      level: 'critical',
      message: `Account ${account} has ${availableXlm.toFixed(7)} spendable XLM, below the minimum of ${minXlm}`,
    });
  } else if (availableXlm < warnXlm) {
    alerts.push({
      code: 'wallet/low-watermark',
      level: 'warning',
      message: `Account ${account} has ${availableXlm.toFixed(7)} spendable XLM, approaching the minimum of ${minXlm}`,
    });
  }

  if (
    options.minRunwayHours !== undefined &&
    Number.isFinite(options.minRunwayHours) &&
    options.minRunwayHours > 0 &&
    runwayHours !== null &&
    runwayHours < options.minRunwayHours
  ) {
    alerts.push({
      code: 'wallet/low-runway',
      level: runwayHours <= 0 ? 'critical' : 'warning',
      message: `Account ${account} has an estimated runway of ${runwayHours.toFixed(1)} hours, below the ${options.minRunwayHours}-hour threshold`,
    });
  }

  const status: WalletStatus = alerts.some((alert) => alert.level === 'critical')
    ? alerts.some((alert) => alert.code === 'wallet/depleted')
      ? 'depleted'
      : 'critical'
    : alerts.length > 0
      ? 'warning'
      : 'ok';

  return {
    account,
    checkedAt: now.toISOString(),
    nativeBalance: native.balance,
    minimumReserve: reserves.minimumXlm,
    availableXlm,
    sellingLiabilities: native.sellingLiabilities,
    reserves,
    trustlines: trustlinesOf(record),
    burnRate,
    runwayHours,
    runwayDays,
    status,
    alerts,
  };
}

/** Parses an untrusted Horizon account payload into the subset used here. */
export function parseHorizonAccount(body: unknown): HorizonAccountRecord {
  const record = asRecord(body);
  if (!record) throw new Error('Horizon account response was not a JSON object');

  const balancesValue = record.balances;
  if (!Array.isArray(balancesValue)) {
    throw new Error('Horizon account response is missing the balances array');
  }

  const balances: HorizonBalance[] = [];
  for (const entry of balancesValue) {
    const balance = asRecord(entry);
    if (!balance || !isString(balance.asset_type) || !isString(balance.balance)) continue;
    balances.push({
      asset_type: balance.asset_type,
      balance: balance.balance,
      ...(isString(balance.limit) ? { limit: balance.limit } : {}),
      ...(isString(balance.buying_liabilities)
        ? { buying_liabilities: balance.buying_liabilities }
        : {}),
      ...(isString(balance.selling_liabilities)
        ? { selling_liabilities: balance.selling_liabilities }
        : {}),
      ...(isString(balance.asset_code) ? { asset_code: balance.asset_code } : {}),
      ...(isString(balance.asset_issuer) ? { asset_issuer: balance.asset_issuer } : {}),
      ...(typeof balance.is_authorized === 'boolean'
        ? { is_authorized: balance.is_authorized }
        : {}),
    });
  }

  const result: HorizonAccountRecord = { balances };
  if (isString(record.id)) result.id = record.id;
  if (isString(record.account_id)) result.account_id = record.account_id;
  if (isInteger(record.subentry_count)) result.subentry_count = record.subentry_count;
  if (isInteger(record.num_sponsoring)) result.num_sponsoring = record.num_sponsoring;
  if (isInteger(record.num_sponsored)) result.num_sponsored = record.num_sponsored;
  return result;
}

function parseActivity(body: unknown): HorizonActivityRecord[] {
  const record = asRecord(body);
  const embedded = asRecord(record?._embedded);
  const records = embedded?.records;
  if (!Array.isArray(records)) return [];

  const parsed: HorizonActivityRecord[] = [];
  for (const entry of records) {
    const item = asRecord(entry);
    if (!item) continue;
    const activity: HorizonActivityRecord = {};
    if (isString(item.id)) activity.id = item.id;
    if (isString(item.type)) activity.type = item.type;
    if (isString(item.created_at)) activity.created_at = item.created_at;
    if (isString(item.amount)) activity.amount = item.amount;
    if (isString(item.asset_type)) activity.asset_type = item.asset_type;
    if (isString(item.source_amount)) activity.source_amount = item.source_amount;
    if (isString(item.source_asset_type)) activity.source_asset_type = item.source_asset_type;
    if (isString(item.from)) activity.from = item.from;
    if (isString(item.to)) activity.to = item.to;
    if (isString(item.source_account)) activity.source_account = item.source_account;
    if (isString(item.fee_charged)) activity.fee_charged = item.fee_charged;
    parsed.push(activity);
  }
  return parsed;
}

/** Human-readable one-line summary used by the CLI and daemon logs. */
export function formatWalletReport(report: WalletBalanceReport): string {
  const runway =
    report.runwayHours === null
      ? 'stable (no spend in window)'
      : `${report.runwayHours.toFixed(1)}h (${(report.runwayDays ?? 0).toFixed(1)}d)`;
  const head = [
    `${report.account}: ${report.nativeBalance.toFixed(7)} XLM`,
    `reserve ${report.minimumReserve.toFixed(7)}`,
    `spendable ${report.availableXlm.toFixed(7)}`,
    `burn ${report.burnRate.burnRatePerDay.toFixed(4)} XLM/day`,
    `runway ${runway}`,
    report.status.toUpperCase(),
  ].join(' | ');
  return report.alerts.length === 0
    ? head
    : `${head}\n${report.alerts.map((alert) => `  ${alert.level} [${alert.code}]: ${alert.message}`).join('\n')}`;
}

/**
 * Polls Horizon and alerts when a hot wallet falls below its operational
 * reserve or projected runway.
 */
export class HotWalletBalanceMonitor {
  private readonly horizonUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly minXlm: number;
  private readonly warnXlm: number | undefined;
  private readonly minRunwayHours: number | undefined;
  private readonly baseReserveXlm: number;
  private readonly lookbackHours: number;
  private readonly pollIntervalMs: number;
  private readonly webhookUrl: string | undefined;
  private readonly logger: (line: string) => void;
  private readonly now: () => Date;
  private readonly maxIterations: number | undefined;
  private readonly controller = new AbortController();

  constructor(options: HotWalletMonitorOptions = { minXlm: 0 }) {
    this.horizonUrl = normalizeHorizonUrl(options.horizonUrl);
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.minXlm = Number.isFinite(options.minXlm) ? Math.max(0, options.minXlm) : 0;
    this.warnXlm =
      options.warnXlm !== undefined && Number.isFinite(options.warnXlm)
        ? Math.max(0, options.warnXlm)
        : undefined;
    this.minRunwayHours =
      options.minRunwayHours !== undefined && Number.isFinite(options.minRunwayHours)
        ? Math.max(0, options.minRunwayHours)
        : undefined;
    this.baseReserveXlm =
      options.baseReserveXlm !== undefined && Number.isFinite(options.baseReserveXlm)
        ? options.baseReserveXlm
        : DEFAULT_BASE_RESERVE_XLM;
    this.lookbackHours =
      options.lookbackHours !== undefined && options.lookbackHours > 0
        ? options.lookbackHours
        : DEFAULT_LOOKBACK_HOURS;
    this.pollIntervalMs =
      options.pollIntervalMs !== undefined && options.pollIntervalMs >= 0
        ? options.pollIntervalMs
        : DEFAULT_POLL_INTERVAL_MS;
    this.webhookUrl = options.webhookUrl;
    this.logger = options.logger ?? (() => {});
    this.now = options.now ?? (() => new Date());
    this.maxIterations = options.maxIterations;
  }

  parseWalletDeclarations(doc: Record<string, unknown>): WalletDeclaration[] {
    return parseWalletDeclarations(doc);
  }

  /** Fetches and evaluates one account. Network failures are thrown so callers can retry. */
  async checkAccount(account: string, signal?: AbortSignal): Promise<WalletBalanceReport> {
    const encoded = encodeURIComponent(account);
    const accountUrl = `${this.horizonUrl}/accounts/${encoded}`;
    const activityUrl = `${this.horizonUrl}/accounts/${encoded}/payments?order=desc&limit=200`;
    const requestOptions: RequestInit = signal ? { signal } : {};

    const response = await this.fetchImpl(accountUrl, requestOptions);
    if (!response.ok) {
      throw new Error(`Horizon returned HTTP ${response.status} for account ${account}`);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new Error(`Horizon returned invalid JSON for account ${account}`);
    }

    const record = parseHorizonAccount(body);
    if (record.account_id === undefined && record.id === undefined) record.account_id = account;

    let activity: HorizonActivityRecord[] = [];
    try {
      const activityResponse = await this.fetchImpl(activityUrl, requestOptions);
      if (activityResponse.ok) activity = parseActivity(await activityResponse.json());
    } catch {
      // The account snapshot is still useful without history; the report
      // simply projects no burn instead of failing the entire check.
    }

    return assessWalletBalance(record, activity, {
      minXlm: this.minXlm,
      ...(this.warnXlm !== undefined ? { warnXlm: this.warnXlm } : {}),
      ...(this.minRunwayHours !== undefined ? { minRunwayHours: this.minRunwayHours } : {}),
      baseReserveXlm: this.baseReserveXlm,
      lookbackHours: this.lookbackHours,
      now: this.now(),
    });
  }

  /** Evaluates every wallet declared in a parsed `stellar.toml`. */
  async checkStellarToml(doc: Record<string, unknown>): Promise<WalletBalanceReport[]> {
    return Promise.all(
      parseWalletDeclarations(doc).map((declaration) => this.checkAccount(declaration.account)),
    );
  }

  /** Sends a webhook notification for one report, or does nothing if it is healthy. */
  async notify(report: WalletBalanceReport): Promise<void> {
    for (const alert of report.alerts) {
      this.logger(`${alert.level.toUpperCase()} [${alert.code}] ${alert.message}`);
    }
    if (report.alerts.length === 0 || this.webhookUrl === undefined) return;

    try {
      const response = await this.fetchImpl(this.webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ source: 'stellar-toml-lint', report }),
      });
      if (!response.ok) {
        this.logger(
          `WARN [wallet/webhook] notification to ${this.webhookUrl} returned HTTP ${response.status}`,
        );
      }
    } catch (error) {
      // Alert delivery must never take down the daemon; the console/log line
      // already emitted above remains the fallback.
      this.logger(`WARN [wallet/webhook] could not deliver notification: ${errorMessage(error)}`);
    }
  }

  /**
   * Polls the given accounts until the signal aborts or `once` is set.
   *
   * A failed poll is logged and retried on the next tick rather than exiting,
   * so a transient Horizon outage does not blind the operator permanently.
   */
  async monitor(
    accounts: string[],
    options: MonitorRunOptions = {},
  ): Promise<WalletBalanceReport[]> {
    const collected: WalletBalanceReport[] = [];
    const signal = options.signal ?? this.controller.signal;
    const intervalMs = options.intervalMs ?? this.pollIntervalMs;
    const maxIterations = options.maxIterations ?? this.maxIterations;
    let iteration = 0;

    while (!signal.aborted) {
      iteration += 1;
      for (const account of accounts) {
        if (signal.aborted) break;
        try {
          const report = await this.checkAccount(account, signal);
          collected.push(report);
          options.onReport?.(report);
          await this.notify(report);
        } catch (error) {
          if (signal.aborted) break;
          this.logger(`WARN [wallet/check-failed] ${account}: ${errorMessage(error)}`);
        }
      }

      if (options.once === true) break;
      if (maxIterations !== undefined && iteration >= maxIterations) break;
      if (signal.aborted) break;
      await abortableSleep(intervalMs, signal);
    }

    return collected;
  }

  /** Starts the daemon. Call {@link stop} to terminate it early. */
  async start(accounts: string[], options: MonitorRunOptions = {}): Promise<WalletBalanceReport[]> {
    return this.monitor(accounts, options);
  }

  /** Aborts an in-flight {@link start}/{@link monitor} run cleanly. */
  stop(): void {
    this.controller.abort();
  }
}

function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted || ms <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(finish, ms);
    function finish(): void {
      clearTimeout(timer);
      signal.removeEventListener('abort', finish);
      resolve();
    }
    signal.addEventListener('abort', finish, { once: true });
  });
}
