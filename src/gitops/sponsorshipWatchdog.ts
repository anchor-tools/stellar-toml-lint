/**
 * Sponsorship Pool Reserve Exhaustion Watchdog
 *
 * Monitors Stellar fee sponsor accounts (used by SEP-24 / SEP-31 fee-bump transactions
 * and BeginSponsoringFutureReservesOp) to detect spendable balance and reserve exhaustion.
 * Simulates transaction surges and projects pool depletion timelines.
 */

import {
  IncidentWebhookDispatcher,
  type Incident,
  type IncidentDelivery,
  type IncidentTargets,
  type IncidentSeverity,
} from './incidentDispatcher.js';

export interface SponsorAccountState {
  accountId: string;
  /** Spendable XLM balance (excluding base reserves for owned entries), in stroops or XLM string/number. */
  balanceXlm: number;
  /** Number of sponsored ledger entries / future reserves currently active. */
  sponsoredEntriesCount: number;
  /** Minimum reserve required per sponsored entry (typically 0.5 XLM or configurable). */
  reservePerEntryXlm?: number;
  /** Estimated base reserve locked by account itself. */
  baseReserveXlm?: number;
}

export interface SponsorshipSimulationOptions {
  /** Number of sponsored transactions in the surge scenario (e.g. 10000). */
  surgeTransactionCount?: number;
  /** Average fee cost per sponsored transaction in XLM (default 0.000100 XLM / 1000 stroops). */
  feePerTransactionXlm?: number;
  /** Additional reserve locked per transaction if entries are created (e.g. 0.5 XLM). */
  reserveLockPerTransactionXlm?: number;
  /** Current burn rate: transactions per second. */
  transactionsPerSecond?: number;
}

export interface SponsorshipSimulationResult {
  accountId: string;
  initialBalanceXlm: number;
  spendableBalanceXlm: number;
  sponsoredEntriesCount: number;
  surgeTransactionCount: number;
  feeCostSurgeXlm: number;
  reserveLockSurgeXlm: number;
  totalSurgeCostXlm: number;
  projectedBalanceAfterSurgeXlm: number;
  isExhaustedAfterSurge: boolean;
  /** Depletion timeline in seconds under continuous current TPS burn rate. */
  depletionSeconds: number | null;
  /** Projected hours until complete exhaustion at current TPS burn rate. */
  depletionHours: number | null;
}

export interface SponsorWatchdogConfig {
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
  dispatcher?: IncidentWebhookDispatcher;
  targets?: IncidentTargets;
  /** Minimum XLM balance safety buffer before triggering an error/critical alert. Default 100 XLM. */
  balanceBufferXlm?: number;
  /** Warning threshold multiplier over buffer. Default 2.0 (200 XLM). */
  warningBufferMultiplier?: number;
}

export const DEFAULT_FEE_PER_TX_XLM = 0.0001;
export const DEFAULT_RESERVE_PER_ENTRY_XLM = 0.5;
export const DEFAULT_BALANCE_BUFFER_XLM = 100;
export const DEFAULT_HORIZON_URL = 'https://horizon.stellar.org';

export class SponsorshipPoolWatchdog {
  private readonly horizonUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly dispatcher: IncidentWebhookDispatcher;
  private readonly targets: IncidentTargets;
  private readonly balanceBufferXlm: number;
  private readonly warningBufferMultiplier: number;

  constructor(config: SponsorWatchdogConfig = {}) {
    this.horizonUrl = (config.horizonUrl ?? DEFAULT_HORIZON_URL).replace(/\/+$/, '');
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.dispatcher = config.dispatcher ?? new IncidentWebhookDispatcher();
    this.targets = config.targets ?? {};
    this.balanceBufferXlm = config.balanceBufferXlm ?? DEFAULT_BALANCE_BUFFER_XLM;
    this.warningBufferMultiplier = config.warningBufferMultiplier ?? 2.0;
  }

  /**
   * Queries Horizon to retrieve the account balance and sponsored reserves statistics.
   */
  async fetchAccountState(accountId: string): Promise<SponsorAccountState> {
    const url = `${this.horizonUrl}/accounts/${encodeURIComponent(accountId)}`;
    const response = await this.fetchImpl(url, {
      headers: { accept: 'application/json' },
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch sponsor account ${accountId} from Horizon: HTTP ${response.status}`,
      );
    }

    const data = (await response.json()) as {
      balances?: Array<{
        asset_type: string;
        balance: string;
        buying_liabilities?: string;
        selling_liabilities?: string;
      }>;
      num_sponsoring?: number;
      num_sponsored?: number;
      subentry_count?: number;
    };

    let nativeBalanceXlm = 0;
    if (Array.isArray(data.balances)) {
      const native = data.balances.find((b) => b.asset_type === 'native');
      if (native) {
        const total = Number.parseFloat(native.balance);
        const buying = Number.parseFloat(native.buying_liabilities ?? '0');
        const selling = Number.parseFloat(native.selling_liabilities ?? '0');
        nativeBalanceXlm = Math.max(0, total - buying - selling);
      }
    }

    // Sponsored entry count is represented by num_sponsoring or subentries in Stellar ledger accounting
    const sponsoredEntriesCount = Number(data.num_sponsoring ?? data.subentry_count ?? 0);

    return {
      accountId,
      balanceXlm: nativeBalanceXlm,
      sponsoredEntriesCount,
      reservePerEntryXlm: DEFAULT_RESERVE_PER_ENTRY_XLM,
    };
  }

  /**
   * Simulates transaction volume surges (e.g. 10,000 sponsored txs) and calculates depletion timelines.
   */
  simulateSurge(
    state: SponsorAccountState,
    options: SponsorshipSimulationOptions = {},
  ): SponsorshipSimulationResult {
    const surgeTransactionCount = options.surgeTransactionCount ?? 10000;
    const feePerTransactionXlm = options.feePerTransactionXlm ?? DEFAULT_FEE_PER_TX_XLM;
    const reserveLockPerTransactionXlm = options.reserveLockPerTransactionXlm ?? 0;
    const tps = options.transactionsPerSecond ?? 1.0;

    const feeCostSurgeXlm = surgeTransactionCount * feePerTransactionXlm;
    const reserveLockSurgeXlm = surgeTransactionCount * reserveLockPerTransactionXlm;
    const totalSurgeCostXlm = feeCostSurgeXlm + reserveLockSurgeXlm;

    const projectedBalanceAfterSurgeXlm = state.balanceXlm - totalSurgeCostXlm;
    const isExhaustedAfterSurge = projectedBalanceAfterSurgeXlm <= 0;

    // Burn rate calculation: total outflow rate per second (fees + reserve locks per tx * tps)
    const burnRatePerSecondXlm = tps * (feePerTransactionXlm + reserveLockPerTransactionXlm);
    let depletionSeconds: number | null = null;
    let depletionHours: number | null = null;

    if (burnRatePerSecondXlm > 0 && state.balanceXlm > 0) {
      depletionSeconds = Math.max(0, state.balanceXlm / burnRatePerSecondXlm);
      depletionHours = depletionSeconds / 3600;
    } else if (state.balanceXlm <= 0) {
      depletionSeconds = 0;
      depletionHours = 0;
    }

    return {
      accountId: state.accountId,
      initialBalanceXlm: state.balanceXlm,
      spendableBalanceXlm: state.balanceXlm,
      sponsoredEntriesCount: state.sponsoredEntriesCount,
      surgeTransactionCount,
      feeCostSurgeXlm,
      reserveLockSurgeXlm,
      totalSurgeCostXlm,
      projectedBalanceAfterSurgeXlm,
      isExhaustedAfterSurge,
      depletionSeconds,
      depletionHours,
    };
  }

  /**
   * Evaluates sponsor account health and dispatches alerts if balances fall below safety buffers.
   */
  async evaluateAndAlert(
    state: SponsorAccountState,
    options: SponsorshipSimulationOptions = {},
  ): Promise<{
    state: SponsorAccountState;
    simulation: SponsorshipSimulationResult;
    severity: IncidentSeverity | 'healthy';
    deliveries: IncidentDelivery[];
  }> {
    const simulation = this.simulateSurge(state, options);
    const criticalThreshold = this.balanceBufferXlm;
    const warningThreshold = this.balanceBufferXlm * this.warningBufferMultiplier;

    let severity: IncidentSeverity | 'healthy' = 'healthy';
    if (state.balanceXlm <= criticalThreshold || simulation.projectedBalanceAfterSurgeXlm <= 0) {
      severity = 'critical';
    } else if (state.balanceXlm <= warningThreshold) {
      severity = 'warning';
    }

    let deliveries: IncidentDelivery[];
    const rule = 'gitops/sponsorship-pool-reserve-exhaustion';
    const source = `stellar-sponsor:${state.accountId.slice(0, 8)}...`;

    if (severity === 'critical' || severity === 'warning') {
      const incident: Incident = {
        id: `sponsor-${state.accountId}`,
        title:
          severity === 'critical'
            ? 'Sponsorship Pool Reserve Exhaustion Critical'
            : 'Sponsorship Pool Reserve Warning',
        summary: `Sponsor account ${state.accountId} has balance ${state.balanceXlm.toFixed(2)} XLM (Buffer: ${criticalThreshold} XLM). Projected balance after ${simulation.surgeTransactionCount} surge txs: ${simulation.projectedBalanceAfterSurgeXlm.toFixed(2)} XLM.`,
        severity: severity === 'critical' ? 'critical' : 'warning',
        source,
        rule,
        details: {
          accountId: state.accountId,
          balanceXlm: Number(state.balanceXlm.toFixed(2)),
          sponsoredEntries: state.sponsoredEntriesCount,
          projectedAfterSurgeXlm: Number(simulation.projectedBalanceAfterSurgeXlm.toFixed(2)),
          depletionHours:
            simulation.depletionHours !== null ? Number(simulation.depletionHours.toFixed(2)) : -1,
        },
        dedupKey: `sponsorship-pool-${state.accountId}`,
      };

      deliveries = await this.dispatcher.dispatch(incident, this.targets);
    } else {
      // Resolve if previously alerting
      const incident: Incident = {
        id: `sponsor-${state.accountId}`,
        title: 'Sponsorship Pool Reserve Healthy',
        summary: `Sponsor account ${state.accountId} balance ${state.balanceXlm.toFixed(2)} XLM is within safe operating parameters.`,
        severity: 'info',
        source,
        rule,
        dedupKey: `sponsorship-pool-${state.accountId}`,
        status: 'resolved',
      };
      deliveries = await this.dispatcher.resolve(incident, this.targets);
    }

    return { state, simulation, severity, deliveries };
  }

  /**
   * High-level check method: fetches state from Horizon, simulates, and alerts in one call.
   */
  async monitor(
    accountId: string,
    options: SponsorshipSimulationOptions = {},
  ): Promise<{
    state: SponsorAccountState;
    simulation: SponsorshipSimulationResult;
    severity: IncidentSeverity | 'healthy';
    deliveries: IncidentDelivery[];
  }> {
    const state = await this.fetchAccountState(accountId);
    return this.evaluateAndAlert(state, options);
  }
}

/**
 * Helper to extract fee sponsor accounts advertised in stellar.toml or service manifests.
 */
export function extractSponsorAccountsFromToml(tomlContent: string): string[] {
  const accounts = new Set<string>();
  // Look for lines containing fee_sponsor, sponsor_account, or similar Stellar public keys (G...)
  const gKeyRegex = /\b(G[A-Z2-7]{55})\b/g;
  const lines = tomlContent.split(/\r?\n/);
  for (const line of lines) {
    if (/(sponsor|fee_bump|fee_pool)/i.test(line)) {
      let match: RegExpExecArray | null;
      while ((match = gKeyRegex.exec(line)) !== null) {
        // Guard against a future change to the regex accidentally matching an
        // empty group captured by a malformed pattern.
        if (match[1] !== undefined) accounts.add(match[1]);
      }
      gKeyRegex.lastIndex = 0;
    }
  }
  return Array.from(accounts);
}
