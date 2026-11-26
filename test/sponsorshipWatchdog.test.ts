import { describe, expect, it } from 'vitest';
import {
  SponsorshipPoolWatchdog,
  extractSponsorAccountsFromToml,
  type SponsorAccountState,
} from '../src/gitops/sponsorshipWatchdog.js';
import { IncidentWebhookDispatcher } from '../src/gitops/incidentDispatcher.js';

describe('SponsorshipPoolWatchdog', () => {
  const mockAccountId = `G${'A'.repeat(55)}`;

  it('extracts sponsor accounts from stellar.toml content', () => {
    const toml = `
      # Stellar TOML configuration
      NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
      FEE_SPONSOR_ACCOUNT="${mockAccountId}"
      OTHER_ACCOUNT="GC_________________________________________________________";
    `;
    const accounts = extractSponsorAccountsFromToml(toml);
    expect(accounts).toContain(mockAccountId);
  });

  it('subtracts minimum reserve and selling liabilities from the Horizon balance', async () => {
    const watchdog = new SponsorshipPoolWatchdog({
      fetchImpl: async () =>
        Response.json({
          balances: [
            {
              asset_type: 'native',
              balance: '50',
              buying_liabilities: '30',
              selling_liabilities: '4',
            },
          ],
          subentry_count: 3,
          num_sponsoring: 4,
          num_sponsored: 1,
        }),
    });

    await expect(watchdog.fetchAccountState(mockAccountId)).resolves.toMatchObject({
      balanceXlm: 42,
      baseReserveXlm: 4,
      sponsoredEntriesCount: 4,
    });
  });

  it('simulates transaction surges and calculates depletion accurately', () => {
    const watchdog = new SponsorshipPoolWatchdog();
    const state: SponsorAccountState = {
      accountId: mockAccountId,
      balanceXlm: 500,
      sponsoredEntriesCount: 50,
    };

    const simulation = watchdog.simulateSurge(state, {
      surgeTransactionCount: 10000,
      feePerTransactionXlm: 0.0001,
      transactionsPerSecond: 5,
    });

    expect(simulation.feeCostSurgeXlm).toBe(1.0);
    expect(simulation.projectedBalanceAfterSurgeXlm).toBe(499);
    expect(simulation.isExhaustedAfterSurge).toBe(false);
    expect(simulation.depletionHours).toBeDefined();
  });

  it('flags critical severity when balance is below safety buffer or exhausted after surge', async () => {
    let dispatchedIncident: any = null;
    const dispatcher = new IncidentWebhookDispatcher({
      fetchImpl: async () => ({ ok: true, status: 200 }) as any,
    });
    // spy on dispatch
    dispatcher.dispatch = async (incident) => {
      dispatchedIncident = incident;
      return [{ channel: 'slack', url: 'https://slack.com', ok: true, attempts: 1 }];
    };

    const fetchImpl = async () => {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          balances: [{ asset_type: 'native', balance: '45.50' }],
          num_sponsoring: 12,
        }),
      } as any;
    };

    const watchdog = new SponsorshipPoolWatchdog({
      fetchImpl,
      dispatcher,
      balanceBufferXlm: 50,
      targets: { slack: 'https://slack.com' },
    });

    const result = await watchdog.monitor(mockAccountId, {
      surgeTransactionCount: 50000,
      feePerTransactionXlm: 0.001,
    });
    expect(result.severity).toBe('critical');
    expect(dispatchedIncident).toBeDefined();
    expect(dispatchedIncident.severity).toBe('critical');
    expect(dispatchedIncident.details.accountId).toBe(mockAccountId);
  });

  it('handles healthy accounts without critical alerts and resolves if needed', async () => {
    let resolvedCalled = false;
    const dispatcher = new IncidentWebhookDispatcher();
    dispatcher.resolve = async () => {
      resolvedCalled = true;
      return [{ channel: 'slack', url: 'https://slack.com', ok: true, attempts: 1 }];
    };

    const fetchImpl = async () => {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          balances: [{ asset_type: 'native', balance: '2500.00' }],
          num_sponsoring: 5,
        }),
      } as any;
    };

    const watchdog = new SponsorshipPoolWatchdog({
      fetchImpl,
      dispatcher,
      balanceBufferXlm: 100,
      targets: { slack: 'https://slack.com' },
    });

    const result = await watchdog.monitor(mockAccountId);
    expect(result.severity).toBe('healthy');
    expect(resolvedCalled).toBe(true);
  });
});
