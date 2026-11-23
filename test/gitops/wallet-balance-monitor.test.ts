import { describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_BASE_RESERVE_XLM,
  HotWalletBalanceMonitor,
  assessWalletBalance,
  calculateBurnRate,
  calculateMinimumReserve,
  formatWalletReport,
  parseHorizonAccount,
  parseWalletDeclarations,
  type HorizonAccountRecord,
  type HorizonActivityRecord,
} from '../../src/gitops/walletBalanceMonitor.js';

function account(overrides: Partial<HorizonAccountRecord> = {}): HorizonAccountRecord {
  return {
    id: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    account_id: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    subentry_count: 0,
    balances: [
      {
        asset_type: 'native',
        balance: '100.0000000',
        selling_liabilities: '0.0000000',
      },
    ],
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function activity(createdAt: string, amount: string): HorizonActivityRecord {
  return {
    id: `${createdAt}:${amount}`,
    type: 'payment',
    created_at: createdAt,
    asset_type: 'native',
    amount,
    from: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    to: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  };
}

describe('parseWalletDeclarations', () => {
  it('finds signing keys, operational wallets, distribution accounts, and currencies', () => {
    const declarations = parseWalletDeclarations({
      SIGNING_KEY: 'GSIGNING',
      ACCOUNTS: ['GACCOUNT'],
      HOT_WALLETS: ['GHOT', { account: 'GHOT2' }],
      OPERATIONAL_WALLETS: ['GOPERATIONAL'],
      DISTRIBUTION_ACCOUNTS: ['GDIST'],
      CURRENCIES: [{ code: 'USD', distribution_account: 'GCURRENCY' }],
    });

    expect(declarations.map((entry) => entry.account)).toEqual([
      'GSIGNING',
      'GACCOUNT',
      'GHOT',
      'GHOT2',
      'GOPERATIONAL',
      'GDIST',
      'GCURRENCY',
    ]);
    expect(declarations.find((entry) => entry.account === 'GSIGNING')?.role).toBe('signing-key');
    expect(declarations.find((entry) => entry.account === 'GHOT')?.role).toBe('hot-wallet');
    expect(declarations.find((entry) => entry.account === 'GCURRENCY')?.role).toBe('distribution');
  });

  it('deduplicates accounts and keeps the first, most specific declaration', () => {
    const declarations = parseWalletDeclarations({
      SIGNING_KEY: 'GSAME',
      ACCOUNTS: ['GSAME'],
      HOT_WALLETS: ['GSAME'],
    });
    expect(declarations).toEqual([{ account: 'GSAME', role: 'signing-key', path: 'SIGNING_KEY' }]);
  });
});

describe('calculateMinimumReserve', () => {
  it('includes the account, subentry, trustline, and sponsorship reserves', () => {
    const reserves = calculateMinimumReserve(
      account({
        subentry_count: 3,
        num_sponsoring: 2,
        num_sponsored: 1,
        balances: [
          { asset_type: 'native', balance: '50', selling_liabilities: '0' },
          {
            asset_type: 'credit_alphanum4',
            asset_code: 'USD',
            asset_issuer: 'GISSUER',
            balance: '10',
            limit: '100',
          },
        ],
      }),
    );

    // (2 base + 3 subentries + 2 sponsoring - 1 sponsored) * 0.5
    expect(reserves.reserveUnits).toBe(6);
    expect(reserves.minimumXlm).toBe(3);
    expect(reserves.trustlineCount).toBe(1);
    expect(reserves.baseReserveXlm).toBe(DEFAULT_BASE_RESERVE_XLM);
  });

  it('never returns a negative reserve for heavily sponsored accounts', () => {
    const reserves = calculateMinimumReserve(account({ num_sponsored: 100 }));
    expect(reserves.reserveUnits).toBe(0);
    expect(reserves.minimumXlm).toBe(0);
  });
});

describe('calculateBurnRate', () => {
  it('sums outbound native payments in the lookback window', () => {
    const now = new Date('2026-01-08T00:00:00.000Z');
    const estimate = calculateBurnRate(
      [
        activity('2026-01-07T00:00:00.000Z', '10'),
        activity('2026-01-06T00:00:00.000Z', '20'),
        activity('2025-12-01T00:00:00.000Z', '999'),
      ],
      'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      { now, lookbackHours: 168 },
    );

    expect(estimate.spentXlm).toBe(30);
    expect(estimate.outgoingCount).toBe(2);
    expect(estimate.burnRatePerHour).toBeCloseTo(30 / 168, 8);
    expect(estimate.burnRatePerDay).toBeCloseTo((30 / 168) * 24, 8);
  });

  it('ignores incoming payments and non-native assets', () => {
    const now = new Date('2026-01-08T00:00:00.000Z');
    const estimate = calculateBurnRate(
      [
        {
          ...activity('2026-01-07T00:00:00.000Z', '100'),
          from: 'GOTHER',
          to: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        },
        {
          ...activity('2026-01-07T00:00:00.000Z', '100'),
          asset_type: 'credit_alphanum4',
        },
      ],
      'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      { now, lookbackHours: 168 },
    );
    expect(estimate.spentXlm).toBe(0);
    expect(estimate.outgoingCount).toBe(0);
  });

  it('counts transaction fees once when transaction records are supplied', () => {
    const now = new Date('2026-01-08T00:00:00.000Z');
    const fee = {
      id: 'tx-1',
      type: 'transaction',
      created_at: '2026-01-07T00:00:00.000Z',
      source_account: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      fee_charged: '100',
    };
    const estimate = calculateBurnRate(
      [fee, fee],
      'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      { now, lookbackHours: 168 },
    );
    expect(estimate.spentXlm).toBeCloseTo(0.00001, 10);
  });
});

describe('assessWalletBalance', () => {
  it('reports a solvent wallet with no alerts', () => {
    const report = assessWalletBalance(account(), [], { minXlm: 10 });
    expect(report.status).toBe('ok');
    expect(report.alerts).toEqual([]);
    expect(report.minimumReserve).toBe(1);
    expect(report.availableXlm).toBe(99);
    expect(report.runwayHours).toBeNull();
  });

  it('reports a low-balance wallet below the minimum', () => {
    const report = assessWalletBalance(
      account({ balances: [{ asset_type: 'native', balance: '6', selling_liabilities: '0' }] }),
      [],
      { minXlm: 10 },
    );
    expect(report.availableXlm).toBe(5);
    expect(report.status).toBe('critical');
    expect(report.alerts.map((alert) => alert.code)).toContain('wallet/below-minimum');
  });

  it('warns at the configured early watermark', () => {
    const report = assessWalletBalance(
      account({ balances: [{ asset_type: 'native', balance: '16', selling_liabilities: '0' }] }),
      [],
      { minXlm: 10, warnXlm: 20 },
    );
    expect(report.availableXlm).toBe(15);
    expect(report.status).toBe('warning');
    expect(report.alerts[0]?.code).toBe('wallet/low-watermark');
  });

  it('reports a depleted wallet when the reserve consumes the balance', () => {
    const report = assessWalletBalance(
      account({ balances: [{ asset_type: 'native', balance: '1', selling_liabilities: '0' }] }),
      [],
      { minXlm: 0 },
    );
    expect(report.availableXlm).toBe(0);
    expect(report.status).toBe('depleted');
    expect(report.alerts[0]?.code).toBe('wallet/depleted');
  });

  it('projects runway and warns when it falls below the threshold', () => {
    const now = new Date('2026-01-08T00:00:00.000Z');
    const report = assessWalletBalance(account(), [activity('2026-01-07T00:00:00.000Z', '70')], {
      minXlm: 10,
      minRunwayHours: 300,
      now,
      lookbackHours: 168,
    });

    expect(report.runwayHours).toBeCloseTo(99 / (70 / 168), 6);
    expect(report.status).toBe('warning');
    expect(report.alerts.map((alert) => alert.code)).toContain('wallet/low-runway');
  });

  it('exposes trustline limits and available capacity', () => {
    const report = assessWalletBalance(
      account({
        balances: [
          { asset_type: 'native', balance: '100', selling_liabilities: '0' },
          {
            asset_type: 'credit_alphanum4',
            asset_code: 'USD',
            asset_issuer: 'GISSUER',
            balance: '75',
            limit: '100',
            selling_liabilities: '5',
          },
        ],
      }),
      [],
      { minXlm: 10 },
    );
    expect(report.trustlines).toEqual([
      {
        assetType: 'credit_alphanum4',
        code: 'USD',
        issuer: 'GISSUER',
        balance: 75,
        limit: 100,
        available: 20,
        authorized: true,
      },
    ]);
  });
});

describe('parseHorizonAccount', () => {
  it('parses a valid Horizon account document', () => {
    expect(parseHorizonAccount(account({ subentry_count: 2 }))).toMatchObject({
      subentry_count: 2,
      balances: [{ asset_type: 'native', balance: '100.0000000' }],
    });
  });

  it('rejects malformed Horizon payloads', () => {
    expect(() => parseHorizonAccount(null)).toThrow('not a JSON object');
    expect(() => parseHorizonAccount({ id: 'G' })).toThrow('balances array');
  });
});

describe('HotWalletBalanceMonitor', () => {
  const positive = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

  function monitorFetch(payments: unknown[] = []): { fetchImpl: typeof fetch; urls: string[] } {
    const urls: string[] = [];
    const fetchImpl = (async (input: string | URL | globalThis.Request) => {
      const url = input.toString();
      urls.push(url);
      if (url.includes('/payments')) {
        return jsonResponse({ _embedded: { records: payments } });
      }
      return jsonResponse(account());
    }) as unknown as typeof fetch;
    return { fetchImpl, urls };
  }

  it('fetches the account and recent payments from Horizon', async () => {
    const { fetchImpl, urls } = monitorFetch([activity('2026-01-07T00:00:00.000Z', '10')]);
    const monitor = new HotWalletBalanceMonitor({
      minXlm: 10,
      fetchImpl,
      horizonUrl: 'https://horizon.example/',
      now: () => new Date('2026-01-08T00:00:00.000Z'),
    });

    const report = await monitor.checkAccount(positive);
    expect(report.account).toBe(positive);
    expect(report.status).toBe('ok');
    expect(urls[0]).toBe(`https://horizon.example/accounts/${positive}`);
    expect(urls[1]).toContain('/payments?order=desc&limit=200');
  });

  it('throws a useful error when Horizon rejects the account request', async () => {
    const fetchImpl = (async () => jsonResponse({}, 404)) as unknown as typeof fetch;
    const monitor = new HotWalletBalanceMonitor({ minXlm: 1, fetchImpl });
    await expect(monitor.checkAccount(positive)).rejects.toThrow('HTTP 404');
  });

  it('degrades gracefully when payment history is unavailable', async () => {
    const fetchImpl = (async (input: string | URL | globalThis.Request) => {
      if (input.toString().includes('/payments')) throw new Error('history unavailable');
      return jsonResponse(account());
    }) as unknown as typeof fetch;
    const monitor = new HotWalletBalanceMonitor({ minXlm: 10, fetchImpl });
    const report = await monitor.checkAccount(positive);
    expect(report.burnRate.spentXlm).toBe(0);
    expect(report.status).toBe('ok');
  });

  it('posts low-watermark alerts to the webhook and logs them', async () => {
    const calls: string[] = [];
    const fetchImpl = (async (input: string | URL | globalThis.Request, init?: RequestInit) => {
      const url = input.toString();
      calls.push(`${init?.method ?? 'GET'} ${url}`);
      if (url.includes('/payments')) return jsonResponse({ _embedded: { records: [] } });
      if (init?.method === 'POST') return jsonResponse({ ok: true });
      return jsonResponse(
        account({ balances: [{ asset_type: 'native', balance: '2', selling_liabilities: '0' }] }),
      );
    }) as unknown as typeof fetch;
    const lines: string[] = [];
    const monitor = new HotWalletBalanceMonitor({
      minXlm: 10,
      fetchImpl,
      webhookUrl: 'https://hooks.example/alert',
      logger: (line) => lines.push(line),
    });

    const report = await monitor.checkAccount(positive);
    await monitor.notify(report);

    expect(calls).toContain('POST https://hooks.example/alert');
    expect(lines.join('\n')).toContain('wallet/below-minimum');
  });

  it('does not post when the wallet is healthy', async () => {
    let posts = 0;
    const fetchImpl = (async (input: string | URL | globalThis.Request, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posts += 1;
        return jsonResponse({ ok: true });
      }
      if (input.toString().includes('/payments'))
        return jsonResponse({ _embedded: { records: [] } });
      return jsonResponse(account());
    }) as unknown as typeof fetch;
    const monitor = new HotWalletBalanceMonitor({
      minXlm: 10,
      fetchImpl,
      webhookUrl: 'https://hooks.example/alert',
    });

    await monitor.notify(assessWalletBalance(account(), [], { minXlm: 10 }));
    expect(posts).toBe(0);
  });

  it('runs once and returns every report', async () => {
    const { fetchImpl } = monitorFetch();
    const monitor = new HotWalletBalanceMonitor({ minXlm: 10, fetchImpl });
    const reports = await monitor.monitor([positive, positive], { once: true });
    expect(reports).toHaveLength(2);
  });

  it('keeps polling until aborted, then terminates cleanly', async () => {
    const { fetchImpl } = monitorFetch();
    const monitor = new HotWalletBalanceMonitor({
      minXlm: 10,
      fetchImpl,
      pollIntervalMs: 1,
    });
    const onReport = vi.fn();
    const running = monitor.start([positive], { onReport });
    setTimeout(() => monitor.stop(), 15);
    const reports = await running;
    expect(onReport.mock.calls.length).toBeGreaterThanOrEqual(1);
    expect(reports.length).toBeGreaterThanOrEqual(1);
  });

  it('stops after the configured iteration cap', async () => {
    const { fetchImpl } = monitorFetch();
    const monitor = new HotWalletBalanceMonitor({ minXlm: 10, fetchImpl });
    const reports = await monitor.monitor([positive], {
      intervalMs: 0,
      maxIterations: 3,
    });
    expect(reports).toHaveLength(3);
  });

  it('honours an external abort signal', async () => {
    const { fetchImpl } = monitorFetch();
    const monitor = new HotWalletBalanceMonitor({ minXlm: 10, fetchImpl });
    const controller = new AbortController();
    controller.abort();
    const reports = await monitor.monitor([positive], { signal: controller.signal });
    expect(reports).toEqual([]);
  });

  it('formats a readable report including alerts', () => {
    const report = assessWalletBalance(
      account({ balances: [{ asset_type: 'native', balance: '2', selling_liabilities: '0' }] }),
      [],
      { minXlm: 10 },
    );
    const text = formatWalletReport(report);
    expect(text).toContain('spendable');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('wallet/below-minimum');
  });
});
