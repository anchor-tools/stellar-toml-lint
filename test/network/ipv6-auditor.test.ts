import { describe, expect, it, vi } from 'vitest';
import {
  auditIpv6Reachability,
  ipv6TargetsOf,
  IPV6_CONNECTION_FAILED_RULE,
  IPV6_CONNECTION_TIMEOUT_RULE,
  MISSING_IPV6_AAAA_RULE,
  type Ipv6ConnectionResult,
  type Ipv6LookupResult,
} from '../../src/network/ipv6-auditor.js';

describe('IPv6 dual-stack connectivity auditor (#383)', () => {
  const dualStackDoc = {
    TRANSFER_SERVER: 'https://api.example.com/sep6',
    DIRECT_PAYMENT_SERVER: 'https://pay.example.com/sep31',
    ANCHOR_QUOTE_SERVER: 'https://quotes.example.com',
  };

  it('passes a dual-stack endpoint: AAAA record resolves and the IPv6 socket accepts', async () => {
    const resolve = vi.fn(async (): Promise<Ipv6LookupResult> => ({
      kind: 'ok',
      addresses: ['2606:4700:4700::1111'],
    }));
    const connect = vi.fn(async (): Promise<Ipv6ConnectionResult> => ({ kind: 'connected' }));

    const diagnostics = await auditIpv6Reachability(dualStackDoc, {
      domain: 'example.com',
      resolve,
      connect,
    });

    expect(diagnostics).toEqual([]);
    expect(resolve).toHaveBeenCalledWith('example.com');
    expect(resolve).toHaveBeenCalledWith('api.example.com');
    expect(resolve).toHaveBeenCalledWith('pay.example.com');
    expect(resolve).toHaveBeenCalledWith('quotes.example.com');
    expect(connect).toHaveBeenCalledTimes(4);
  });

  it('asserts network/missing-ipv6-aaaa-record (warning) when a host publishes no AAAA record', async () => {
    const resolve = vi.fn(async (hostname: string): Promise<Ipv6LookupResult> =>
      hostname === 'api.example.com' ? { kind: 'none' } : { kind: 'ok', addresses: ['2001:db8::1'] },
    );
    const connect = vi.fn(async (): Promise<Ipv6ConnectionResult> => ({ kind: 'connected' }));

    const diagnostics = await auditIpv6Reachability(dualStackDoc, {
      domain: 'example.com',
      resolve,
      connect,
    });

    const missing = diagnostics.filter((d) => d.rule === MISSING_IPV6_AAAA_RULE);
    expect(missing).toHaveLength(1);
    expect(missing[0]?.severity).toBe('warning');
    expect(missing[0]?.path).toBe('TRANSFER_SERVER');
    expect(missing[0]?.message).toContain('api.example.com');
  });

  it('asserts network/ipv6-connection-timeout (error) when AAAA exists but the socket hangs', async () => {
    const resolve = vi.fn(async (): Promise<Ipv6LookupResult> => ({
      kind: 'ok',
      addresses: ['2001:db8::dead'],
    }));
    const connect = vi.fn(async (address: string): Promise<Ipv6ConnectionResult> =>
      address === '2001:db8::dead' ? { kind: 'timeout' } : { kind: 'connected' },
    );

    const diagnostics = await auditIpv6Reachability(
      { DIRECT_PAYMENT_SERVER: 'https://pay.example.com' },
      { resolve, connect },
    );

    const timeouts = diagnostics.filter((d) => d.rule === IPV6_CONNECTION_TIMEOUT_RULE);
    expect(timeouts).toHaveLength(1);
    expect(timeouts[0]?.severity).toBe('error');
    expect(timeouts[0]?.message).toContain('[2001:db8::dead]');
  });

  it('asserts network/ipv6-connection-failed (warning) on a refused IPv6 socket', async () => {
    const resolve = vi.fn(async (): Promise<Ipv6LookupResult> => ({
      kind: 'ok',
      addresses: ['2001:db8::2'],
    }));
    const connect = vi.fn(async (): Promise<Ipv6ConnectionResult> => ({ kind: 'refused' }));

    const diagnostics = await auditIpv6Reachability(
      { ANCHOR_QUOTE_SERVER: 'https://quotes.example.com' },
      { resolve, connect },
    );

    expect(diagnostics.some((d) => d.rule === IPV6_CONNECTION_FAILED_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('stays silent when DNS cannot be observed instead of accusing the endpoint', async () => {
    const resolve = vi.fn(async (): Promise<Ipv6LookupResult> => ({
      kind: 'error',
      detail: 'DNS lookup failed (ESERVFAIL)',
    }));
    const connect = vi.fn(async (): Promise<Ipv6ConnectionResult> => ({ kind: 'connected' }));

    const diagnostics = await auditIpv6Reachability(dualStackDoc, { resolve, connect });

    expect(diagnostics).toEqual([]);
    expect(connect).not.toHaveBeenCalled();
  });

  it('respects rule severity overrides and skips disabled rules entirely', async () => {
    const resolve = vi.fn(async (): Promise<Ipv6LookupResult> => ({ kind: 'none' }));
    const connect = vi.fn(async (): Promise<Ipv6ConnectionResult> => ({ kind: 'connected' }));

    const diagnostics = await auditIpv6Reachability(dualStackDoc, {
      resolve,
      connect,
      rules: {
        [MISSING_IPV6_AAAA_RULE]: 'off',
        [IPV6_CONNECTION_TIMEOUT_RULE]: 'off',
        [IPV6_CONNECTION_FAILED_RULE]: 'off',
      },
    });

    expect(diagnostics).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();

    const raised = await auditIpv6Reachability(dualStackDoc, {
      resolve,
      connect,
      rules: { [MISSING_IPV6_AAAA_RULE]: 'error' },
    });
    expect(raised[0]?.severity).toBe('error');
  });

  it('deduplicates hosts shared between endpoints and skips IP literals', () => {
    const targets = ipv6TargetsOf(
      {
        TRANSFER_SERVER: 'https://api.example.com/sep6',
        KYC_SERVER: 'https://api.example.com/kyc',
        WEB_AUTH_ENDPOINT: 'https://[2001:db8::5]:443/auth',
        HORIZON_URL: 'https://horizon.example.com',
      },
      'example.com',
    );

    expect(targets.map((t) => `${t.host}:${t.port}:${t.path}`)).toEqual([
      'example.com:443:domain',
      'api.example.com:443:TRANSFER_SERVER',
      'horizon.example.com:443:HORIZON_URL',
    ]);
  });

  it('returns no diagnostics when the document declares no endpoints', async () => {
    const diagnostics = await auditIpv6Reachability({ CURRENCIES: [] });
    expect(diagnostics).toEqual([]);
  });
});
