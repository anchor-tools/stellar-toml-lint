import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { certExpiryRules, checkCertExpiry } from '../src/network/cert-expiry.js';

const EXPIRING_RULE = 'security/tls-cert-expiring-soon';
const EXPIRED_RULE = 'security/tls-cert-expired';

const DAY = 86_400_000;

function doc(...lines: string[]): Record<string, unknown> {
  return lint(lines.join('\n')).parsed ?? {};
}

const ONE_ENDPOINT = doc('WEB_AUTH_ENDPOINT="https://auth.example.com/sep10"');

/** A probe that always reports the same certificate expiry. */
function probeReturning(expiry: Date | null) {
  const calls: [string, number][] = [];
  const probe = async (host: string, port: number): Promise<Date | null> => {
    calls.push([host, port]);
    return expiry;
  };
  return { probe, calls };
}

describe('TLS certificate expiry audit', () => {
  it('is silent for a certificate valid for 180 days', async () => {
    const { probe } = probeReturning(new Date(Date.now() + 180 * DAY));
    expect(await checkCertExpiry(ONE_ENDPOINT, { probe })).toEqual([]);
  });

  it('is silent for a certificate valid for 35 days', async () => {
    const { probe } = probeReturning(new Date(Date.now() + 35 * DAY));
    expect(await checkCertExpiry(ONE_ENDPOINT, { probe })).toEqual([]);
  });

  it('warns when the certificate expires within 30 days', async () => {
    const { probe } = probeReturning(new Date(Date.now() + 10 * DAY));
    const diagnostics = await checkCertExpiry(ONE_ENDPOINT, { probe });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: EXPIRING_RULE,
        severity: 'warning',
        category: 'network',
        path: 'WEB_AUTH_ENDPOINT',
        message: expect.stringContaining('expires in 10 days'),
      }),
    );
  });

  it('warns when the certificate expires within days, not weeks', async () => {
    const { probe } = probeReturning(new Date(Date.now() + 2 * DAY));
    const diagnostics = await checkCertExpiry(ONE_ENDPOINT, { probe });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: EXPIRING_RULE,
        severity: 'warning',
        message: expect.stringContaining('expires in 2 days'),
      }),
    );
  });

  it('errors once the certificate is past expiration', async () => {
    const { probe } = probeReturning(new Date(Date.now() - DAY));
    const diagnostics = await checkCertExpiry(ONE_ENDPOINT, { probe });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: EXPIRED_RULE,
        severity: 'error',
        category: 'network',
        path: 'WEB_AUTH_ENDPOINT',
        message: expect.stringContaining('expired on'),
      }),
    );
  });

  it('stays silent when the certificate cannot be observed', async () => {
    const { probe, calls } = probeReturning(null);
    expect(await checkCertExpiry(ONE_ENDPOINT, { probe })).toEqual([]);
    expect(calls).toEqual([['auth.example.com', 443]]);
  });

  it('probes each host once, however many endpoints name it', async () => {
    const source = [
      'WEB_AUTH_ENDPOINT="https://api.example.com/auth"',
      'KYC_SERVER="https://api.example.com/kyc"',
      'TRANSFER_SERVER="https://api.example.com/sep6"',
    ].join('\n');
    const { probe, calls } = probeReturning(new Date(Date.now() + 10 * DAY));

    const diagnostics = await checkCertExpiry(doc(source), { probe });

    expect(calls).toEqual([['api.example.com', 443]]);
    expect(diagnostics).toHaveLength(1);
  });

  it('checks HORIZON_URL alongside the SEP endpoint fields', async () => {
    const { probe, calls } = probeReturning(new Date(Date.now() + 180 * DAY));
    await checkCertExpiry(doc('HORIZON_URL="https://horizon.example.com"'), { probe });
    expect(calls).toEqual([['horizon.example.com', 443]]);
  });

  it('ignores endpoints that are not https URLs', async () => {
    const { probe, calls } = probeReturning(new Date(Date.now() + DAY));
    await checkCertExpiry(
      doc(
        'TRANSFER_SERVER="http://api.example.com/sep6"',
        'WEB_AUTH_ENDPOINT="not a url"',
        'HORIZON_URL="https://horizon.example.com"',
      ),
      { probe },
    );
    expect(calls).toEqual([['horizon.example.com', 443]]);
  });

  it('opens no sockets when both rules are off', async () => {
    const { probe, calls } = probeReturning(new Date(Date.now() - DAY));
    const diagnostics = await checkCertExpiry(ONE_ENDPOINT, {
      probe,
      rules: { [EXPIRING_RULE]: 'off', [EXPIRED_RULE]: 'off' },
    });

    expect(diagnostics).toEqual([]);
    expect(calls).toEqual([]);
  });

  it('honours --off on a single rule', async () => {
    const { probe } = probeReturning(new Date(Date.now() + 10 * DAY));
    const diagnostics = await checkCertExpiry(ONE_ENDPOINT, {
      probe,
      rules: { [EXPIRING_RULE]: 'off' },
    });
    expect(diagnostics).toEqual([]);

    const expired = probeReturning(new Date(Date.now() - DAY));
    const kept = await checkCertExpiry(ONE_ENDPOINT, {
      probe: expired.probe,
      rules: { [EXPIRING_RULE]: 'off' },
    });
    expect(kept).toContainEqual(expect.objectContaining({ rule: EXPIRED_RULE }));
  });

  it('stays silent when the file declares no endpoints', async () => {
    const { probe, calls } = probeReturning(new Date(Date.now() - DAY));
    expect(await checkCertExpiry(doc('VERSION="2.7.0"'), { probe })).toEqual([]);
    expect(calls).toEqual([]);
  });

  it('registers the expected rule ids and severities', () => {
    expect(certExpiryRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: EXPIRED_RULE, severity: 'error' },
      { id: EXPIRING_RULE, severity: 'warning' },
    ]);
  });
});
