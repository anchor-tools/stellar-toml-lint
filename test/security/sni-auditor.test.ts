import { describe, expect, it, vi } from 'vitest';
import {
  checkSniFallback,
  SECURITY_SNI_FALLBACK_INFORMATION_LEAK,
} from '../../src/security/sni-auditor.js';

describe('TLS SNI fallback auditor', () => {
  it('passes when the server rejects missing SNI and the fallback certificate is public', async () => {
    const probe = vi.fn(async (_host: string, _port: number, servername?: string) =>
      servername === undefined ? null : { subjectAltName: 'DNS:anchor.example.com' },
    );

    await expect(
      checkSniFallback({ TRANSFER_SERVER: 'https://anchor.example.com' }, { probe }),
    ).resolves.toEqual([]);
    expect(probe).toHaveBeenCalledTimes(2);
  });

  it('reports private IPs and internal names in fallback certificates', async () => {
    const probe = async (_host: string, _port: number, servername?: string) =>
      servername === undefined
        ? { subjectAltName: 'DNS:payments.internal, IP Address:10.2.3.4' }
        : null;

    const diagnostics = await checkSniFallback(
      { TRANSFER_SERVER: 'https://anchor.example.com' },
      { probe },
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: SECURITY_SNI_FALLBACK_INFORMATION_LEAK,
      severity: 'warning',
      path: 'TRANSFER_SERVER',
    });
    expect(diagnostics[0]?.message).toContain('payments.internal');
    expect(diagnostics[0]?.message).toContain('10.2.3.4');
  });

  it('does not open TLS connections when its rule is disabled', async () => {
    const probe = vi.fn();
    await expect(
      checkSniFallback(
        { TRANSFER_SERVER: 'https://anchor.example.com' },
        { probe, rules: { [SECURITY_SNI_FALLBACK_INFORMATION_LEAK]: 'off' } },
      ),
    ).resolves.toEqual([]);
    expect(probe).not.toHaveBeenCalled();
  });
});
