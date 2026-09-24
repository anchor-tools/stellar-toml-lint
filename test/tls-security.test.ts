import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint, lintDomain } from '../src/lint.js';
import { isDeprecatedTlsVersion, isWeakCipherSuite, weakCipherSuiteIn } from '../src/tls.js';
import type { TlsSession } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * The fixture that asserts zero diagnostics, so TLS is the only variable in
 * these cases — a clean session must keep it at zero.
 */
const CLEAN = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');

const session = (
  protocol: string | null,
  cipher: string | null,
  standard?: string,
): TlsSession => ({
  protocol,
  cipher,
  ...(standard === undefined ? {} : { cipherStandard: standard }),
});

/** A fetch stub, mirroring the one in lint-domain.test.ts. */
function stubFetch(body = CLEAN) {
  const impl = (async () => {
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' },
    });
  }) as unknown as typeof fetch;
  return { impl };
}

const ruleIds = (result: { diagnostics: { rule: string }[] }): string[] =>
  result.diagnostics.map((d) => d.rule);

describe('security/deprecated-tls-version', () => {
  it.each(['TLSv1', 'TLSv1.1', 'SSLv3'])('flags %s as deprecated', (protocol) => {
    const result = lint(CLEAN, { tls: session(protocol, 'TLS_AES_256_GCM_SHA384') });
    const [d] = result.diagnostics.filter((x) => x.rule === 'security/deprecated-tls-version');
    expect(d?.severity).toBe('warning');
    expect(d?.message).toBe(
      `Host negotiated deprecated protocol ${protocol}. Upgrade to TLS 1.2 or TLS 1.3.`,
    );
  });

  it.each(['TLSv1.2', 'TLSv1.3'])('accepts %s', (protocol) => {
    const result = lint(CLEAN, { tls: session(protocol, 'TLS_AES_256_GCM_SHA384') });
    expect(ruleIds(result)).not.toContain('security/deprecated-tls-version');
  });

  it('stays silent when no session was observed', () => {
    expect(ruleIds(lint(CLEAN))).not.toContain('security/deprecated-tls-version');
  });
});

describe('security/weak-cipher-suite', () => {
  it('flags a 3DES/CBC suite', () => {
    // The suite named in the rule request: both 3DES and CBC are weak.
    const result = lint(CLEAN, { tls: session('TLSv1.2', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA') });
    const [d] = result.diagnostics.filter((x) => x.rule === 'security/weak-cipher-suite');
    expect(d?.severity).toBe('warning');
    expect(d?.message).toBe('Host negotiated weak cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA.');
  });

  it.each([
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_NULL_SHA',
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'DES-CBC3-SHA',
  ])('flags %s', (cipher) => {
    const result = lint(CLEAN, { tls: session('TLSv1.2', cipher) });
    expect(ruleIds(result)).toContain('security/weak-cipher-suite');
  });

  it('catches a CBC suite whose OpenSSL name hides the mode', () => {
    // Node reports `name` (OpenSSL) and `standardName` (IANA). AES128-SHA256 is
    // a CBC suite, but only the IANA name says so.
    const result = lint(CLEAN, {
      tls: session('TLSv1.2', 'AES128-SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA256'),
    });
    const [d] = result.diagnostics.filter((x) => x.rule === 'security/weak-cipher-suite');
    expect(d?.message).toContain('TLS_RSA_WITH_AES_128_CBC_SHA256');
  });

  it.each([
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
  ])('accepts the AEAD suite %s', (cipher) => {
    const result = lint(CLEAN, { tls: session('TLSv1.3', cipher) });
    expect(ruleIds(result)).not.toContain('security/weak-cipher-suite');
  });

  it('stays silent when no session was observed', () => {
    expect(ruleIds(lint(CLEAN))).not.toContain('security/weak-cipher-suite');
  });
});

describe('a secure TLS session', () => {
  it('produces no diagnostics at all', () => {
    const result = lint(CLEAN, {
      tls: session('TLSv1.3', 'TLS_AES_256_GCM_SHA384', 'TLS_AES_256_GCM_SHA384'),
    });
    expect(result.diagnostics.map((d) => `${d.severity} ${d.rule}: ${d.message}`)).toEqual([]);
  });

  it('still passes in strict mode', () => {
    expect(
      lint(CLEAN, {
        tls: session('TLSv1.3', 'TLS_AES_256_GCM_SHA384'),
        strict: true,
      }).ok,
    ).toBe(true);
  });
});

describe('TLS predicates', () => {
  it('recognises retired protocols by exact version', () => {
    expect(isDeprecatedTlsVersion('TLSv1')).toBe(true);
    expect(isDeprecatedTlsVersion('TLSv1.1')).toBe(true);
    expect(isDeprecatedTlsVersion('tlsv1.1')).toBe(true);
    expect(isDeprecatedTlsVersion('TLSv1.2')).toBe(false);
    expect(isDeprecatedTlsVersion('TLSv1.3')).toBe(false);
    // A version that merely starts with a deprecated one must not match.
    expect(isDeprecatedTlsVersion('TLSv1.10')).toBe(false);
    expect(isDeprecatedTlsVersion(null)).toBe(false);
    expect(isDeprecatedTlsVersion(undefined)).toBe(false);
  });

  it('matches weak markers as tokens, not substrings', () => {
    expect(isWeakCipherSuite('TLS_RSA_WITH_3DES_EDE_CBC_SHA')).toBe(true);
    expect(isWeakCipherSuite('TLS_RSA_WITH_AES_256_GCM_SHA384')).toBe(false);
    // "DES" appears inside a longer token and must not match on its own.
    expect(isWeakCipherSuite('TLS_FANTASY_DESK_SHA')).toBe(false);
  });

  it('reports the suite name that exposed the weakness', () => {
    expect(
      weakCipherSuiteIn(session('TLSv1.2', 'AES128-SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA256')),
    ).toBe('TLS_RSA_WITH_AES_128_CBC_SHA256');
    expect(weakCipherSuiteIn(session('TLSv1.3', 'TLS_AES_256_GCM_SHA384'))).toBeUndefined();
  });
});

describe('lintDomain TLS audit', () => {
  it('reports the protocol and suite the host negotiated', async () => {
    const { impl } = stubFetch();
    const result = await lintDomain('example.com', {}, impl, async () =>
      session('TLSv1', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'),
    );
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining(['security/deprecated-tls-version', 'security/weak-cipher-suite']),
    );
  });

  it('probes the host it fetched, on the default port', async () => {
    const { impl } = stubFetch();
    const probe = vi.fn(async () => session('TLSv1.3', 'TLS_AES_256_GCM_SHA384'));
    await lintDomain('example.com', {}, impl, probe);
    expect(probe).toHaveBeenCalledWith('example.com', 443);
  });

  it('does not open a probe when both rules are switched off', async () => {
    const { impl } = stubFetch();
    const probe = vi.fn(async () => session('TLSv1', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'));
    const result = await lintDomain(
      'example.com',
      { rules: { 'security/deprecated-tls-version': 'off', 'security/weak-cipher-suite': 'off' } },
      impl,
      probe,
    );
    expect(probe).not.toHaveBeenCalled();
    expect(ruleIds(result)).not.toContain('security/deprecated-tls-version');
  });

  it('honours a severity override', async () => {
    const { impl } = stubFetch();
    const result = await lintDomain(
      'example.com',
      { rules: { 'security/deprecated-tls-version': 'error' } },
      impl,
      async () => session('TLSv1.1', null),
    );
    const d = result.diagnostics.find((x) => x.rule === 'security/deprecated-tls-version');
    expect(d?.severity).toBe('error');
  });

  it('does not probe when the caller injects a fetch without a probe', async () => {
    // Tests and embedders own the transport when they inject a fetch; the audit
    // must not reach out to a real host behind their back.
    const { impl } = stubFetch();
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).not.toContain('security/weak-cipher-suite');
    expect(ruleIds(result)).not.toContain('security/deprecated-tls-version');
  });
});
