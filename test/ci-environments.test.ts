import { describe, expect, it } from 'vitest';
import {
  CI_ENVIRONMENTS,
  CI_ENVIRONMENT_NAMES,
  FUTURENET_NETWORK_PASSPHRASE,
  PUBLIC_NETWORK_PASSPHRASE,
  STANDALONE_NETWORK_PASSPHRASE,
  TESTNET_NETWORK_PASSPHRASE,
  checkNetworkIsolation,
  parseCiMatrix,
  resolveCiEnvironment,
} from '../src/gitops/ciEnvironments.js';

function toml(lines: Record<string, string>): string {
  return Object.entries(lines)
    .map(([key, value]) => `${key}="${value}"`)
    .join('\n');
}

describe('environment profiles', () => {
  it('covers development, staging, testnet and public', () => {
    expect(CI_ENVIRONMENT_NAMES).toEqual(['development', 'staging', 'testnet', 'public']);
    expect(CI_ENVIRONMENTS.public.allowedPassphrases).toEqual([PUBLIC_NETWORK_PASSPHRASE]);
    expect(CI_ENVIRONMENTS.testnet.checkNetworkByDefault).toBe(true);
    expect(CI_ENVIRONMENTS.development.checkNetworkByDefault).toBe(false);
  });

  it('resolves aliases case-insensitively', () => {
    expect(resolveCiEnvironment('Prod')).toBe('public');
    expect(resolveCiEnvironment(' mainnet ')).toBe('public');
    expect(resolveCiEnvironment('pubnet')).toBe('public');
    expect(resolveCiEnvironment('dev')).toBe('development');
    expect(resolveCiEnvironment('local')).toBe('development');
    expect(resolveCiEnvironment('stage')).toBe('staging');
    expect(resolveCiEnvironment('test')).toBe('testnet');
    expect(resolveCiEnvironment('futurenet')).toBeUndefined();
  });

  it('parses a --matrix list, deduplicating and keeping order', () => {
    expect(parseCiMatrix('testnet,public')).toEqual(['testnet', 'public']);
    expect(parseCiMatrix('prod, dev,,public, development')).toEqual(['public', 'development']);
    expect(() => parseCiMatrix('testnet,moon')).toThrow('Unknown environment "moon"');
    expect(() => parseCiMatrix(' , ')).toThrow('at least one environment');
  });
});

describe('checkNetworkIsolation', () => {
  it('accepts a file on its own network', () => {
    const source = toml({
      NETWORK_PASSPHRASE: TESTNET_NETWORK_PASSPHRASE,
      HORIZON_URL: 'https://horizon-testnet.stellar.org',
      TRANSFER_SERVER: 'https://testnet.anchor.example/sep6',
    });
    expect(checkNetworkIsolation(source, 'testnet')).toEqual([]);
    expect(checkNetworkIsolation(source, 'staging')).toEqual([]);
    expect(checkNetworkIsolation(source, 'development')).toEqual([]);
  });

  it('allows standalone and futurenet where the profile does', () => {
    expect(
      checkNetworkIsolation(
        toml({ NETWORK_PASSPHRASE: STANDALONE_NETWORK_PASSPHRASE }),
        'development',
      ),
    ).toEqual([]);
    expect(
      checkNetworkIsolation(
        toml({
          NETWORK_PASSPHRASE: FUTURENET_NETWORK_PASSPHRASE,
          HORIZON_URL: 'https://horizon-futurenet.stellar.org',
        }),
        'staging',
      ),
    ).toEqual([]);
  });

  it('flags a sandbox tenant declaring the public network, with its position', () => {
    const [finding, ...rest] = checkNetworkIsolation(
      `VERSION="2.7.0"\nNETWORK_PASSPHRASE="${PUBLIC_NETWORK_PASSPHRASE}"\n`,
      'staging',
    );
    expect(rest).toEqual([]);
    expect(finding).toMatchObject({
      rule: 'ci/network-passphrase-mismatch',
      severity: 'error',
      category: 'network',
      path: 'NETWORK_PASSPHRASE',
      position: { line: 2, column: 1 },
    });
    expect(finding?.message).toContain('declares the public network passphrase');
    expect(finding?.suggestion).toContain(TESTNET_NETWORK_PASSPHRASE);
  });

  it.each([
    [TESTNET_NETWORK_PASSPHRASE, 'testnet'],
    [FUTURENET_NETWORK_PASSPHRASE, 'futurenet'],
    [STANDALONE_NETWORK_PASSPHRASE, 'standalone'],
    ['My Private Network ; 2024', 'custom'],
  ])('flags production declaring %s', (passphrase, name) => {
    const findings = checkNetworkIsolation(toml({ NETWORK_PASSPHRASE: passphrase }), 'public');
    expect(findings.map((f) => f.rule)).toEqual(['ci/network-passphrase-mismatch']);
    expect(findings[0]?.message).toContain(`the ${name} network passphrase`);
  });

  it('requires an explicit passphrase everywhere except production', () => {
    const source = 'VERSION="2.7.0"\n';
    expect(checkNetworkIsolation(source, 'public')).toEqual([]);
    for (const env of ['development', 'staging', 'testnet'] as const) {
      const findings = checkNetworkIsolation(source, env);
      expect(findings.map((f) => f.rule)).toEqual(['ci/network-passphrase-missing']);
      expect(findings[0]).not.toHaveProperty('position');
    }
  });

  it('flags a well-known Horizon serving the wrong network', () => {
    const testnetHorizonInProd = checkNetworkIsolation(
      toml({
        NETWORK_PASSPHRASE: PUBLIC_NETWORK_PASSPHRASE,
        HORIZON_URL: 'https://horizon-testnet.stellar.org/',
      }),
      'public',
    );
    expect(testnetHorizonInProd.map((f) => f.rule)).toEqual(['ci/horizon-network-mismatch']);
    expect(testnetHorizonInProd[0]?.message).toContain('a testnet Horizon');

    const prodHorizonInTestnet = checkNetworkIsolation(
      toml({
        NETWORK_PASSPHRASE: TESTNET_NETWORK_PASSPHRASE,
        HORIZON_URL: 'https://horizon.stellar.org',
      }),
      'testnet',
    );
    expect(prodHorizonInTestnet.map((f) => f.rule)).toEqual(['ci/horizon-network-mismatch']);
    expect(prodHorizonInTestnet[0]?.position).toEqual({ line: 2, column: 1 });
  });

  it('flags development and staging endpoints in the production file', () => {
    const findings = checkNetworkIsolation(
      toml({
        NETWORK_PASSPHRASE: PUBLIC_NETWORK_PASSPHRASE,
        HORIZON_URL: 'https://horizon.stellar.org',
        TRANSFER_SERVER: 'https://staging.anchor.example/sep6',
        WEB_AUTH_ENDPOINT: 'http://localhost:8000/auth',
        KYC_SERVER: 'https://10.0.0.5/kyc',
        FEDERATION_SERVER: 'https://api.anchor.example/federation',
        DIRECT_PAYMENT_SERVER: 'https://qa-api.anchor.example/sep31',
        ANCHOR_QUOTE_SERVER: 'https://quotes.anchor.internal/sep38',
        AUTH_SERVER: 'https://192.168.1.4',
        TRANSFER_SERVER_SEP0024: 'https://172.20.0.1/sep24',
      }),
      'public',
    );
    expect(findings.map((f) => `${f.rule}:${f.path}`)).toEqual([
      'ci/non-production-endpoint:AUTH_SERVER',
      'ci/non-production-endpoint:TRANSFER_SERVER',
      'ci/non-production-endpoint:TRANSFER_SERVER_SEP0024',
      'ci/non-production-endpoint:KYC_SERVER',
      'ci/non-production-endpoint:WEB_AUTH_ENDPOINT',
      'ci/non-production-endpoint:ANCHOR_QUOTE_SERVER',
    ]);
  });

  it('judges a self-hosted Horizon by its hostname in production', () => {
    const findings = checkNetworkIsolation(
      toml({
        NETWORK_PASSPHRASE: PUBLIC_NETWORK_PASSPHRASE,
        HORIZON_URL: 'https://horizon.dev.anchor.example',
      }),
      'public',
    );
    expect(findings.map((f) => f.rule)).toEqual(['ci/non-production-endpoint']);
  });

  it('recognises loopback and link-local style hosts', () => {
    for (const host of ['127.0.0.1', '0.0.0.0', '[::1]', 'api.localhost', 'box.local']) {
      const findings = checkNetworkIsolation(
        toml({
          NETWORK_PASSPHRASE: PUBLIC_NETWORK_PASSPHRASE,
          TRANSFER_SERVER: `https://${host}/sep6`,
        }),
        'public',
      );
      expect(
        findings.map((f) => f.rule),
        host,
      ).toEqual(['ci/non-production-endpoint']);
    }
  });

  it('ignores non-string and unparseable URL values', () => {
    const source = `NETWORK_PASSPHRASE="${PUBLIC_NETWORK_PASSPHRASE}"\nTRANSFER_SERVER=42\nKYC_SERVER="not a url"\nHORIZON_URL="::"\n`;
    expect(checkNetworkIsolation(source, 'public')).toEqual([]);
  });

  it('omits the position when the source index cannot locate the key', () => {
    // An escaped key parses to NETWORK_PASSPHRASE but defeats the line scanner.
    const [finding] = checkNetworkIsolation(
      `"NETWORK\\u005FPASSPHRASE" = "${PUBLIC_NETWORK_PASSPHRASE}"\n`,
      'testnet',
    );
    expect(finding?.rule).toBe('ci/network-passphrase-mismatch');
    expect(finding).not.toHaveProperty('position');
  });

  it('returns nothing for files the linter cannot parse', () => {
    expect(checkNetworkIsolation('NETWORK_PASSPHRASE = = "x"', 'testnet')).toEqual([]);
  });

  it('tolerates a byte order mark and keeps linter-compatible columns', () => {
    const [finding] = checkNetworkIsolation(
      `${String.fromCharCode(0xfeff)}NETWORK_PASSPHRASE="${PUBLIC_NETWORK_PASSPHRASE}"\n`,
      'testnet',
    );
    expect(finding?.position).toEqual({ line: 1, column: 1 });
    expect(
      checkNetworkIsolation(
        `${String.fromCharCode(0xfeff)}NETWORK_PASSPHRASE="${TESTNET_NETWORK_PASSPHRASE}"\n`,
        'testnet',
      ),
    ).toEqual([]);
  });
});
