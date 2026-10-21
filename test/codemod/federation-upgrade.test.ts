import { describe, expect, it } from 'vitest';
import {
  canonicalFederationServer,
  legacyLookupFlags,
  upgradeFederationDeclaration,
  FEDERATION_SERVER_INVALID_RULE,
  FEDERATION_SERVER_UNREACHABLE_RULE,
  FEDERATION_UPGRADE_APPLIED_RULE,
  FEDERATION_UPGRADE_SKIPPED_RULE,
  federationUpgradeRules,
} from '../../src/codemod/federation-upgrade.js';

const LEGACY_TOML = `# Legacy anchor configuration
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
FEDERATION_SERVER = "http://api.example.com/federation/?q={q}&type={type}" # keep this comment

[DOCUMENTATION]
ORG_NAME = "Example Anchor"
ORG_URL = "https://example.com"
`;

const CANONICAL_TOML = `VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
FEDERATION_SERVER = "https://api.example.com/federation"
`;

function unreachableFetch(): typeof fetch {
  return (async () => {
    throw new Error('connection refused');
  }) as unknown as typeof fetch;
}

function notFoundFetch(): typeof fetch {
  return (async () =>
    new Response('{"detail":"not found"}', {
      status: 404,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
}

describe('canonicalFederationServer', () => {
  it('upgrades http, removes the trailing slash, and keeps the path', () => {
    expect(canonicalFederationServer('http://api.example.com/federation/')).toBe(
      'https://api.example.com/federation',
    );
  });

  it('removes a legacy lookup template and query string', () => {
    expect(canonicalFederationServer('https://api.example.com/federation?q={q}&type={type}')).toBe(
      'https://api.example.com/federation',
    );
  });

  it('removes fragments and placeholder spellings', () => {
    expect(canonicalFederationServer('https://api.example.com/federation#reverse')).toBe(
      'https://api.example.com/federation',
    );
    expect(canonicalFederationServer('https://api.example.com/fed/%s')).toBe(
      'https://api.example.com/fed',
    );
  });

  it('defaults a bare host to the SEP-2 /federation path', () => {
    expect(canonicalFederationServer('api.example.com')).toBe('https://api.example.com/federation');
  });

  it('rejects an empty value', () => {
    expect(canonicalFederationServer('   ')).toBeUndefined();
  });
});

describe('legacyLookupFlags', () => {
  it('defaults an undifferentiated declaration to both lookups', () => {
    expect(legacyLookupFlags('https://api.example.com/federation')).toEqual({
      forward: true,
      reverse: true,
    });
  });

  it('preserves a reverse-only declaration', () => {
    expect(legacyLookupFlags('https://api.example.com/federation?type=id')).toEqual({
      forward: false,
      reverse: true,
    });
  });

  it('preserves a forward-only declaration', () => {
    expect(legacyLookupFlags('https://api.example.com/federation?type=name')).toEqual({
      forward: true,
      reverse: false,
    });
  });

  it('keeps both when the legacy template named both', () => {
    expect(legacyLookupFlags('https://api.example.com/f?q={q}&type={type}')).toEqual({
      forward: true,
      reverse: true,
    });
  });
});

describe('upgradeFederationDeclaration', () => {
  it('rewrites the declaration and keeps comments and unrelated keys', async () => {
    const result = await upgradeFederationDeclaration(LEGACY_TOML);

    expect(result.changed).toBe(true);
    expect(result.applied).toBe(true);
    expect(result.source).toContain('FEDERATION_SERVER = "https://api.example.com/federation"');
    expect(result.source).toContain('# keep this comment');
    expect(result.source).toContain('# Legacy anchor configuration');
    expect(result.source).toContain('ORG_NAME = "Example Anchor"');
    expect(result.diagnostics.some((d) => d.rule === FEDERATION_UPGRADE_APPLIED_RULE)).toBe(true);
  });

  it('prints a unified diff with the file path in the headers', async () => {
    const result = await upgradeFederationDeclaration(LEGACY_TOML, {
      filePath: 'anchor/stellar.toml',
    });

    expect(result.diff).toContain('--- a/anchor/stellar.toml');
    expect(result.diff).toContain('+++ b/anchor/stellar.toml');
    expect(result.diff).toContain('-FEDERATION_SERVER = "http://api.example.com/federation/');
    expect(result.diff).toContain('+FEDERATION_SERVER = "https://api.example.com/federation"');
  });

  it('is a no-op for an already canonical declaration', async () => {
    const result = await upgradeFederationDeclaration(CANONICAL_TOML);

    expect(result.changed).toBe(false);
    expect(result.applied).toBe(false);
    expect(result.source).toBe(CANONICAL_TOML);
    expect(result.federationServer).toBe('https://api.example.com/federation');
    expect(result.diagnostics.some((d) => d.rule === FEDERATION_UPGRADE_SKIPPED_RULE)).toBe(true);
  });

  it('reports a file with no federation declaration as skipped', async () => {
    const result = await upgradeFederationDeclaration(
      'VERSION = "2.7.0"\nNETWORK_PASSPHRASE = "Test SDF Network ; September 2015"\n',
    );

    expect(result.changed).toBe(false);
    expect(result.diagnostics.some((d) => d.rule === FEDERATION_UPGRADE_SKIPPED_RULE)).toBe(true);
  });

  it('reports an unusable declaration as an error', async () => {
    const result = await upgradeFederationDeclaration('FEDERATION_SERVER = "   "\n');

    expect(result.changed).toBe(false);
    const hit = result.diagnostics.find((d) => d.rule === FEDERATION_SERVER_INVALID_RULE);
    expect(hit?.severity).toBe('error');
  });

  it('probes both lookup directions under --check-network', async () => {
    const seen: string[] = [];
    const recordingFetch = (async (input: unknown) => {
      seen.push(String(input));
      return new Response('{}', { status: 404 });
    }) as unknown as typeof fetch;

    const result = await upgradeFederationDeclaration(LEGACY_TOML, {
      checkNetwork: true,
      fetchImpl: recordingFetch,
    });

    expect(seen.length).toBe(2);
    expect(seen[0]).toContain('type=name');
    expect(seen[1]).toContain('type=id');
    expect(result.diagnostics.some((d) => d.rule === FEDERATION_SERVER_UNREACHABLE_RULE)).toBe(
      false,
    );
  });

  it('warns when the rewritten endpoint is unreachable', async () => {
    const result = await upgradeFederationDeclaration(LEGACY_TOML, {
      checkNetwork: true,
      fetchImpl: unreachableFetch(),
    });

    const hit = result.diagnostics.find((d) => d.rule === FEDERATION_SERVER_UNREACHABLE_RULE);
    expect(hit?.severity).toBe('warning');
    expect(hit?.message).toContain('https://api.example.com/federation');
  });

  it('warns when every lookup answers 5xx', async () => {
    const failingFetch = (async () =>
      new Response('upstream down', { status: 503 })) as unknown as typeof fetch;

    const result = await upgradeFederationDeclaration(LEGACY_TOML, {
      checkNetwork: true,
      fetchImpl: failingFetch,
    });

    expect(result.diagnostics.some((d) => d.rule === FEDERATION_SERVER_UNREACHABLE_RULE)).toBe(
      true,
    );
  });

  it('treats a 404 for an unknown account as a healthy server', async () => {
    const result = await upgradeFederationDeclaration(LEGACY_TOML, {
      checkNetwork: true,
      fetchImpl: notFoundFetch(),
    });

    expect(result.diagnostics.some((d) => d.rule === FEDERATION_SERVER_UNREACHABLE_RULE)).toBe(
      false,
    );
  });

  it('honours a rule override that turns the warning off', async () => {
    const result = await upgradeFederationDeclaration(LEGACY_TOML, {
      checkNetwork: true,
      fetchImpl: unreachableFetch(),
      rules: { [FEDERATION_SERVER_UNREACHABLE_RULE]: 'off' },
    });

    expect(result.diagnostics.some((d) => d.rule === FEDERATION_SERVER_UNREACHABLE_RULE)).toBe(
      false,
    );
  });
});

describe('federationUpgradeRules', () => {
  it('registers every diagnostic id the codemod can emit', () => {
    const ids = federationUpgradeRules.map((rule) => rule.id);
    expect(ids).toEqual([
      FEDERATION_UPGRADE_APPLIED_RULE,
      FEDERATION_UPGRADE_SKIPPED_RULE,
      FEDERATION_SERVER_INVALID_RULE,
      FEDERATION_SERVER_UNREACHABLE_RULE,
    ]);
  });
});
