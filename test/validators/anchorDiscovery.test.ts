import { describe, expect, it, vi } from 'vitest';
import {
  type AnchorDiscoveryOptions,
  AnchorDiscoveryValidator,
  CAPABILITY_MISMATCH_RULE,
  DEFAULT_DIRECTORY_REGISTRIES,
  parseDirectoryRecords,
  PROFILE_OUT_OF_SYNC_RULE,
  REGISTRY_UNREACHABLE_RULE,
  SCHEMA_INVALID_RULE,
  validateAnchorDiscovery,
} from '../../src/validators/anchorDiscovery.js';

const ACCOUNT = 'GDG3MQ5KRQHKY2AEVD46HMMJS6YQ2SIBYUTNEYLUJ4NQIKRMXFQORS3F';

const doc = {
  DOCUMENTATION: {
    ORG_NAME: 'Example Anchor',
    ORG_URL: 'https://example.com',
  },
  ACCOUNTS: [ACCOUNT],
  TRANSFER_SERVER_SEP0024: 'https://example.com/sep24',
  DIRECT_PAYMENT_SERVER: 'https://api.example.com/sep31',
};

function records(entries: Record<string, unknown>[]): Response {
  return new Response(JSON.stringify({ _embedded: { records: entries } }), { status: 200 });
}

function inSyncEntry(): Record<string, unknown> {
  return {
    address: ACCOUNT,
    name: 'Example Anchor',
    domain: 'example.com',
    url: 'https://example.com',
    tags: ['anchor', 'sep24', 'sep-31'],
  };
}

function options(fetchImpl: typeof fetch, extra: Partial<AnchorDiscoveryOptions> = {}): AnchorDiscoveryOptions {
  return { fetchImpl, domain: 'example.com', ...extra };
}

describe('anchor discovery and directory listing compliance validator (#397)', () => {
  it('passes when the directory listing and stellar.toml agree', async () => {
    const fetchImpl = vi.fn(async () => records([inSyncEntry()])) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    expect(diagnostics).toEqual([]);
    expect(fetchImpl).toHaveBeenCalledWith(
      expect.stringContaining('api.stellar.expert/explorer/directory?search=example.com'),
      expect.anything(),
    );
  });

  it('asserts directory/profile-out-of-sync when ORG_URL differs from the listing URL', async () => {
    const fetchImpl = vi.fn(async () =>
      records([{ ...inSyncEntry(), url: 'https://old.example.com' }]),
    ) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    const findings = diagnostics.filter((d) => d.rule === PROFILE_OUT_OF_SYNC_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('warning');
    expect(findings[0]?.path).toBe('DOCUMENTATION.ORG_URL');
    expect(findings[0]?.message).toContain('https://old.example.com');
  });

  it('asserts profile-out-of-sync when the organisation name drifted', async () => {
    const fetchImpl = vi.fn(async () =>
      records([{ ...inSyncEntry(), name: 'Renamed Anchor Ltd' }]),
    ) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    expect(diagnostics.some((d) => d.rule === PROFILE_OUT_OF_SYNC_RULE)).toBe(true);
    expect(diagnostics[0]?.message).toContain('Renamed Anchor Ltd');
  });

  it('asserts profile-out-of-sync when directory accounts are missing from ACCOUNTS', async () => {
    const other = 'GDDOZFWVFZVVRG644A2XKBR5L53OLFIQKACZDSJIOI2HZVQ5H645NJKI';
    const fetchImpl = vi.fn(async () => records([{ ...inSyncEntry(), address: other }])) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    const finding = diagnostics.find((d) => d.rule === PROFILE_OUT_OF_SYNC_RULE);
    expect(finding?.path).toBe('ACCOUNTS');
  });

  it('asserts directory/capability-mismatch for a SEP the directory does not advertise', async () => {
    const fetchImpl = vi.fn(async () =>
      records([{ ...inSyncEntry(), tags: ['anchor', 'sep24'] }]),
    ) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    const findings = diagnostics.filter((d) => d.rule === CAPABILITY_MISMATCH_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('SEP-31');
    expect(findings[0]?.path).toBe('DIRECT_PAYMENT_SERVER');
  });

  it('asserts capability-mismatch for a stale SEP flag the file no longer declares', async () => {
    const fetchImpl = vi.fn(async () =>
      records([{ ...inSyncEntry(), tags: ['anchor', 'sep24', 'sep31', 'sep38'] }]),
    ) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    const findings = diagnostics.filter((d) => d.rule === CAPABILITY_MISMATCH_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('SEP-38');
  });

  it('handles registry timeouts gracefully with directory/registry-unreachable', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('The operation was aborted');
    }) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    const findings = diagnostics.filter((d) => d.rule === REGISTRY_UNREACHABLE_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('warning');
  });

  it('asserts directory/schema-invalid for an unrecognised feed shape', async () => {
    const fetchImpl = vi.fn(
      async () => new Response(JSON.stringify({ unexpected: true }), { status: 200 }),
    ) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, options(fetchImpl));

    expect(diagnostics.some((d) => d.rule === SCHEMA_INVALID_RULE)).toBe(true);
  });

  it('uses configurable directory endpoints and reports a missing listing', async () => {
    const fetchImpl = vi.fn(async () => records([])) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(
      doc,
      options(fetchImpl, {
        directories: [{ name: 'Internal Registry', url: 'https://registry.internal.example/directory' }],
      }),
    );

    expect(fetchImpl).toHaveBeenCalledWith(
      expect.stringContaining('registry.internal.example/directory?search=example.com'),
      expect.anything(),
    );
    const finding = diagnostics.find((d) => d.rule === PROFILE_OUT_OF_SYNC_RULE);
    expect(finding?.message).toContain('no directory entry for example.com');
  });

  it('derives the domain from DOCUMENTATION.ORG_URL when --domain is absent', async () => {
    const fetchImpl = vi.fn(async () => records([inSyncEntry()])) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(doc, { fetchImpl });
    expect(diagnostics).toEqual([]);
  });

  it('stays silent when no anchor domain can be determined', async () => {
    const fetchImpl = vi.fn(async () => records([])) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery({ CURRENCIES: [] }, { fetchImpl });
    expect(diagnostics).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('respects rule severity overrides', async () => {
    const fetchImpl = vi.fn(async () => records([{ ...inSyncEntry(), url: 'https://old.example.com' }])) as unknown as typeof fetch;

    const diagnostics = await validateAnchorDiscovery(
      doc,
      options(fetchImpl, { rules: { [PROFILE_OUT_OF_SYNC_RULE]: 'off' } }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('parses every recognised feed schema and normalizes capabilities', () => {
    expect(parseDirectoryRecords([{ domain: 'a.example' }])?.[0]?.domain).toBe('a.example');
    expect(parseDirectoryRecords({ records: [{ domain: 'b.example' }] })?.[0]?.domain).toBe(
      'b.example',
    );
    expect(parseDirectoryRecords({ _embedded: { records: [] } })).toEqual([]);
    expect(parseDirectoryRecords({ nope: true })).toBeUndefined();

    const [entry] = parseDirectoryRecords([
      {
        domain: 'c.example',
        tags: ['anchor', 'sep6'],
        seps: ['8'],
        capabilities: { sep24: true, sep38: false },
      },
    ]) ?? [];
    expect(entry?.seps).toEqual(['24', '6', '8']);
    expect(entry?.tags).toEqual(['anchor', 'sep6']);
    expect(DEFAULT_DIRECTORY_REGISTRIES.length).toBeGreaterThan(0);
  });

  it('exposes the class form for repeated audits', async () => {
    const fetchImpl = vi.fn(async () => records([inSyncEntry()])) as unknown as typeof fetch;
    const validator = new AnchorDiscoveryValidator(options(fetchImpl));

    await expect(validator.validate(doc)).resolves.toEqual([]);
    await expect(validator.validate(doc)).resolves.toEqual([]);
  });
});
