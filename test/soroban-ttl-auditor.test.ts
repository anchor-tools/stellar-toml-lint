import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import {
  DEFAULT_CRITICAL_BUFFER_LEDGERS,
  DEFAULT_MIN_BUFFER_LEDGERS,
  STORAGE_TTL_ARCHIVED_RULE,
  STORAGE_TTL_CRITICAL_RULE,
  STORAGE_TTL_EXPIRING_RULE,
  STORAGE_TTL_UNAVAILABLE_RULE,
  SorobanTtlAuditor,
  auditContractStorageTtl,
  auditTomlStorageTtl,
  classifyTtl,
  estimateExtendTtlResources,
  ledgersToDays,
  persistentStorageKey,
  storageKeysFromInstance,
  temporaryStorageKey,
  ttlThresholdsOf,
} from '../src/soroban/ttlAuditor.js';
import { contractCodeKey, contractDataInstanceKey, sorobanRuleIds } from '../src/soroban.js';
import { checkContracts } from '../src/rules/soroban.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const OTHER_CONTRACT = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
const RPC = 'https://soroban-testnet.stellar.org';
const LATEST = 1_000_000;

const instanceKey = contractDataInstanceKey(CONTRACT);
const balanceKey = persistentStorageKey(CONTRACT, xdr.ScVal.scvSymbol('balance'));
const tempKey = temporaryStorageKey(CONTRACT, xdr.ScVal.scvSymbol('quote'));
const codeKeyHash = Buffer.alloc(32, 7);
const codeKey = contractCodeKey(codeKeyHash);

function instanceEntryXdr(storage: xdr.ScVal[] = []): string {
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(codeKeyHash),
          storage: storage.map(
            (key) => new xdr.ScMapEntry({ key, val: xdr.ScVal.scvI64(new xdr.Int64(1)) }),
          ),
        }),
      ),
    }),
  ).toXDR('base64');
}

interface EntryMock {
  xdr?: string;
  liveUntilLedgerSeq?: number;
  lastModifiedLedgerSeq?: number;
}

/** An RPC that answers `getLedgerEntries` from a key → entry map. */
function rpcWith(entries: Map<string, EntryMock>): typeof fetch {
  return (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const found = request.params.keys
      .filter((key) => entries.has(key))
      .map((key) => ({ key, ...entries.get(key) }));
    return new Response(
      JSON.stringify({ jsonrpc: '2.0', id: 1, result: { latestLedger: LATEST, entries: found } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

const rulesOf = (diagnostics: { rule: string }[]) => diagnostics.map((d) => d.rule);

describe('estimateExtendTtlResources', () => {
  it('projects CPU, bytes, and fee bid from the entry count and extension', () => {
    const estimate = estimateExtendTtlResources(2, LATEST, LATEST + 100_000, LATEST + 200_000);

    expect(estimate).toEqual({
      entries: 2,
      extendToLedger: LATEST + 200_000,
      ledgerExtension: 100_000,
      cpuInstructions: 40_000 + 2 * 25_000,
      readBytes: 128,
      writeBytes: 256,
      resourceFeeStroops: 90_000 + 128 + 2 * 100_000 * 25,
      feeBidStroops: 90_000 + 128 + 2 * 100_000 * 25 + 100,
    });
  });

  it('uses the default extension when the entry has no live TTL', () => {
    const estimate = estimateExtendTtlResources(1, LATEST, undefined, LATEST + 10);
    expect(estimate.ledgerExtension).toBe(DEFAULT_MIN_BUFFER_LEDGERS);
  });

  it('clamps a negative entry count and an already-far TTL', () => {
    const estimate = estimateExtendTtlResources(-3, LATEST, LATEST + 900_000, LATEST + 10);
    expect(estimate.entries).toBe(0);
    expect(estimate.ledgerExtension).toBe(0);
    expect(estimate.cpuInstructions).toBe(40_000);
  });
});

describe('classifyTtl', () => {
  const thresholds = ttlThresholdsOf();

  it('marks an entry below the critical horizon as critical', () => {
    expect(classifyTtl(DEFAULT_CRITICAL_BUFFER_LEDGERS - 1, thresholds)).toBe('critical');
  });

  it('marks an entry between the horizons as expiring', () => {
    expect(classifyTtl(DEFAULT_MIN_BUFFER_LEDGERS - 1, thresholds)).toBe('expiring');
    expect(classifyTtl(DEFAULT_CRITICAL_BUFFER_LEDGERS, thresholds)).toBe('expiring');
  });

  it('marks a comfortable entry as healthy', () => {
    expect(classifyTtl(DEFAULT_MIN_BUFFER_LEDGERS, thresholds)).toBe('healthy');
  });

  it('marks a missing or passed TTL as archived', () => {
    expect(classifyTtl(undefined, thresholds)).toBe('archived');
    expect(classifyTtl(0, thresholds)).toBe('archived');
    expect(classifyTtl(-12, thresholds)).toBe('archived');
  });

  it('keeps the critical horizon at or below the renewal horizon', () => {
    expect(
      ttlThresholdsOf({ minBufferLedgers: 1_000, criticalBufferLedgers: 5_000 })
        .criticalBufferLedgers,
    ).toBe(1_000);
  });

  it('converts ledgers to days at five seconds per ledger', () => {
    expect(ledgersToDays(17_280)).toBe(1);
    expect(ledgersToDays(DEFAULT_MIN_BUFFER_LEDGERS)).toBe(30);
    expect(ledgersToDays(-1)).toBe(0);
  });
});

describe('storageKeysFromInstance', () => {
  it('lists persistent and temporary keys for every instance storage key', () => {
    const keys = storageKeysFromInstance(CONTRACT, instanceEntryXdr([xdr.ScVal.scvSymbol('a')]));
    expect(keys.map((entry) => entry.kind)).toEqual(['persistent', 'temporary']);
    expect(keys[0]?.key).toBe(persistentStorageKey(CONTRACT, xdr.ScVal.scvSymbol('a')));
    expect(keys[1]?.key).toBe(temporaryStorageKey(CONTRACT, xdr.ScVal.scvSymbol('a')));
  });

  it('returns nothing for a malformed or non-instance entry', () => {
    expect(storageKeysFromInstance(CONTRACT, 'not-xdr')).toEqual([]);
    expect(storageKeysFromInstance(CONTRACT, undefined)).toEqual([]);
  });
});

describe('auditContractStorageTtl', () => {
  function entriesWith(instanceTtl: number | undefined, extra: [string, EntryMock][] = []) {
    const entries = new Map<string, EntryMock>();
    entries.set(instanceKey, {
      xdr: instanceEntryXdr([xdr.ScVal.scvSymbol('balance')]),
      ...(instanceTtl === undefined ? {} : { liveUntilLedgerSeq: instanceTtl }),
    });
    entries.set(balanceKey, { liveUntilLedgerSeq: LATEST + 600_000 });
    entries.set(codeKey, { liveUntilLedgerSeq: LATEST + 600_000 });
    for (const [key, entry] of extra) entries.set(key, entry);
    return entries;
  }

  it('reports a healthy contract with no diagnostics', async () => {
    const report = await auditContractStorageTtl(
      CONTRACT,
      RPC,
      rpcWith(entriesWith(LATEST + 600_000)),
    );

    expect(report.contractId).toBe(CONTRACT);
    expect(report.latestLedger).toBe(LATEST);
    expect(report.diagnostics).toEqual([]);
    expect(report.extension).toBeUndefined();
    expect(report.entries.every((entry) => entry.health === 'healthy')).toBe(true);
    expect(report.entries.map((entry) => entry.kind)).toContain('instance');
  });

  it('warns when an entry sits inside the renewal buffer', async () => {
    const report = await auditContractStorageTtl(
      CONTRACT,
      RPC,
      rpcWith(entriesWith(LATEST + 400_000)),
    );

    expect(rulesOf(report.diagnostics)).toEqual([STORAGE_TTL_EXPIRING_RULE]);
    expect(report.diagnostics[0]).toMatchObject({ severity: 'warning', category: 'network' });
    expect(report.diagnostics[0]?.message).toContain('~23 days');
    expect(report.extension?.entries).toBe(1);
  });

  it('errors when an entry is inside the critical buffer', async () => {
    const report = await auditContractStorageTtl(
      CONTRACT,
      RPC,
      rpcWith(entriesWith(LATEST + 10_000)),
    );

    expect(rulesOf(report.diagnostics)).toContain(STORAGE_TTL_CRITICAL_RULE);
    expect(report.diagnostics[0]?.severity).toBe('error');
  });

  it('errors when the instance entry has already expired', async () => {
    const report = await auditContractStorageTtl(CONTRACT, RPC, rpcWith(entriesWith(LATEST - 50)));

    expect(report.entries[0]?.health).toBe('archived');
    expect(rulesOf(report.diagnostics)).toContain(STORAGE_TTL_ARCHIVED_RULE);
  });

  it('errors when an explicitly named temporary key is archived', async () => {
    const report = await auditContractStorageTtl(
      CONTRACT,
      RPC,
      rpcWith(entriesWith(LATEST + 600_000)),
      {
        storageKeys: [{ key: tempKey, kind: 'temporary', label: 'quote:USDC', required: true }],
      },
    );

    expect(rulesOf(report.diagnostics)).toEqual([STORAGE_TTL_ARCHIVED_RULE]);
    expect(report.diagnostics[0]?.message).toContain('temporary storage quote:USDC is archived');
  });

  it('handles a contract with zero storage keys', async () => {
    const entries = new Map<string, EntryMock>([
      [instanceKey, { xdr: instanceEntryXdr([]), liveUntilLedgerSeq: LATEST + 600_000 }],
      [codeKey, { liveUntilLedgerSeq: LATEST + 600_000 }],
    ]);
    const report = await auditContractStorageTtl(CONTRACT, RPC, rpcWith(entries));

    expect(report.diagnostics).toEqual([]);
    expect(report.entries.map((entry) => entry.kind)).toEqual(['instance', 'code']);
  });

  it('degrades to one warning when the RPC is unreachable', async () => {
    const down = (async () => {
      throw new Error('timeout');
    }) as unknown as typeof fetch;

    const report = await auditContractStorageTtl(CONTRACT, RPC, down);
    expect(rulesOf(report.diagnostics)).toEqual([STORAGE_TTL_UNAVAILABLE_RULE]);
    expect(report.diagnostics[0]?.severity).toBe('warning');
  });

  it('honours rule overrides', async () => {
    const report = await auditContractStorageTtl(
      CONTRACT,
      RPC,
      rpcWith(entriesWith(LATEST + 400_000)),
      { rules: { [STORAGE_TTL_EXPIRING_RULE]: 'off' } },
    );
    expect(report.diagnostics).toEqual([]);
  });

  it('honours a custom buffer', async () => {
    const report = await auditContractStorageTtl(
      CONTRACT,
      RPC,
      rpcWith(entriesWith(LATEST + 400_000)),
      { minBufferLedgers: 100_000, criticalBufferLedgers: 10_000 },
    );
    expect(report.diagnostics).toEqual([]);
  });
});

describe('SorobanTtlAuditor', () => {
  it('audits several contracts and keeps the reports in order', async () => {
    const entries = new Map<string, EntryMock>([
      [instanceKey, { xdr: instanceEntryXdr([]), liveUntilLedgerSeq: LATEST + 600_000 }],
      [codeKey, { liveUntilLedgerSeq: LATEST + 600_000 }],
    ]);
    const reports = await new SorobanTtlAuditor().auditAll(
      [CONTRACT, OTHER_CONTRACT],
      RPC,
      rpcWith(entries),
    );

    expect(reports.map((report) => report.contractId)).toEqual([CONTRACT, OTHER_CONTRACT]);
    expect(rulesOf(reports[0]!.diagnostics)).toEqual([]);
    // The second contract's instance entry is absent, which is archival.
    expect(rulesOf(reports[1]!.diagnostics)).toEqual([STORAGE_TTL_ARCHIVED_RULE]);
  });
});

describe('auditTomlStorageTtl', () => {
  const doc = (): Record<string, unknown> =>
    parse(
      [
        'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
        `WEB_AUTH_CONTRACT_ID = "${OTHER_CONTRACT}"`,
        '[[CURRENCIES]]',
        'code = "USDC"',
        `contract = "${CONTRACT}"`,
      ].join('\n'),
    ) as Record<string, unknown>;

  it('audits CURRENCIES contracts and WEB_AUTH_CONTRACT_ID', async () => {
    const entries = new Map<string, EntryMock>([
      [instanceKey, { xdr: instanceEntryXdr([]), liveUntilLedgerSeq: LATEST + 600_000 }],
      [codeKey, { liveUntilLedgerSeq: LATEST + 600_000 }],
    ]);
    const diagnostics = await auditTomlStorageTtl(doc(), rpcWith(entries));

    expect(rulesOf(diagnostics)).toEqual([STORAGE_TTL_ARCHIVED_RULE]);
  });

  it('stays silent when no network can be derived', async () => {
    const offline = parse(
      ['[[CURRENCIES]]', 'code = "USDC"', `contract = "${CONTRACT}"`].join('\n'),
    ) as Record<string, unknown>;
    const called = { count: 0 };
    const fetchSpy = (async () => {
      called.count++;
      return new Response('{}');
    }) as unknown as typeof fetch;

    expect(await auditTomlStorageTtl(offline, fetchSpy)).toEqual([]);
    expect(called.count).toBe(0);
  });

  it('runs from checkContracts when storageTtl is opted in', async () => {
    const entries = new Map<string, EntryMock>([
      [instanceKey, { xdr: instanceEntryXdr([]), liveUntilLedgerSeq: LATEST + 10_000 }],
      [codeKey, { liveUntilLedgerSeq: LATEST + 10_000 }],
    ]);

    const diagnostics = await checkContracts(doc(), rpcWith(entries), {
      rpcUrl: RPC,
      horizonUrl: 'http://horizon.invalid',
      storageTtl: {},
    });

    expect(rulesOf(diagnostics)).toContain(STORAGE_TTL_CRITICAL_RULE);
  });
});

describe('rule registration', () => {
  it('registers every storage TTL rule id', () => {
    for (const rule of [
      STORAGE_TTL_ARCHIVED_RULE,
      STORAGE_TTL_CRITICAL_RULE,
      STORAGE_TTL_EXPIRING_RULE,
      STORAGE_TTL_UNAVAILABLE_RULE,
    ]) {
      expect(sorobanRuleIds).toContain(rule);
    }
  });
});
