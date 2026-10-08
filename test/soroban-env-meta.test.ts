import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import { lint } from '../src/lint.js';
import {
  DEFAULT_PROTOCOL_VERSION,
  DEPRECATED_PROTOCOL_RULE,
  MISSING_ENV_META_RULE,
  auditTomlContractEnvMeta,
  envMetaRules,
  extractEnvMeta,
  verifyEnvMeta,
} from '../src/soroban/env-meta.js';
import {
  codeEntryXdr,
  envMetaWasm,
  instanceEntryXdr,
  rpcFetch,
  specWasm,
} from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const WASM_HASH = Buffer.alloc(32, 0x11);

function envMetaBytes(protocol: number, preRelease = 0): Buffer {
  return envMetaWasm([
    xdr.ScEnvMetaEntry.scEnvMetaKindInterfaceVersion(
      new xdr.ScEnvMetaEntryInterfaceVersion({ protocol, preRelease }),
    ),
  ]);
}

describe('soroban env-meta extractor (#80)', () => {
  it('extracts the interface version from the contractenvmetav0 section', () => {
    expect(extractEnvMeta(envMetaBytes(22, 3))).toEqual({ protocol: 22, preRelease: 3 });
  });

  it('returns undefined when the section is absent', () => {
    expect(extractEnvMeta(specWasm([]))).toBeUndefined();
  });

  it('passes when the contract was compiled against the current protocol version', () => {
    const diagnostics = verifyEnvMeta(envMetaBytes(DEFAULT_PROTOCOL_VERSION), CONTRACT, {
      protocolVersion: DEFAULT_PROTOCOL_VERSION,
    });
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/deprecated-protocol-version on an outdated protocol', () => {
    const diagnostics = verifyEnvMeta(envMetaBytes(20), CONTRACT, { protocolVersion: 22 });
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: DEPRECATED_PROTOCOL_RULE,
        severity: 'error',
        message: expect.stringContaining('protocol 20'),
      }),
    );
  });

  it('asserts soroban/missing-env-meta when the section is absent', () => {
    const diagnostics = verifyEnvMeta(specWasm([]), CONTRACT, { protocolVersion: 22 });
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: MISSING_ENV_META_RULE, severity: 'warning' }),
    );
  });

  it('fetches the contract WASM and audits it over the RPC', async () => {
    const { fetchImpl } = rpcFetch(
      instanceEntryXdr({ contractId: CONTRACT, wasmHash: WASM_HASH }),
      codeEntryXdr(envMetaBytes(22), WASM_HASH),
    );

    const source = [
      'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      `contract="${CONTRACT}"`,
    ].join('\n');
    const doc = lint(source).parsed ?? {};

    const diagnostics = await auditTomlContractEnvMeta(doc, fetchImpl, { protocolVersion: 22 });
    expect(diagnostics).toEqual([]);
  });

  it('registers both rule definitions', () => {
    expect(envMetaRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: MISSING_ENV_META_RULE, severity: 'warning' },
      { id: DEPRECATED_PROTOCOL_RULE, severity: 'error' },
    ]);
  });
});
