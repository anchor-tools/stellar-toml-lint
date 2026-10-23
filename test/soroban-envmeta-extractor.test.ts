import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  DEPRECATED_COMPILER_RULE,
  MALFORMED_ENVMETA_RULE,
  extractEnvMetaEntries,
  verifyEnvMeta,
} from '../src/soroban/envmeta-extractor.js';
import { envMetaWasm, specWasm, wasmWithCustomSection } from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';

function envMeta(protocol: number, preRelease = 0): Buffer {
  return envMetaWasm([
    xdr.ScEnvMetaEntry.scEnvMetaKindInterfaceVersion(
      new xdr.ScEnvMetaEntryInterfaceVersion({ protocol, preRelease }),
    ),
  ]);
}

describe('contractenvmetav0 extractor (#285)', () => {
  it('decodes interface-version entries', () => {
    expect(extractEnvMetaEntries(envMeta(22, 3))).toEqual({
      entries: [{ protocol: 22, preRelease: 3 }],
      malformed: false,
    });
  });

  it('treats an absent section as "no metadata", not as malformed XDR', () => {
    expect(extractEnvMetaEntries(specWasm([]))).toEqual({ entries: [], malformed: false });
  });

  it('reports a section that is not valid XDR as malformed', () => {
    const wasm = wasmWithCustomSection('contractenvmetav0', Buffer.from([0xff, 0x00]));
    const extraction = extractEnvMetaEntries(wasm);

    expect(extraction.malformed).toBe(true);
    expect(extraction.error).toBeTruthy();
  });

  it('passes a contract compiled against the active protocol', () => {
    expect(verifyEnvMeta(envMeta(22), CONTRACT, { protocolVersion: 22 })).toEqual([]);
  });

  it('asserts soroban/deprecated-compiler-version for an outdated toolchain', () => {
    const diagnostics = verifyEnvMeta(envMeta(20), CONTRACT, { protocolVersion: 22 });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: DEPRECATED_COMPILER_RULE,
        severity: 'warning',
        message: expect.stringContaining('protocol 20'),
      }),
    );
  });

  it('asserts soroban/malformed-envmeta-xdr when decoding fails', () => {
    const wasm = wasmWithCustomSection('contractenvmetav0', Buffer.from([0xff, 0x00]));
    const diagnostics = verifyEnvMeta(wasm, CONTRACT, { protocolVersion: 22 });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: MALFORMED_ENVMETA_RULE, severity: 'error' }),
    );
  });
});
