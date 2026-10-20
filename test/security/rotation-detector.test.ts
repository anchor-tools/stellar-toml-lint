import { describe, expect, it } from 'vitest';
import {
  STALE_SIGNING_KEY_POST_ROTATION_RULE,
  UNRECORDED_SIGNER_ADDITION_RULE,
  analyzeKeyRotations,
  checkKeyRotation,
  rotationEventsFromOperations,
} from '../../src/security/rotation-detector.js';

const SIGNING_KEY = 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN';
const NEW_KEY = 'GBVNNPOFVV2YNXSQXDJPBV2YJETLLMGGGGGGGGGGGGGGGGGGGGGGGGGGGG';
const ROTATION_AT = '2026-10-19T12:00:00Z';
const NOW = new Date('2026-10-20T12:00:00Z');

function operationsResponse(records: unknown[]): Response {
  return new Response(JSON.stringify({ _embedded: { records } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

describe('key rotation detector', () => {
  it('extracts set_options signer and master-weight changes', () => {
    const events = rotationEventsFromOperations(SIGNING_KEY, [
      { type: 'payment', created_at: ROTATION_AT },
      {
        type: 'set_options',
        created_at: ROTATION_AT,
        signer_key: NEW_KEY,
        signer_weight: 1,
        master_key_weight: 0,
      },
    ]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ account: SIGNING_KEY, signerKey: NEW_KEY });
  });

  it('passes when stellar.toml is updated within 24 hours of the rotation', () => {
    const diagnostics = analyzeKeyRotations(
      {
        signingKey: SIGNING_KEY,
        operations: [
          {
            type: 'set_options',
            created_at: ROTATION_AT,
            signer_key: SIGNING_KEY,
            signer_weight: 1,
          },
        ],
        tomlUpdatedAt: '2026-10-19T18:00:00Z',
        now: NOW,
      },
      { rules: {} },
    );
    expect(diagnostics.filter((d) => d.rule === STALE_SIGNING_KEY_POST_ROTATION_RULE)).toEqual([]);
  });

  it('flags a stale key after an on-chain rotation', () => {
    const diagnostics = analyzeKeyRotations({
      signingKey: SIGNING_KEY,
      operations: [
        { type: 'set_options', created_at: ROTATION_AT, signer_key: SIGNING_KEY, signer_weight: 1 },
      ],
      tomlUpdatedAt: '2026-10-18T12:00:00Z',
      now: NOW,
    });
    const finding = diagnostics.find((d) => d.rule === STALE_SIGNING_KEY_POST_ROTATION_RULE);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('error');
    expect(finding?.path).toBe('SIGNING_KEY');
  });

  it('flags a TOML update more than 24 hours after the rotation', () => {
    const diagnostics = analyzeKeyRotations({
      signingKey: SIGNING_KEY,
      operations: [
        { type: 'set_options', created_at: ROTATION_AT, signer_key: SIGNING_KEY, signer_weight: 1 },
      ],
      tomlUpdatedAt: '2026-10-21T12:00:00Z',
      now: NOW,
    });
    expect(diagnostics.map((d) => d.rule)).toContain(STALE_SIGNING_KEY_POST_ROTATION_RULE);
  });

  it('warns about an unrecorded signer addition', () => {
    const diagnostics = analyzeKeyRotations({
      signingKey: SIGNING_KEY,
      operations: [
        { type: 'set_options', created_at: ROTATION_AT, signer_key: NEW_KEY, signer_weight: 1 },
      ],
      tomlUpdatedAt: '2026-10-19T18:00:00Z',
      now: NOW,
    });
    expect(diagnostics.map((d) => d.rule)).toContain(UNRECORDED_SIGNER_ADDITION_RULE);
  });

  it('fetches operation history and asserts the stale rule', async () => {
    const fetchImpl = (async (input: string | URL | globalThis.Request) => {
      const url = String(input);
      if (url.includes('/operations')) {
        return operationsResponse([
          {
            type: 'set_options',
            created_at: ROTATION_AT,
            signer_key: SIGNING_KEY,
            signer_weight: 1,
          },
        ]);
      }
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const diagnostics = await checkKeyRotation(
      { SIGNING_KEY },
      {
        fetchImpl,
        horizonUrl: 'https://horizon.example',
        tomlUpdatedAt: '2026-10-18T00:00:00Z',
        now: NOW,
      },
    );
    expect(diagnostics.map((d) => d.rule)).toContain(STALE_SIGNING_KEY_POST_ROTATION_RULE);
  });

  it('degrades to silence when Horizon is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    expect(
      await checkKeyRotation(
        { SIGNING_KEY },
        { fetchImpl, horizonUrl: 'https://horizon.example', now: NOW },
      ),
    ).toEqual([]);
  });

  it('ignores rotations older than the 90-day window', () => {
    const diagnostics = analyzeKeyRotations({
      signingKey: SIGNING_KEY,
      operations: [
        {
          type: 'set_options',
          created_at: '2026-01-01T00:00:00Z',
          signer_key: SIGNING_KEY,
          signer_weight: 1,
        },
      ],
      tomlUpdatedAt: '2026-01-02T00:00:00Z',
      now: NOW,
    });
    expect(diagnostics).toEqual([]);
  });
});
