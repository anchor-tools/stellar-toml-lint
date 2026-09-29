import { describe, expect, it, vi } from 'vitest';
import { verifyHistoryArchive } from '../src/validators/history.js';

const HISTORY = 'https://history.example.com/prd/core-live/core_live_001/';
const HAS = {
  version: 1,
  server: 'https://history.example.com/prd/core-live/core_live_001',
  currentLedger: 52_000_000,
};

function response(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

describe('verifyHistoryArchive', () => {
  it('accepts a valid HAS document and follows redirects', async () => {
    const fetchImpl = vi.fn(async () => Response.json(HAS)) as unknown as typeof fetch;
    const result = await verifyHistoryArchive(HISTORY, fetchImpl);
    expect(result).toEqual({ status: 'valid' });
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://history.example.com/prd/core-live/core_live_001/.well-known/stellar-history.json',
      { redirect: 'follow' },
    );
  });

  it('reports an S3 access-denied response as unreachable', async () => {
    const fetchImpl = vi.fn(async () => response('Access Denied', 403)) as unknown as typeof fetch;
    expect(await verifyHistoryArchive(HISTORY, fetchImpl)).toEqual({
      status: 'unreachable',
      message: 'the HAS file returned HTTP 403',
    });
  });

  it('reports a transport failure as unreachable', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('connection timed out');
    }) as unknown as typeof fetch;
    expect((await verifyHistoryArchive(HISTORY, fetchImpl)).status).toBe('unreachable');
  });

  it('reports malformed JSON separately', async () => {
    const fetchImpl = vi.fn(async () => response('{')) as unknown as typeof fetch;
    expect(await verifyHistoryArchive(HISTORY, fetchImpl)).toEqual({
      status: 'malformed',
      message: 'the HAS file is not valid JSON',
    });
  });

  it.each([
    [{ ...HAS, version: 0 }, 'version'],
    [{ ...HAS, version: 1.5 }, 'version'],
    [{ ...HAS, server: '' }, 'server'],
    [{ ...HAS, currentLedger: 0 }, 'currentLedger'],
    [{ ...HAS, currentLedger: 1.2 }, 'currentLedger'],
    [{ version: 1 }, 'server'],
  ])('rejects invalid HAS fields', async (body, field) => {
    const fetchImpl = vi.fn(async () => Response.json(body)) as unknown as typeof fetch;
    const result = await verifyHistoryArchive(HISTORY, fetchImpl);
    expect(result.status).toBe('malformed');
    if (result.status === 'malformed') expect(result.message).toContain(field);
  });
});
