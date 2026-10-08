import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  auditSep8Timeout,
  SEP8_APPROVAL_SERVER_HIGH_LATENCY,
  SEP8_APPROVAL_SERVER_UNRESPONSIVE,
} from '../src/protocols/sep8-resilience.js';

const slowFetch =
  (delayMs: number): typeof fetch =>
  () =>
    new Promise((resolve) => setTimeout(() => resolve({ ok: true } as Response), delayMs));

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('auditSep8Timeout', () => {
  it('passes a fast, healthy approval server', async () => {
    const fetchImpl = vi.fn(slowFetch(10));
    const diagnostics = await auditSep8Timeout('https://example.com/sep8', { fetchImpl });
    expect(diagnostics).toEqual([]);
    expect(fetchImpl).toHaveBeenCalledTimes(5);
  });

  it('reports approval-server-high-latency when average latency exceeds the 3000ms SLA', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    // Each probe takes 4000ms of mocked clock time; no real waiting occurs.
    const fetchImpl = vi.fn(() => {
      const startedAt = Date.now();
      return new Promise<Response>((resolve) => {
        setTimeout(() => {
          vi.setSystemTime(Date.now() + 4000);
          void startedAt;
          resolve({ ok: true } as Response);
        }, 4000);
      });
    });
    const diagnosticsPromise = auditSep8Timeout('https://example.com/sep8', { fetchImpl });
    await vi.runAllTimersAsync();
    const diagnostics = await diagnosticsPromise;
    expect(diagnostics).toContain(SEP8_APPROVAL_SERVER_HIGH_LATENCY);
  });

  it('reports approval-server-unresponsive when more than 2 of 5 probes fail', async () => {
    const fetchImpl = vi.fn(() => Promise.reject(new Error('timeout')));
    const diagnostics = await auditSep8Timeout('https://example.com/sep8', { fetchImpl });
    expect(diagnostics).toContain(SEP8_APPROVAL_SERVER_UNRESPONSIVE);
  });

  it('treats HTTP error responses (e.g. malformed transaction envelopes) as failures', async () => {
    let call = 0;
    const fetchImpl = vi.fn(() => {
      call++;
      // Three of five probes rejected with 400 (malformed envelope) is more
      // than the failure tolerance, so the server is unresponsive.
      if (call <= 3) {
        return Promise.resolve({ ok: false, status: 400 } as Response);
      }
      return Promise.resolve({ ok: true } as Response);
    });
    const diagnostics = await auditSep8Timeout('https://example.com/sep8', { fetchImpl });
    expect(diagnostics).toContain(SEP8_APPROVAL_SERVER_UNRESPONSIVE);
    expect(diagnostics).not.toContain(SEP8_APPROVAL_SERVER_HIGH_LATENCY);
  });

  it('stays quiet while failures are within tolerance', async () => {
    let call = 0;
    const fetchImpl = vi.fn(() => {
      call++;
      return call <= 2
        ? Promise.resolve({ ok: false, status: 503 } as Response)
        : Promise.resolve({ ok: true } as Response);
    });
    const diagnostics = await auditSep8Timeout('https://example.com/sep8', { fetchImpl });
    expect(diagnostics).toEqual([]);
  });
});
