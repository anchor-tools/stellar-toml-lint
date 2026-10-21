import { describe, expect, it } from 'vitest';
import {
  simulateSep24Lifecycle,
  isValidTransition,
  sep24LifecycleRules,
  ILLEGAL_STATE_TRANSITION_RULE,
  MISSING_LIFECYCLE_TIMESTAMPS_RULE,
  SEP24_ALLOWED_TRANSITIONS,
  SEP24_TERMINAL_STATES,
} from '../../src/protocols/sep24-lifecycle.js';

const TRANSFER_SERVER = 'https://transfer.example.com/sep24';

const DOC = {
  TRANSFER_SERVER_SEP0024: TRANSFER_SERVER,
  CURRENCIES: [
    {
      code: 'USD',
      issuer: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      is_asset_anchored: true,
    },
  ],
};

const QUICK = { pollIntervalMs: 1, pollDurationMs: 500, maxPolls: 10 };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Serves an interactive deposit and then the supplied transaction payloads in
 * order. Once the list runs out the last payload is repeated, matching an
 * anchor that keeps answering with its terminal status.
 */
function lifecycleFetch(payloads: Array<Record<string, unknown>>): typeof fetch {
  let poll = 0;

  return (async (input: unknown, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = (init?.method ?? 'GET').toUpperCase();

    if (method === 'POST' && url.pathname.endsWith('/transactions/deposit/interactive')) {
      return jsonResponse({ id: 'txn-1', url: 'https://example.com/interactive' });
    }

    if (method === 'GET' && url.pathname.endsWith('/transaction')) {
      const payload = payloads[Math.min(poll, payloads.length - 1)] ?? {};
      poll += 1;
      return jsonResponse(payload);
    }

    return jsonResponse({ error: 'not found' }, 404);
  }) as unknown as typeof fetch;
}

describe('isValidTransition', () => {
  it('allows the documented forward edges', () => {
    expect(isValidTransition('incomplete', 'pending_user_transfer_start')).toBe(true);
    expect(isValidTransition('pending_user_transfer_start', 'pending_anchor')).toBe(true);
    expect(isValidTransition('pending_anchor', 'pending_stellar')).toBe(true);
    expect(isValidTransition('pending_stellar', 'completed')).toBe(true);
  });

  it('allows a repeated status', () => {
    expect(isValidTransition('pending_anchor', 'pending_anchor')).toBe(true);
    expect(isValidTransition('completed', 'completed')).toBe(true);
  });

  it('forbids leaving a terminal status', () => {
    for (const terminal of SEP24_TERMINAL_STATES) {
      expect(SEP24_ALLOWED_TRANSITIONS[terminal]).toEqual([]);
      expect(isValidTransition(terminal, 'pending_anchor')).toBe(false);
      if (terminal !== 'completed') {
        expect(isValidTransition(terminal, 'completed')).toBe(false);
      }
    }
  });

  it('forbids an unknown source status', () => {
    expect(isValidTransition('processing', 'completed')).toBe(false);
  });
});

describe('simulateSep24Lifecycle', () => {
  it('passes a valid progression to completed', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([
        { status: 'pending_user_transfer_start', started_at: '2026-10-21T00:00:00Z' },
        { status: 'pending_anchor', started_at: '2026-10-21T00:00:00Z' },
        {
          status: 'completed',
          started_at: '2026-10-21T00:00:00Z',
          completed_at: '2026-10-21T00:05:00Z',
        },
      ]),
      QUICK,
    );

    expect(diagnostics).toEqual([]);
  });

  it('passes a withdrawal-style external wait', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([
        { status: 'pending_user_transfer_start', started_at: '2026-10-21T00:00:00Z' },
        { status: 'pending_external', started_at: '2026-10-21T00:00:00Z' },
        { status: 'pending_anchor', started_at: '2026-10-21T00:00:00Z' },
        {
          status: 'completed',
          started_at: '2026-10-21T00:00:00Z',
          completed_at: '2026-10-21T00:10:00Z',
        },
      ]),
      QUICK,
    );

    expect(diagnostics).toEqual([]);
  });

  it('asserts sep24/illegal-state-transition when a completed transaction regresses', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([
        {
          status: 'completed',
          started_at: '2026-10-21T00:00:00Z',
          completed_at: '2026-10-21T00:05:00Z',
        },
        { status: 'pending_anchor' },
      ]),
      QUICK,
    );

    const hit = diagnostics.find((d) => d.rule === ILLEGAL_STATE_TRANSITION_RULE);
    expect(hit?.severity).toBe('error');
    expect(hit?.message).toContain('regressed from completed to pending_anchor');
  });

  it('asserts sep24/illegal-state-transition for an unknown status', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([{ status: 'processing', started_at: '2026-10-21T00:00:00Z' }]),
      QUICK,
    );

    const hit = diagnostics.find((d) => d.rule === ILLEGAL_STATE_TRANSITION_RULE);
    expect(hit?.severity).toBe('error');
    expect(hit?.message).toContain('unknown status "processing"');
  });

  it('asserts sep24/illegal-state-transition when status is missing', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([{ amount_in: '10' }]),
      QUICK,
    );

    const hit = diagnostics.find((d) => d.rule === ILLEGAL_STATE_TRANSITION_RULE);
    expect(hit?.message).toContain('no status');
  });

  it('asserts sep24/missing-lifecycle-timestamps for absent started_at and completed_at', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([{ status: 'pending_anchor' }, { status: 'completed' }]),
      QUICK,
    );

    const hits = diagnostics.filter((d) => d.rule === MISSING_LIFECYCLE_TIMESTAMPS_RULE);
    expect(hits.length).toBeGreaterThanOrEqual(2);
    expect(hits.every((d) => d.severity === 'warning')).toBe(true);
    expect(hits.some((d) => d.message.includes('started_at'))).toBe(true);
    expect(hits.some((d) => d.message.includes('completed_at'))).toBe(true);
  });

  it('stays silent without a transfer server', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      { CURRENCIES: [{ code: 'USD' }] },
      lifecycleFetch([{ status: 'completed' }]),
    );

    expect(diagnostics).toEqual([]);
  });

  it('stays silent when the interactive session cannot be opened', async () => {
    const refusing = (async () =>
      jsonResponse({ error: 'unauthorized' }, 401)) as unknown as typeof fetch;

    const diagnostics = await simulateSep24Lifecycle(DOC, refusing, QUICK);
    expect(diagnostics).toEqual([]);
  });

  it('stays silent when the transfer server is unreachable', async () => {
    const failing = (async () => {
      throw new Error('connection refused');
    }) as unknown as typeof fetch;

    const diagnostics = await simulateSep24Lifecycle(DOC, failing, QUICK);
    expect(diagnostics).toEqual([]);
  });

  it('honours a rule override that turns the transition check off', async () => {
    const diagnostics = await simulateSep24Lifecycle(
      DOC,
      lifecycleFetch([
        {
          status: 'completed',
          started_at: '2026-10-21T00:00:00Z',
          completed_at: '2026-10-21T00:05:00Z',
        },
        { status: 'pending_anchor' },
      ]),
      { ...QUICK, rules: { [ILLEGAL_STATE_TRANSITION_RULE]: 'off' } },
    );

    expect(diagnostics.filter((d) => d.rule === ILLEGAL_STATE_TRANSITION_RULE)).toEqual([]);
  });
});

describe('sep24LifecycleRules', () => {
  it('registers both diagnostics', () => {
    const byId = new Map(sep24LifecycleRules.map((rule) => [rule.id, rule]));
    expect([...byId.keys()]).toEqual([
      ILLEGAL_STATE_TRANSITION_RULE,
      MISSING_LIFECYCLE_TIMESTAMPS_RULE,
    ]);
    expect(byId.get(ILLEGAL_STATE_TRANSITION_RULE)?.severity).toBe('error');
    expect(byId.get(MISSING_LIFECYCLE_TIMESTAMPS_RULE)?.severity).toBe('warning');
  });
});
