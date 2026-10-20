import { describe, expect, it } from 'vitest';
import {
  checkOverlayDos,
  OVERLAY_PEER_SOCKET_EXHAUSTION,
  OVERLAY_UNPROTECTED_CONNECTION_CHURN,
} from '../../src/overlay/dos-tester.js';

const doc = {
  VALIDATORS: [{ HOST: 'validator.example:11625' }],
};

describe('overlay DOS resilience tester', () => {
  it('passes a node that throttles sequential churn and remains responsive', async () => {
    let calls = 0;
    const diagnostics = await checkOverlayDos(doc, {
      probe: async () => {
        calls += 1;
        return calls <= 5
          ? { status: 'accepted', durationMs: 5 }
          : { status: 'backoff', durationMs: 20 };
      },
      authorizedProbe: async () => ({ status: 'accepted', durationMs: 5 }),
    });

    expect(calls).toBe(10);
    expect(diagnostics).toEqual([]);
  });

  it('reports warning and exhaustion when burst connections hang', async () => {
    const diagnostics = await checkOverlayDos(doc, {
      probe: async () => ({ status: 'timeout', durationMs: 2_000 }),
      authorizedProbe: async () => ({ status: 'timeout', durationMs: 2_000 }),
    });

    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toEqual([
      OVERLAY_UNPROTECTED_CONNECTION_CHURN,
      OVERLAY_PEER_SOCKET_EXHAUSTION,
    ]);
  });
});
