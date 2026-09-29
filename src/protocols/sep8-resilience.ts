export const SEP8_APPROVAL_SERVER_HIGH_LATENCY = 'sep8/approval-server-high-latency';
export const SEP8_APPROVAL_SERVER_UNRESPONSIVE = 'sep8/approval-server-unresponsive';

const DEFAULT_SAMPLES = 5;
const DEFAULT_FAILURE_TOLERANCE = 2;
const DEFAULT_SLA_MS = 3000;

export interface Sep8AuditOptions {
  /** Number of synthetic compliance requests to send (default 5). */
  samples?: number;
  /** Average latency above which the approval server is flagged as slow (default 3000ms). */
  slaMs?: number;
  /** Failures beyond this count mark the server unresponsive (default 2). */
  failureTolerance?: number;
  /** Override fetch for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Synthetic non-mutating transaction envelope sent as the compliance probe. */
  envelope?: string;
}

/**
 * SEP-8 approval server latency and resilience auditor.
 *
 * Sends `samples` non-mutating synthetic compliance requests (an HTTP error or
 * malformed envelope counts as a failed probe) and emits:
 * - `sep8/approval-server-unresponsive` when more than `failureTolerance`
 *   probes fail;
 * - `sep8/approval-server-high-latency` when the average successful response
 *   time exceeds `slaMs`.
 */
export async function auditSep8Timeout(
  serverUrl: string,
  options: Sep8AuditOptions = {},
): Promise<string[]> {
  const samples = options.samples ?? DEFAULT_SAMPLES;
  const slaMs = options.slaMs ?? DEFAULT_SLA_MS;
  const failureTolerance = options.failureTolerance ?? DEFAULT_FAILURE_TOLERANCE;
  const doFetch = options.fetchImpl ?? fetch;
  const envelope = options.envelope ?? 'AAAAAgAAAAB0ZXN0LWVuY2Vsb3BlAAAAAAAAAAAB';

  const diagnostics: string[] = [];
  let totalLatency = 0;
  let latencySamples = 0;
  let failures = 0;

  for (let i = 0; i < samples; i++) {
    const start = Date.now();
    try {
      const res = await doFetch(serverUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ tx: envelope }).toString(),
      });
      if (!res.ok) {
        throw new Error(`approval server responded with status ${res.status}`);
      }
      totalLatency += Date.now() - start;
      latencySamples++;
    } catch {
      // HTTP errors, malformed envelopes, and network failures all count
      // against the approval server's resilience.
      failures++;
    }
  }

  if (failures > failureTolerance) {
    diagnostics.push(SEP8_APPROVAL_SERVER_UNRESPONSIVE);
  } else if (latencySamples > 0 && totalLatency / latencySamples > slaMs) {
    diagnostics.push(SEP8_APPROVAL_SERVER_HIGH_LATENCY);
  }
  return diagnostics;
}
