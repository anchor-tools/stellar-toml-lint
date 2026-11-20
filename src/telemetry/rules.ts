import type { Rule } from '../types.js';

/** Rule metadata for diagnostics emitted by the asynchronous trace audit. */
export const telemetryRules: Rule[] = [
  {
    id: 'telemetry/correlation-observed',
    category: 'network',
    severity: 'info',
    description: 'A service response exposed valid W3C trace correlation metadata',
    run: () => {},
  },
  {
    id: 'telemetry/trace-restarted',
    category: 'network',
    severity: 'info',
    description: 'A service exposed valid trace metadata with a different trace ID',
    run: () => {},
  },
  {
    id: 'telemetry/correlation-unobservable',
    category: 'network',
    severity: 'info',
    description: 'A response did not expose trace correlation metadata',
    run: () => {},
  },
  {
    id: 'telemetry/invalid-correlation',
    category: 'network',
    severity: 'error',
    description: 'A service exposed malformed or inconsistent trace correlation metadata',
    run: () => {},
  },
  {
    id: 'telemetry/unreachable-endpoint',
    category: 'network',
    severity: 'warning',
    description: 'A service endpoint could not be safely reached for trace observation',
    run: () => {},
  },
  {
    id: 'telemetry/no-endpoints',
    category: 'network',
    severity: 'info',
    description: 'No audited anchor service endpoint was declared',
    run: () => {},
  },
];
