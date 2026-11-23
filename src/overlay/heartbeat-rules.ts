/**
 * Rule declarations for the overlay heartbeat watchdog.
 *
 * Kept apart from `heartbeatWatchdog.ts` because the watchdog owns a TCP socket
 * and imports Node built-ins, while the linter's rule registry is shared with the
 * browser bundle. Declaring the ids here keeps `src/rules/index.ts` free of
 * `node:net`.
 */

import type { Rule } from '../types.js';

export const HEARTBEAT_UNRESPONSIVE = 'overlay/heartbeat-unresponsive';
export const HEARTBEAT_ERRATIC = 'overlay/heartbeat-erratic';
export const HEARTBEAT_KEEPALIVE_DISABLED = 'overlay/heartbeat-keepalive-disabled';
export const HEARTBEAT_KEEPALIVE_DELAY = 'overlay/heartbeat-keepalive-delay';
export const HEARTBEAT_UNACKNOWLEDGED_SOCKET = 'overlay/heartbeat-unacknowledged-socket';
export const HEARTBEAT_SUDDEN_CLOSURE = 'overlay/heartbeat-sudden-closure';

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const overlayHeartbeatRules: Rule[] = [
  {
    id: HEARTBEAT_UNRESPONSIVE,
    category: 'network',
    severity: 'error',
    description: 'An advertised validator must acknowledge overlay heartbeat probes',
    run() {},
  },
  {
    id: HEARTBEAT_ERRATIC,
    category: 'network',
    severity: 'warning',
    description: 'Heartbeat latency jitter must stay within the configured overlay budget',
    run() {},
  },
  {
    id: HEARTBEAT_KEEPALIVE_DISABLED,
    category: 'network',
    severity: 'warning',
    description: 'Overlay sockets must enable TCP keepalive',
    run() {},
  },
  {
    id: HEARTBEAT_KEEPALIVE_DELAY,
    category: 'network',
    severity: 'warning',
    description: 'TCP keepalive initial delay must fit the overlay detection budget',
    run() {},
  },
  {
    id: HEARTBEAT_UNACKNOWLEDGED_SOCKET,
    category: 'network',
    severity: 'error',
    description: 'Overlay sockets must not retain unacknowledged probes',
    run() {},
  },
  {
    id: HEARTBEAT_SUDDEN_CLOSURE,
    category: 'network',
    severity: 'warning',
    description: 'Sudden overlay connection closures must be distinguished from idle timeouts',
    run() {},
  },
];

export const overlayHeartbeatRuleIds: readonly string[] = overlayHeartbeatRules.map(
  (rule) => rule.id,
);
