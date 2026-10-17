/** Structured log-line rendering for reconcile outcomes. */

import type { ReconcileOutcome } from './controller.js';

/**
 * Renders one reconcile outcome as a single JSON log line, e.g.
 *
 * {"level":"info","resource":"default/acme","valid":true,
 *  "errors":0,"warnings":2,"configMap":"acme-stellar-toml"}
 *
 * Structured because operators ship these to Loki/CloudLogging, not eyeballs.
 */
export function formatOutcome(outcome: ReconcileOutcome): string {
  return JSON.stringify({
    level: outcome.syncError ? 'error' : 'info',
    resource: `${outcome.namespace}/${outcome.name}`,
    valid: outcome.validation.valid,
    errors: outcome.validation.counts.error,
    warnings: outcome.validation.counts.warning,
    ...(outcome.published.configMapName ? { configMap: outcome.published.configMapName } : {}),
    ...(outcome.published.ingressName ? { ingress: outcome.published.ingressName } : {}),
    ...(outcome.syncError ? { syncError: outcome.syncError } : {}),
  });
}
