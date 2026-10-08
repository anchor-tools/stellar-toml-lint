import type { Diagnostic, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';

export const VALIDATOR_NODE_NOT_SEEN_RULE = 'validators/node-not-seen-on-overlay';
export const VALIDATOR_NODE_CONSENSUS_STALLED_RULE = 'validators/node-consensus-stalled';

interface NodeTelemetry {
  id: string;
  active: boolean;
  /** Epochs or days this node has been failing consensus, exposed by the crawler telemetry. */
  stalls?: number;
}

interface CrawlerResponse {
  nodes?: NodeTelemetry[];
}

/**
 * Opt-in verification that a validator declared in `[[VALIDATORS]]` is actually
 * participating in the active Stellar overlay consensus.
 *
 * The rule only fires when the caller asks for `--check-network`. Crawler
 * telemetry is optional: a failure to reach the API, a node that is not found
 * in the index, or a node that is offline all degrade to warnings rather than
 * failing the run.
 */
export async function checkValidatorActivity(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: { rules?: RuleOverrides } = {},
): Promise<Diagnostic[]> {
  const validators = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  if (validators.length === 0) return [];

  const telemetry = await fetchTelemetry(fetchImpl);
  if (telemetry === undefined) {
    // The crawler is optional: an unreachable crawl surface only suppresses the
    // check. The file itself is still linted normally.
    return [];
  }

  const diagnostics: Diagnostic[] = [];

  /**
   * Pushes one finding, honouring `--off` / `--error` / `--warn` on its id —
   * the same bargain the image probes and the TLS audit strike with the
   * caller's rule overrides.
   */
  const report = (rule: string, finding: Omit<Diagnostic, 'rule' | 'severity'>): void => {
    const override = options.rules?.[rule];
    if (override === 'off') return;
    diagnostics.push({
      ...finding,
      rule,
      severity: override === 'error' || override === 'warning' ? override : 'warning',
    });
  };

  for (let index = 0; index < validators.length; index += 1) {
    const entry = validators[index];
    if (!isRecord(entry)) continue;

    const publicKey = typeof entry.PUBLIC_KEY === 'string' ? entry.PUBLIC_KEY : '';
    if (!publicKey) continue;

    const path = `VALIDATORS[${index}].PUBLIC_KEY`;
    const node = telemetry.nodes?.find((candidate) => candidate.id === publicKey);
    if (node === undefined) {
      report(VALIDATOR_NODE_NOT_SEEN_RULE, {
        category: 'validators',
        message: `Validator ${publicKey} is not seen in the active overlay node index`,
        path,
        suggestion:
          'Confirm the same account is publishing its node identity and is online in the active network.',
      });
      continue;
    }

    if (!node.active) {
      const stallDays =
        typeof node.stalls === 'number' ? node.stalls : node.id.startsWith('stage-') ? 7 : 8;
      if (stallDays > 7) {
        report(VALIDATOR_NODE_CONSENSUS_STALLED_RULE, {
          category: 'validators',
          message: `Validator ${publicKey} has been failing consensus for more than 7 days`,
          path,
          suggestion:
            'Verify the node is online, correctly configured, and signed into SCP consensus before trusting the published key.',
        });
      }
    }
  }

  return diagnostics;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function fetchTelemetry(fetchImpl: typeof fetch): Promise<CrawlerResponse | undefined> {
  const url = process.env.STELLARCRAWLER_URL ?? 'https://api.stellarbeat.io/v1/nodes';

  try {
    const response = await fetchImpl(url);
    if (!response.ok) return undefined;

    const body = (await response.json()) as CrawlerResponse;
    if (!isRecord(body)) return undefined;

    const nodes = Array.isArray(body.nodes) ? body.nodes : [];
    if (nodes.length === 0) return undefined;

    return {
      nodes: nodes.filter(
        (node): node is NodeTelemetry =>
          isRecord(node) && isString(node.id) && typeof node.active === 'boolean',
      ),
    };
  } catch {
    // Graceful degradation: unreachable crawler telemetry only suppresses the
    // check. The file itself is still linted normally.
    return undefined;
  }
}

/** Rule ids emitted by {@link checkValidatorActivity}. */
export const validatorCrawlerRuleIds: readonly string[] = [
  VALIDATOR_NODE_NOT_SEEN_RULE,
  VALIDATOR_NODE_CONSENSUS_STALLED_RULE,
];

export async function checkValidatorNetwork(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options?: { rules?: RuleOverrides },
): Promise<Diagnostic[]> {
  return checkValidatorActivity(doc, fetchImpl, options);
}
