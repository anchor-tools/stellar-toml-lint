import type { Diagnostic, RuleOverrides } from '../types.js';
import { isString, isUrl, isInteger } from '../predicates.js';

export const BINARY_OUTDATED_RULE = 'validators/binary-outdated-for-upgrade';
export const MISSING_SCHEDULE_RULE = 'validators/missing-upgrade-vote-schedule';

interface NodeTelemetry {
  id: string;
  active: boolean;
  versionStr?: string;
  upgradeSchedule?: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

export async function checkUpgradeSimulator(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: { rules?: RuleOverrides } = {},
): Promise<Diagnostic[]> {
  const validators = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  if (validators.length === 0) return [];

  const horizonUrl = doc.HORIZON_URL;
  if (!isString(horizonUrl) || !isUrl(horizonUrl)) return [];

  let horizonResponse: Response;
  try {
    horizonResponse = await fetchImpl(horizonUrl);
  } catch {
    return [];
  }
  if (!horizonResponse.ok) return [];

  let horizonBody: unknown;
  try {
    horizonBody = await horizonResponse.json();
  } catch {
    return [];
  }

  if (!isRecord(horizonBody)) return [];
  const coreSupported = horizonBody.core_supported_protocol_version;
  const current = horizonBody.current_protocol_version;

  if (!isInteger(coreSupported) || !isInteger(current)) return [];
  if (coreSupported <= current) return [];

  const upcomingProtocol = coreSupported;

  const crawlerUrl = process.env.STELLARCRAWLER_URL ?? 'https://api.stellarbeat.io/v1/nodes';
  let telemetryNodes: NodeTelemetry[] = [];
  try {
    const crawlerResponse = await fetchImpl(crawlerUrl);
    if (crawlerResponse.ok) {
      const crawlerBody = await crawlerResponse.json();
      if (isRecord(crawlerBody) && Array.isArray(crawlerBody.nodes)) {
        telemetryNodes = crawlerBody.nodes.filter(
          (node): node is NodeTelemetry =>
            isRecord(node) && isString(node.id) && typeof node.active === 'boolean',
        );
      }
    }
  } catch {
    // Ignore crawler fetch error
  }

  const diagnostics: Diagnostic[] = [];

  for (let index = 0; index < validators.length; index += 1) {
    const entry = validators[index];
    if (!isRecord(entry)) continue;

    const publicKey = typeof entry.PUBLIC_KEY === 'string' ? entry.PUBLIC_KEY : '';
    if (!publicKey) continue;

    const path = `VALIDATORS[${index}].PUBLIC_KEY`;
    const node = telemetryNodes.find((candidate) => candidate.id === publicKey);

    if (!node) continue;

    // Check version
    if (node.versionStr) {
      const match = node.versionStr.match(/stellar-core (\d+)\./i);
      if (match) {
        const nodeMajorVersion = parseInt(match[1] as string, 10);
        if (nodeMajorVersion < upcomingProtocol) {
          const severity = severityFor(BINARY_OUTDATED_RULE, 'error', options.rules);
          if (severity) {
            diagnostics.push({
              rule: BINARY_OUTDATED_RULE,
              severity,
              category: 'validators',
              message: `Validator ${publicKey} is running stellar-core ${nodeMajorVersion}.x which does not support upcoming protocol ${upcomingProtocol}`,
              path,
              suggestion: `Upgrade validator node to stellar-core ${upcomingProtocol}.0.0 or newer.`,
            });
          }
          continue; // Already outdated, skip schedule check
        }
      }
    }

    // Check schedule if they support it
    // Some node schemas might expose `upgradeSchedule` or `schedule` or something similar.
    // If it's missing but they support the protocol, they haven't scheduled a vote.
    // Let's assume if `node.upgradeSchedule` is missing or null, they haven't voted.
    if (!node.upgradeSchedule) {
      const severity = severityFor(MISSING_SCHEDULE_RULE, 'warning', options.rules);
      if (severity) {
        diagnostics.push({
          rule: MISSING_SCHEDULE_RULE,
          severity,
          category: 'validators',
          message: `Validator ${publicKey} has not scheduled a vote for the upcoming protocol ${upcomingProtocol} upgrade`,
          path,
          suggestion:
            'Configure the upgradetime in the validator configuration to support the migration.',
        });
      }
    }
  }

  return diagnostics;
}
