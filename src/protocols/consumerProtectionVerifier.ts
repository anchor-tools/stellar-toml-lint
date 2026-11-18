/**
 * Anchor dispute resolution and consumer protection policy verifier.
 *
 * Runs under opt-in `--audit-consumer-protection`; document reachability is
 * only probed with `--check-network`.
 *
 * Regulators (EU MiCA, US state money-transmitter rules) require complaint
 * and dispute channels to be disclosed. Wallets can only show them if the
 * anchor publishes them in `[DOCUMENTATION]`.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isEmail, isHttpsUrl, isString } from '../predicates.js';

const MISSING_RULE = 'consumerprotection/missing-field';
const INVALID_RULE = 'consumerprotection/invalid-field';
const UNREACHABLE_RULE = 'consumerprotection/dispute-url-unreachable';

const SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md#organization-documentation';

type Category = 'contact' | 'dispute' | 'jurisdiction' | 'licensing';

const REQUIRED_FIELDS: { key: string; category: Category }[] = [
  { key: 'ORG_COMPLAINTS_EMAIL', category: 'contact' },
  { key: 'ORG_DISPUTE_RESOLUTION_URL', category: 'dispute' },
  { key: 'ORG_JURISDICTION', category: 'jurisdiction' },
  { key: 'ORG_LICENSES', category: 'licensing' },
];

export interface ConsumerProtectionOptions {
  rules?: RuleOverrides;
  /** Probe the dispute resolution URL over HTTP. */
  checkReachability?: boolean;
}

export interface ScorecardItem {
  field: string;
  category: Category;
  status: 'pass' | 'fail';
  detail: string;
}

export interface ConsumerProtectionScorecard {
  items: ScorecardItem[];
  passed: number;
  total: number;
  /** 0-100. */
  score: number;
}

export interface ConsumerProtectionResult {
  diagnostics: Diagnostic[];
  scorecard: ConsumerProtectionScorecard;
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

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Looks in `[DOCUMENTATION]`, then `[DOCUMENTATION.ORG_LEGAL]`, then the root. */
function lookup(doc: Record<string, unknown>, key: string): unknown {
  const documentation = doc.DOCUMENTATION;
  if (isRecord(documentation)) {
    const legal = documentation.ORG_LEGAL;
    if (isRecord(legal) && legal[key] !== undefined) return legal[key];
    if (documentation[key] !== undefined) return documentation[key];
  }
  return doc[key];
}

function validate(key: string, value: unknown): string | undefined {
  switch (key) {
    case 'ORG_COMPLAINTS_EMAIL':
      return isString(value) && isEmail(value) ? undefined : 'must be a valid email address';
    case 'ORG_DISPUTE_RESOLUTION_URL':
      return isString(value) && isHttpsUrl(value) ? undefined : 'must be an https URL';
    case 'ORG_JURISDICTION':
      return isString(value) && value.trim() !== '' ? undefined : 'must be a non-empty string';
    default:
      return (isString(value) && value.trim() !== '') ||
        (Array.isArray(value) && value.length > 0 && value.every((v) => isString(v) && v !== ''))
        ? undefined
        : 'must be a non-empty string or list of licenses';
  }
}

export class ConsumerProtectionVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: ConsumerProtectionOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<ConsumerProtectionResult> {
    const diagnostics: Diagnostic[] = [];
    const items: ScorecardItem[] = [];
    const push = (
      rule: string,
      fallback: 'error' | 'warning',
      message: string,
      path: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'documentation',
        message,
        path: `DOCUMENTATION.ORG_LEGAL.${path}`,
        helpUri: SPEC,
        suggestion,
      });
    };

    for (const { key, category } of REQUIRED_FIELDS) {
      const value = lookup(doc, key);
      if (value === undefined) {
        items.push({ field: key, category, status: 'fail', detail: 'missing' });
        push(
          MISSING_RULE,
          'warning',
          `${key} is not declared`,
          key,
          `Publish ${key} so wallets can show consumers their complaint and dispute rights.`,
        );
        continue;
      }
      const problem = validate(key, value);
      if (problem !== undefined) {
        items.push({ field: key, category, status: 'fail', detail: problem });
        push(INVALID_RULE, 'warning', `${key} ${problem}`, key, `Fix the value of ${key}.`);
        continue;
      }
      items.push({ field: key, category, status: 'pass', detail: 'ok' });
    }

    const url = lookup(doc, 'ORG_DISPUTE_RESOLUTION_URL');
    if (this.options.checkReachability && isString(url) && isHttpsUrl(url)) {
      const problem = await this.probe(url);
      if (problem !== undefined) {
        const item = items.find((i) => i.field === 'ORG_DISPUTE_RESOLUTION_URL');
        if (item) {
          item.status = 'fail';
          item.detail = problem;
        }
        push(
          UNREACHABLE_RULE,
          'warning',
          `ORG_DISPUTE_RESOLUTION_URL ${problem}`,
          'ORG_DISPUTE_RESOLUTION_URL',
          'Serve the dispute resolution terms at a stable URL returning 200 OK with readable content.',
        );
      }
    }

    const passed = items.filter((i) => i.status === 'pass').length;
    return {
      diagnostics,
      scorecard: {
        items,
        passed,
        total: items.length,
        score: Math.round((passed / items.length) * 100),
      },
    };
  }

  private async probe(url: string): Promise<string | undefined> {
    try {
      const response = await this.fetchImpl(url);
      if (response.status !== 200) return `returned HTTP ${response.status}`;
      const body = await response.text();
      return body.trim() === '' ? 'returned an empty document' : undefined;
    } catch (error) {
      return `could not be reached (${error instanceof Error ? error.message : String(error)})`;
    }
  }
}

export async function auditConsumerProtection(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ConsumerProtectionOptions = {},
): Promise<ConsumerProtectionResult> {
  return new ConsumerProtectionVerifier(fetchImpl, options).verify(doc);
}

/** Renders the transparency scorecard as a plain-text checklist. */
export function renderScorecard(scorecard: ConsumerProtectionScorecard): string {
  const lines = scorecard.items.map(
    (i) =>
      `  [${i.status === 'pass' ? 'x' : ' '}] ${i.category.padEnd(12)} ${i.field}: ${i.detail}`,
  );
  return `Consumer protection scorecard: ${scorecard.score}% (${scorecard.passed}/${scorecard.total})\n${lines.join('\n')}\n`;
}

export const consumerProtectionRules: Rule[] = [
  {
    id: MISSING_RULE,
    category: 'documentation',
    severity: 'warning',
    description:
      'Anchors should disclose complaints contact, dispute URL, jurisdiction and licenses',
    run() {},
  },
  {
    id: INVALID_RULE,
    category: 'documentation',
    severity: 'warning',
    description: 'Consumer protection fields must be well-formed',
    run() {},
  },
  {
    id: UNREACHABLE_RULE,
    category: 'documentation',
    severity: 'warning',
    description: 'The dispute resolution URL must return 200 OK with readable terms',
    run() {},
  },
];

export const consumerProtectionRuleIds: readonly string[] = consumerProtectionRules.map(
  (rule) => rule.id,
);
