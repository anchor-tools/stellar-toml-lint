/**
 * SEP-38 delivery method and fee transparency verifier.
 *
 * Runs under `stellar-toml-lint verify-delivery-methods --domain <domain>`.
 *
 * SEP-38 quotes can settle off-chain through delivery methods such as bank
 * transfer, mobile money or cash pickup. Wallets can only show a transparent
 * cost breakdown if the anchor (a) advertises each method with a stable name
 * and a human description and (b) itemises the delivery charge in the quote
 * fee breakdown instead of folding it into an opaque total.
 *
 * The verifier reads `GET /info`, validates every `buy_delivery_methods` and
 * `sell_delivery_methods` entry, then books read-only quotes through those
 * methods and inspects `fee.details`. No quote is executed.
 */

import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import {
  fetchWithTimeout,
  isRecord,
  severityFor,
  toScaled,
  trimTrailingSlashes,
} from './verifierSupport.js';

const UNVERIFIABLE_RULE = 'sep38/delivery-unverifiable';
const INVALID_METHOD_RULE = 'sep38/delivery-method-invalid';
const DUPLICATE_METHOD_RULE = 'sep38/delivery-method-duplicate';
const MISSING_FEE_RULE = 'sep38/delivery-fee-missing';
const MISSING_BREAKDOWN_RULE = 'sep38/delivery-fee-breakdown-missing';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md';
const CATEGORY: RuleCategory = 'network';

/** Delivery method identifiers are lowercase tokens, not free-form prose. */
export const DELIVERY_METHOD_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

export type DeliveryDirection = 'buy' | 'sell';

export interface DeliveryMethod {
  name: string;
  description?: string;
}

export interface DeliveryMethodIssue {
  code: string;
  asset?: string;
  direction: DeliveryDirection;
  name?: string;
  message: string;
}

export interface DeliveryQuoteProbe {
  asset: string;
  direction: DeliveryDirection;
  method: string;
  status?: number;
  /** Delivery-fee entries found in `fee.details`. */
  itemisedDeliveryFees: number;
  /** True when the quote was returned and itemised the delivery charge. */
  transparent: boolean;
}

export interface Sep38DeliveryReport {
  quoteServer: string;
  assets: number;
  methods: number;
  probes: DeliveryQuoteProbe[];
  findings: { code: string; severity: Severity; message: string }[];
  ok: boolean;
}

export interface Sep38DeliveryResult {
  report: Sep38DeliveryReport;
  diagnostics: Diagnostic[];
}

export interface Sep38DeliveryOptions {
  rules?: RuleOverrides;
  /** Quote server base; defaults to `ANCHOR_QUOTE_SERVER`. */
  quoteServer?: string;
  /** SEP-10 token, when the quote server requires authentication. */
  token?: string;
  /** Pair to probe; defaults to the first advertised deliverable asset. */
  sellAsset?: string;
  buyAsset?: string;
  sellAmount?: string;
  timeoutMs?: number;
  /** Book a quote per method. Defaults to true. */
  checkQuotes?: boolean;
}

function ruleDiagnostics(
  code: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  path = 'ANCHOR_QUOTE_SERVER',
): Diagnostic[] {
  const severity = severityFor(code, fallback, rules);
  if (severity === undefined) return [];
  return [{ rule: code, severity, category: CATEGORY, message, path, helpUri: SPEC, suggestion }];
}

/**
 * Validates the delivery method arrays of one `/info` asset. Returns the
 * accepted methods and every schema issue found, so the caller can decide
 * whether a quote is still worth booking.
 */
export function validateDeliveryMethods(
  raw: unknown,
  direction: DeliveryDirection,
  asset?: string,
): { methods: DeliveryMethod[]; issues: DeliveryMethodIssue[] } {
  const field = `${direction}_delivery_methods`;
  const issues: DeliveryMethodIssue[] = [];
  const methods: DeliveryMethod[] = [];
  if (raw === undefined) return { methods, issues };
  if (!Array.isArray(raw)) {
    issues.push({
      code: INVALID_METHOD_RULE,
      direction,
      ...(asset === undefined ? {} : { asset }),
      message: `${field} is not an array`,
    });
    return { methods, issues };
  }

  const seen = new Set<string>();
  raw.forEach((entry, index) => {
    if (!isRecord(entry)) {
      issues.push({
        code: INVALID_METHOD_RULE,
        direction,
        ...(asset === undefined ? {} : { asset }),
        message: `${field}[${index}] is not an object`,
      });
      return;
    }
    const name = typeof entry.name === 'string' ? entry.name.trim() : '';
    const description = typeof entry.description === 'string' ? entry.description.trim() : '';
    if (name === '') {
      issues.push({
        code: INVALID_METHOD_RULE,
        direction,
        ...(asset === undefined ? {} : { asset }),
        message: `${field}[${index}].name is missing`,
      });
      return;
    }
    if (!DELIVERY_METHOD_NAME_PATTERN.test(name)) {
      issues.push({
        code: INVALID_METHOD_RULE,
        direction,
        name,
        ...(asset === undefined ? {} : { asset }),
        message: `${field}[${index}].name "${name}" is not a lowercase identifier`,
      });
    }
    if (description === '') {
      issues.push({
        code: INVALID_METHOD_RULE,
        direction,
        name,
        ...(asset === undefined ? {} : { asset }),
        message: `${field}[${index}] ("${name}") has no description`,
      });
    }
    if (seen.has(name)) {
      issues.push({
        code: DUPLICATE_METHOD_RULE,
        direction,
        name,
        ...(asset === undefined ? {} : { asset }),
        message: `${field} declares "${name}" more than once`,
      });
      return;
    }
    seen.add(name);
    methods.push({ name, ...(description === '' ? {} : { description }) });
  });

  return { methods, issues };
}

/** Reads `fee.details` and counts entries that itemise the delivery charge. */
export function countDeliveryFeeItems(
  fee: unknown,
  method: string,
): { details: number; delivery: number } {
  if (!isRecord(fee) || !Array.isArray(fee.details)) return { details: 0, delivery: 0 };
  let delivery = 0;
  for (const entry of fee.details) {
    if (!isRecord(entry)) continue;
    const name = typeof entry.name === 'string' ? entry.name.toLowerCase() : '';
    const description =
      typeof entry.description === 'string' ? entry.description.toLowerCase() : '';
    if (
      name.includes('deliver') ||
      description.includes('deliver') ||
      name === method.toLowerCase()
    ) {
      delivery += 1;
    }
  }
  return { details: fee.details.length, delivery };
}

/** `true` when the fee object is a well-formed SEP-38 fee with a total. */
export function isValidFee(fee: unknown): boolean {
  return (
    isRecord(fee) &&
    typeof fee.total === 'string' &&
    toScaled(fee.total) !== undefined &&
    typeof fee.asset === 'string' &&
    fee.asset.trim() !== ''
  );
}

export class Sep38DeliveryMethodVerifier {
  private readonly fetchImpl: typeof fetch;
  private readonly options: Sep38DeliveryOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: Sep38DeliveryOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  async audit(doc: Record<string, unknown>): Promise<Sep38DeliveryResult> {
    const quoteServer =
      this.options.quoteServer ??
      (typeof doc.ANCHOR_QUOTE_SERVER === 'string' ? doc.ANCHOR_QUOTE_SERVER : undefined);
    const report: Sep38DeliveryReport = {
      quoteServer: quoteServer ?? '',
      assets: 0,
      methods: 0,
      probes: [],
      findings: [],
      ok: false,
    };
    const diagnostics: Diagnostic[] = [];
    const add = (items: Diagnostic[]): void => {
      diagnostics.push(...items);
      for (const item of items) {
        report.findings.push({ code: item.rule, severity: item.severity, message: item.message });
      }
    };

    if (quoteServer === undefined) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          'No ANCHOR_QUOTE_SERVER is advertised, so delivery methods cannot be audited',
          'Publish ANCHOR_QUOTE_SERVER in stellar.toml.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const base = trimTrailingSlashes(quoteServer);
    let info: Record<string, unknown>;
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/info`,
        { method: 'GET', headers: { accept: 'application/json' } },
        this.options.timeoutMs ?? 8000,
      );
      if (!response.ok) {
        add(
          ruleDiagnostics(
            UNVERIFIABLE_RULE,
            'warning',
            `GET /info returned HTTP ${response.status}`,
            'Confirm ANCHOR_QUOTE_SERVER answers the SEP-38 info schema.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      const body: unknown = await response.json();
      if (!isRecord(body)) {
        add(
          ruleDiagnostics(
            UNVERIFIABLE_RULE,
            'warning',
            'SEP-38 /info response is not an object',
            'Return `{ "assets": [ ... ] }`.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      info = body;
    } catch (error) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          `GET /info failed: ${error instanceof Error ? error.message : String(error)}`,
          'Confirm ANCHOR_QUOTE_SERVER is reachable from the audit host.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const assets = Array.isArray(info.assets) ? info.assets.filter(isRecord) : [];
    report.assets = assets.length;
    if (assets.length === 0) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          'SEP-38 /info advertises no assets, so delivery methods cannot be audited',
          'List quoteable assets with their buy/sell delivery methods.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const quoteCandidates: { asset: string; direction: DeliveryDirection; method: string }[] = [];
    for (const asset of assets) {
      const label = typeof asset.asset === 'string' ? asset.asset : undefined;
      for (const direction of ['buy', 'sell'] as const) {
        const field = `${direction}_delivery_methods`;
        const { methods, issues } = validateDeliveryMethods(asset[field], direction, label);
        report.methods += methods.length;
        for (const issue of issues) {
          add(
            ruleDiagnostics(
              issue.code,
              'error',
              issue.message,
              `Document ${field} entries with a lowercase name and a human description.`,
              this.options.rules,
              label === undefined ? field : `${label}.${field}`,
            ),
          );
        }
        for (const method of methods) {
          quoteCandidates.push({
            asset: label ?? '',
            direction,
            method: method.name,
          });
        }
      }
    }

    if (this.options.checkQuotes !== false) {
      for (const candidate of quoteCandidates) {
        const probe = await this.probeQuote(base, candidate, assets);
        if (probe === undefined) continue;
        report.probes.push(probe);
        if (probe.status === undefined || probe.status >= 400) {
          add(
            ruleDiagnostics(
              MISSING_FEE_RULE,
              'warning',
              `POST /quote for ${candidate.direction} method "${candidate.method}" returned HTTP ${probe.status ?? 'n/a'}`,
              'Accept quotes that specify an advertised delivery method.',
              this.options.rules,
            ),
          );
          continue;
        }
        if (!probe.transparent) {
          add(
            ruleDiagnostics(
              probe.itemisedDeliveryFees === 0 ? MISSING_BREAKDOWN_RULE : MISSING_FEE_RULE,
              'error',
              `Quote for ${candidate.direction} method "${candidate.method}" does not itemise the delivery fee`,
              'Add a named delivery charge to `fee.details`.',
              this.options.rules,
            ),
          );
        }
      }
    }

    report.ok = report.findings.length === 0;
    return { report, diagnostics };
  }

  private async probeQuote(
    base: string,
    candidate: { asset: string; direction: DeliveryDirection; method: string },
    assets: Record<string, unknown>[],
  ): Promise<DeliveryQuoteProbe | undefined> {
    const sellAsset =
      this.options.sellAsset ??
      (candidate.direction === 'sell' ? candidate.asset : this.firstAsset(assets));
    const buyAsset =
      this.options.buyAsset ??
      (candidate.direction === 'buy' ? candidate.asset : this.firstAsset(assets, sellAsset));
    if (sellAsset === undefined || buyAsset === undefined || sellAsset === buyAsset)
      return undefined;

    const payload: Record<string, string> = {
      sell_asset: sellAsset,
      buy_asset: buyAsset,
      sell_amount: this.options.sellAmount ?? '1',
      context: 'sep38',
      ...(candidate.direction === 'sell'
        ? { sell_delivery_method: candidate.method }
        : { buy_delivery_method: candidate.method }),
    };
    const probe: DeliveryQuoteProbe = {
      asset: candidate.asset,
      direction: candidate.direction,
      method: candidate.method,
      itemisedDeliveryFees: 0,
      transparent: false,
    };
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/quote`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json',
            ...(this.options.token === undefined
              ? {}
              : { authorization: `Bearer ${this.options.token}` }),
          },
          body: JSON.stringify(payload),
        },
        this.options.timeoutMs ?? 8000,
      );
      probe.status = response.status;
      if (!response.ok) return probe;
      const body: unknown = await response.json();
      if (!isRecord(body)) return probe;
      const fee = body.fee;
      if (!isValidFee(fee)) return probe;
      const counts = countDeliveryFeeItems(fee, candidate.method);
      probe.itemisedDeliveryFees = counts.delivery;
      probe.transparent = counts.details > 0 && counts.delivery > 0;
      return probe;
    } catch {
      return probe;
    }
  }

  private firstAsset(assets: Record<string, unknown>[], exclude?: string): string | undefined {
    for (const asset of assets) {
      const label = typeof asset.asset === 'string' ? asset.asset : undefined;
      if (label !== undefined && label !== exclude) return label;
    }
    return undefined;
  }
}

export async function verifySep38DeliveryMethods(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep38DeliveryOptions = {},
): Promise<Sep38DeliveryResult> {
  return new Sep38DeliveryMethodVerifier(fetchImpl, options).audit(doc);
}

export function renderSep38DeliveryReport(report: Sep38DeliveryReport): string {
  const lines = [
    'SEP-38 delivery methods',
    `  quote server: ${report.quoteServer || 'not advertised'}`,
    `  assets:       ${report.assets}`,
    `  methods:      ${report.methods}`,
  ];
  for (const probe of report.probes) {
    lines.push(
      `  ${probe.direction} ${probe.method} (${probe.asset}): ${probe.transparent ? 'itemised' : 'not itemised'}`,
    );
  }
  lines.push(`  result:       ${report.ok ? 'PASS' : 'FAIL'}`);
  for (const finding of report.findings) {
    lines.push(`  [${finding.severity}] ${finding.code}: ${finding.message}`);
  }
  return `${lines.join('\n')}\n`;
}

export const sep38DeliveryRules: Rule[] = [
  {
    id: UNVERIFIABLE_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'SEP-38 delivery methods could not be audited',
    run() {},
  },
  {
    id: INVALID_METHOD_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-38 delivery methods need a valid name and description',
    run() {},
  },
  {
    id: DUPLICATE_METHOD_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-38 delivery methods must be unique per asset and direction',
    run() {},
  },
  {
    id: MISSING_FEE_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Delivery-method quotes must succeed and expose a fee',
    run() {},
  },
  {
    id: MISSING_BREAKDOWN_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Delivery-method quotes must itemise the delivery charge',
    run() {},
  },
];

export const sep38DeliveryRuleIds: readonly string[] = sep38DeliveryRules.map((rule) => rule.id);
