import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { adaptiveFetch } from '../network/adaptive-client.js';
import { isString, isUrl } from '../predicates.js';

const CONTRADICTORY_RULE = 'fees/contradictory-fee-schedules';
const UNDISCLOSED_RULE = 'fees/undisclosed-percentage-fee';

const SEP1_CURRENCIES_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md#currency';

const EPSILON = 1e-9;

interface AuditOptions {
  rules?: RuleOverrides;
}

export interface FeeTier {
  minAmount?: number;
  maxAmount?: number;
  fixed?: number;
  percent?: number;
}

export interface FeeSchedule {
  fixed?: number;
  percent?: number;
  minimum?: number;
  maximum?: number;
  tiers?: FeeTier[];
}

interface DeclaredAsset {
  code: string;
  index: number;
  schedule: FeeSchedule | undefined;
  quoteAsset: string | undefined;
}

interface FeeSource {
  label: string;
  schedule: FeeSchedule;
}

interface InfoFees {
  deposit: Map<string, FeeSchedule>;
  withdraw: Map<string, FeeSchedule>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function numericField(
  record: Record<string, unknown>,
  names: readonly string[],
): number | undefined {
  for (const name of names) {
    const value = record[name];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (isString(value) && value.trim() !== '') {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return undefined;
}

function tiersOf(value: unknown): FeeTier[] | undefined {
  if (!Array.isArray(value)) return undefined;

  const tiers: FeeTier[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const tier: FeeTier = {};
    const minAmount = numericField(entry, ['min_amount', 'minAmount', 'min', 'from']);
    const maxAmount = numericField(entry, ['max_amount', 'maxAmount', 'max', 'to']);
    const fixed = numericField(entry, ['fee_fixed', 'fixed', 'fixed_fee']);
    const percent = numericField(entry, ['fee_percent', 'percent', 'percentage', 'percentage_fee']);
    if (minAmount !== undefined) tier.minAmount = minAmount;
    if (maxAmount !== undefined) tier.maxAmount = maxAmount;
    if (fixed !== undefined) tier.fixed = fixed;
    if (percent !== undefined) tier.percent = percent;
    if (tier.fixed !== undefined || tier.percent !== undefined) tiers.push(tier);
  }

  return tiers.length > 0 ? tiers : undefined;
}

export function normalizeFeeSchedule(value: unknown): FeeSchedule | undefined {
  if (!isRecord(value)) return undefined;

  const schedule: FeeSchedule = {};
  const fixed = numericField(value, ['fee_fixed', 'fixed', 'fixed_fee']);
  const percent = numericField(value, ['fee_percent', 'percent', 'percentage', 'percentage_fee']);
  const minimum = numericField(value, ['fee_minimum', 'min_fee', 'minimum']);
  const maximum = numericField(value, ['fee_maximum', 'max_fee', 'maximum']);
  const tiers = tiersOf(value.fee_tiers ?? value.feeTiers ?? value.tiers ?? value.fee_schedule);

  if (fixed !== undefined) schedule.fixed = fixed;
  if (percent !== undefined) schedule.percent = percent;
  if (minimum !== undefined) schedule.minimum = minimum;
  if (maximum !== undefined) schedule.maximum = maximum;
  if (tiers !== undefined) schedule.tiers = tiers;

  return Object.keys(schedule).length > 0 ? schedule : undefined;
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

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  path: string,
  helpUri: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];

  return [
    {
      rule,
      severity,
      category: 'fees',
      message: detail,
      path,
      helpUri,
      suggestion,
    },
  ];
}

function declaredAssets(doc: Record<string, unknown>): DeclaredAsset[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];

  const assets: DeclaredAsset[] = [];
  for (const [index, entry] of currencies.entries()) {
    if (!isRecord(entry) || entry.toml !== undefined || !isString(entry.code)) continue;
    const code = entry.code;
    if (code.length === 0) continue;

    let quoteAsset: string | undefined;
    if (code.toLowerCase() === 'native') {
      quoteAsset = 'stellar:XLM';
    } else if (isString(entry.issuer)) {
      quoteAsset = `stellar:${code}:${entry.issuer}`;
    }

    assets.push({ code, index, schedule: normalizeFeeSchedule(entry), quoteAsset });
  }
  return assets;
}

async function fetchInfoFees(base: string, fetchImpl: typeof fetch): Promise<InfoFees | undefined> {
  let response: Response;
  try {
    response = await fetchImpl(`${base}/info`);
  } catch {
    return undefined;
  }
  if (!response.ok) return undefined;

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return undefined;
  }
  if (!isRecord(body)) return undefined;

  const readDirection = (value: unknown): Map<string, FeeSchedule> => {
    const fees = new Map<string, FeeSchedule>();
    if (!isRecord(value)) return fees;
    for (const [code, entry] of Object.entries(value)) {
      const schedule = normalizeFeeSchedule(entry);
      if (schedule !== undefined) fees.set(code, schedule);
    }
    return fees;
  };

  return {
    deposit: readDirection(body.deposit),
    withdraw: readDirection(body.withdraw),
  };
}

async function fetchPriceFees(
  base: string,
  asset: DeclaredAsset,
  fetchImpl: typeof fetch,
): Promise<FeeSchedule | undefined> {
  if (asset.quoteAsset === undefined) return undefined;
  const url = `${base}/prices?sell_asset=${encodeURIComponent(asset.quoteAsset)}`;

  let response: Response;
  try {
    response = await fetchImpl(url);
  } catch {
    return undefined;
  }
  if (!response.ok) return undefined;

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return undefined;
  }
  if (!isRecord(body)) return undefined;

  const topLevel = normalizeFeeSchedule(body);
  if (topLevel !== undefined) return topLevel;

  const buyAssets = body.buy_assets;
  if (!Array.isArray(buyAssets)) return undefined;
  for (const entry of buyAssets) {
    const schedule = normalizeFeeSchedule(entry);
    if (schedule !== undefined) return schedule;
  }
  return undefined;
}

function valuesDiffer(values: readonly number[]): boolean {
  if (values.length < 2) return false;
  const min = Math.min(...values);
  const max = Math.max(...values);
  return max - min > EPSILON;
}

function describeSchedule(label: string, schedule: FeeSchedule): string {
  const parts: string[] = [];
  if (schedule.fixed !== undefined) parts.push(`fee_fixed ${schedule.fixed}`);
  if (schedule.percent !== undefined) parts.push(`fee_percent ${schedule.percent}`);
  return `${label} reports ${parts.join(' and ')}`;
}

function tierValuesDiffer(left: FeeSchedule, right: FeeSchedule): boolean {
  if (left.tiers === undefined || right.tiers === undefined) return false;
  if (left.tiers.length !== right.tiers.length) return true;

  return left.tiers.some((tier, index) => {
    const other = right.tiers?.[index];
    if (other === undefined) return true;
    if (
      tier.fixed !== undefined &&
      other.fixed !== undefined &&
      Math.abs(tier.fixed - other.fixed) > EPSILON
    ) {
      return true;
    }
    return (
      tier.percent !== undefined &&
      other.percent !== undefined &&
      Math.abs(tier.percent - other.percent) > EPSILON
    );
  });
}

function compareGroup(
  asset: DeclaredAsset,
  direction: string,
  sources: readonly FeeSource[],
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  if (sources.length < 2) return [];
  const diagnostics: Diagnostic[] = [];
  const path = `CURRENCIES[${asset.index}]`;

  const fixedValues = sources
    .map((source) => source.schedule.fixed)
    .filter((value): value is number => value !== undefined);
  if (valuesDiffer(fixedValues)) {
    diagnostics.push(
      ...finding(
        CONTRADICTORY_RULE,
        'error',
        `Fixed fees for ${asset.code} disagree across ${direction} declarations: ${sources
          .filter((source) => source.schedule.fixed !== undefined)
          .map((source) => describeSchedule(source.label, source.schedule))
          .join('; ')}`,
        `${path}.fee_fixed`,
        SEP1_CURRENCIES_URL,
        `Publish the same fixed fee in stellar.toml, SEP-6 /info, SEP-24 /info, and SEP-38 /prices for ${asset.code}.`,
        rules,
      ),
    );
  }

  const percentValues = sources
    .map((source) => source.schedule.percent)
    .filter((value): value is number => value !== undefined);
  if (valuesDiffer(percentValues)) {
    diagnostics.push(
      ...finding(
        CONTRADICTORY_RULE,
        'error',
        `Percentage fees for ${asset.code} disagree across ${direction} declarations: ${sources
          .filter((source) => source.schedule.percent !== undefined)
          .map((source) => describeSchedule(source.label, source.schedule))
          .join('; ')}`,
        `${path}.fee_percent`,
        SEP1_CURRENCIES_URL,
        `Publish the same percentage fee in stellar.toml, SEP-6 /info, SEP-24 /info, and SEP-38 /prices for ${asset.code}.`,
        rules,
      ),
    );
  }

  const tiered = sources.filter((source) => source.schedule.tiers !== undefined);
  for (let left = 0; left < tiered.length; left++) {
    for (let right = left + 1; right < tiered.length; right++) {
      const leftSource = tiered[left];
      const rightSource = tiered[right];
      if (leftSource === undefined || rightSource === undefined) continue;
      if (!tierValuesDiffer(leftSource.schedule, rightSource.schedule)) continue;

      diagnostics.push(
        ...finding(
          CONTRADICTORY_RULE,
          'error',
          `Tiered fee schedules for ${asset.code} disagree across ${direction} declarations between ${leftSource.label} and ${rightSource.label}`,
          `${path}.fee_tiers`,
          SEP1_CURRENCIES_URL,
          `Align the tiered fixed and percentage fees for ${asset.code} across every advertised endpoint.`,
          rules,
        ),
      );
    }
  }

  return diagnostics;
}

function compareUndisclosed(
  asset: DeclaredAsset,
  direction: string,
  declared: FeeSchedule | undefined,
  endpointSources: readonly FeeSource[],
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const declaredPercent = declared?.percent;
  if (declaredPercent === undefined) return [];

  return endpointSources.flatMap((source) => {
    const percent = source.schedule.percent;
    if (percent === undefined || percent <= declaredPercent + EPSILON) return [];
    return finding(
      UNDISCLOSED_RULE,
      'warning',
      `${source.label} charges ${percent}% for ${asset.code} ${direction}, above the ${declaredPercent}% declared in stellar.toml`,
      `CURRENCIES[${asset.index}].fee_percent`,
      SEP1_CURRENCIES_URL,
      `Disclose the ${percent}% ${direction} fee in stellar.toml or lower the fee advertised by ${source.label}.`,
      rules,
    );
  });
}

export async function checkCrossSepFees(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = adaptiveFetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const assets = declaredAssets(doc);
  if (assets.length === 0) return [];

  const transferServer =
    isString(doc.TRANSFER_SERVER) && isUrl(doc.TRANSFER_SERVER)
      ? doc.TRANSFER_SERVER.replace(/\/+$/, '')
      : undefined;
  const transferServerSep24 =
    isString(doc.TRANSFER_SERVER_SEP0024) && isUrl(doc.TRANSFER_SERVER_SEP0024)
      ? doc.TRANSFER_SERVER_SEP0024.replace(/\/+$/, '')
      : undefined;
  const quoteServer =
    isString(doc.ANCHOR_QUOTE_SERVER) && isUrl(doc.ANCHOR_QUOTE_SERVER)
      ? doc.ANCHOR_QUOTE_SERVER.replace(/\/+$/, '')
      : undefined;

  if (
    transferServer === undefined &&
    transferServerSep24 === undefined &&
    quoteServer === undefined
  ) {
    return [];
  }

  const sep6 =
    transferServer === undefined ? undefined : await fetchInfoFees(transferServer, fetchImpl);
  const sep24 =
    transferServerSep24 === undefined
      ? undefined
      : await fetchInfoFees(transferServerSep24, fetchImpl);

  const diagnostics: Diagnostic[] = [];
  for (const asset of assets) {
    const priceSchedule =
      quoteServer === undefined ? undefined : await fetchPriceFees(quoteServer, asset, fetchImpl);

    const tomlSource: FeeSource | undefined =
      asset.schedule === undefined
        ? undefined
        : { label: 'stellar.toml', schedule: asset.schedule };

    const depositSources: FeeSource[] = [];
    const withdrawSources: FeeSource[] = [];
    const priceSources: FeeSource[] = [];

    if (tomlSource !== undefined) {
      depositSources.push(tomlSource);
      withdrawSources.push(tomlSource);
      priceSources.push(tomlSource);
    }

    const add = (target: FeeSource[], label: string, schedule: FeeSchedule | undefined): void => {
      if (schedule !== undefined) target.push({ label, schedule });
    };

    add(depositSources, 'SEP-6 /info (deposit)', sep6?.deposit.get(asset.code));
    add(withdrawSources, 'SEP-6 /info (withdraw)', sep6?.withdraw.get(asset.code));
    add(depositSources, 'SEP-24 /info (deposit)', sep24?.deposit.get(asset.code));
    add(withdrawSources, 'SEP-24 /info (withdraw)', sep24?.withdraw.get(asset.code));
    add(priceSources, 'SEP-38 /prices', priceSchedule);

    diagnostics.push(
      ...compareGroup(asset, 'deposit', depositSources, options.rules),
      ...compareGroup(asset, 'withdraw', withdrawSources, options.rules),
      ...compareGroup(asset, 'quote', priceSources, options.rules),
      ...compareUndisclosed(
        asset,
        'deposit',
        asset.schedule,
        depositSources.slice(1),
        options.rules,
      ),
      ...compareUndisclosed(
        asset,
        'withdraw',
        asset.schedule,
        withdrawSources.slice(1),
        options.rules,
      ),
      ...compareUndisclosed(asset, 'quote', asset.schedule, priceSources.slice(1), options.rules),
    );
  }

  return diagnostics;
}

export const crossSepFeeRules: Rule[] = [
  {
    id: CONTRADICTORY_RULE,
    category: 'fees',
    severity: 'error',
    description:
      'Fixed, percentage, and tiered fees must agree across SEP-1, SEP-6, SEP-24, and SEP-38',
    run() {},
  },
  {
    id: UNDISCLOSED_RULE,
    category: 'fees',
    severity: 'warning',
    description: 'An endpoint must not charge a higher percentage fee than stellar.toml declares',
    run() {},
  },
];

export const crossSepFeeRuleIds: readonly string[] = crossSepFeeRules.map((rule) => rule.id);
