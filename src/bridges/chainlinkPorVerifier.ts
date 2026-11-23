/**
 * Chainlink Proof of Reserve (PoR) feed verifier.
 *
 * Runs under opt-in `--verify-por-feed` (or `stellar-toml-lint verify-por-feed
 * --domain <domain>`); the oracle and Horizon are only queried with
 * `--check-network`.
 *
 * Feeds are declared in `[DOCUMENTATION.PROOF_OF_RESERVES]` as
 * `CHAINLINK_FEEDS = [{ asset, chain, aggregator, rpc?, heartbeat? }]`, or per
 * currency as `chainlink_por = { chain, aggregator, rpc?, heartbeat? }`. For
 * each feed the verifier reads `decimals()` and `latestRoundData()` from the
 * AggregatorV3 contract over JSON-RPC, then checks that the round is complete,
 * that `updatedAt` is within the heartbeat (at most 24 hours), and that the
 * reported reserve covers the asset's issued supply on Stellar. The
 * collateralization ratio of every probed feed is reported as an `info`
 * diagnostic.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, isRecord } from '../protocols/verifierSupport.js';
import {
  AMOUNT_SCALE,
  DEFAULT_EVM_RPC,
  EVM_ADDRESS,
  abiWords,
  bridgeRule,
  covers,
  diagnosticSink,
  ethCall,
  formatBps,
  formatUnits,
  horizonFor,
  ratioBps,
  resolveAsset,
  stellarSupply,
  toInt256,
} from './bridgeSupport.js';
import type { Push, RpcOptions, StellarAsset } from './bridgeSupport.js';

const INVALID_RULE = 'por/invalid-feed';
const RPC_RULE = 'por/rpc-unavailable';
const ANSWER_RULE = 'por/invalid-answer';
const ROUND_RULE = 'por/incomplete-round';
const STALE_RULE = 'por/stale-feed';
const SUPPLY_RULE = 'por/supply-unavailable';
const UNDER_RULE = 'por/undercollateralized';
const RATIO_RULE = 'por/collateralization';

const SPEC = 'https://docs.chain.link/data-feeds/proof-of-reserve';

/** Chainlink's maximum acceptable PoR heartbeat. */
export const MAX_HEARTBEAT_SECONDS = 86_400;
/** Tolerated clock skew before an `updatedAt` in the future is flagged. */
const FUTURE_SKEW_SECONDS = 300;

const SELECTOR_DECIMALS = '0x313ce567';
const SELECTOR_LATEST_ROUND = '0xfeaf968c';

export interface PorFeed {
  path: string;
  asset?: StellarAsset;
  chain: string;
  aggregator: string;
  rpc: string;
  heartbeat: number;
}

export interface PorRound {
  roundId: bigint;
  answer: bigint;
  startedAt: bigint;
  updatedAt: bigint;
  answeredInRound: bigint;
}

export interface PorFeedReport {
  path: string;
  aggregator: string;
  chain: string;
  reserve?: string;
  supply?: string;
  ageSeconds?: number;
  /** Reserve / supply as a percentage, e.g. `102.5%`. */
  collateralRatio?: string;
}

export interface ChainlinkPorOptions extends RpcOptions {
  rules?: RuleOverrides;
  /** Query the aggregator and Horizon. */
  probe?: boolean;
  /** Current time in ms; defaults to `Date.now()`. */
  now?: number;
  horizonUrl?: string;
  /** Known Stellar supplies keyed `CODE:ISSUER` or `CODE`, skipping Horizon. */
  supplies?: Record<string, string>;
}

export interface ChainlinkPorResult {
  diagnostics: Diagnostic[];
  feeds: PorFeedReport[];
}

/** Decodes the five ABI words returned by `latestRoundData()`. */
export function decodeLatestRoundData(data: Uint8Array): PorRound | undefined {
  const words = abiWords(data);
  if (words.length < 5) return undefined;
  const [roundId, answer, startedAt, updatedAt, answeredInRound] = words as [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
  ];
  return { roundId, answer: toInt256(answer), startedAt, updatedAt, answeredInRound };
}

/** Collects feed declarations with their TOML paths, valid or not. */
export function collectPorFeeds(
  doc: Record<string, unknown>,
): { path: string; entry: Record<string, unknown> | undefined; asset: unknown }[] {
  const out: { path: string; entry: Record<string, unknown> | undefined; asset: unknown }[] = [];
  const docs = isRecord(doc.DOCUMENTATION) ? doc.DOCUMENTATION : undefined;
  const por = docs && isRecord(docs.PROOF_OF_RESERVES) ? docs.PROOF_OF_RESERVES : undefined;
  if (por && Array.isArray(por.CHAINLINK_FEEDS)) {
    por.CHAINLINK_FEEDS.forEach((entry, i) => {
      out.push({
        path: `DOCUMENTATION.PROOF_OF_RESERVES.CHAINLINK_FEEDS[${i}]`,
        entry: isRecord(entry) ? entry : undefined,
        asset: isRecord(entry) ? entry.asset : undefined,
      });
    });
  }
  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((currency, i) => {
      if (!isRecord(currency) || currency.chainlink_por === undefined) return;
      const entry = currency.chainlink_por;
      out.push({
        path: `CURRENCIES[${i}].chainlink_por`,
        entry: isRecord(entry) ? entry : undefined,
        asset: isString(currency.issuer)
          ? `${String(currency.code)}:${currency.issuer}`
          : undefined,
      });
    });
  }
  return out;
}

function validateFeed(
  doc: Record<string, unknown>,
  decl: ReturnType<typeof collectPorFeeds>[number],
  push: Push,
): PorFeed | undefined {
  const invalid = (message: string, suggestion: string): undefined => {
    push(INVALID_RULE, 'error', message, decl.path, suggestion);
    return undefined;
  };
  const e = decl.entry;
  if (e === undefined)
    return invalid('Chainlink feed must be a table', 'Use { chain, aggregator }.');
  const asset = resolveAsset(doc, decl.asset);
  if (asset === undefined) {
    return invalid(
      'Chainlink feed does not name a Stellar asset declared in CURRENCIES',
      'Set asset = "CODE:ISSUER" (or a CODE declared once in CURRENCIES).',
    );
  }
  if (!isString(e.aggregator) || !EVM_ADDRESS.test(e.aggregator)) {
    return invalid(
      'Chainlink aggregator must be a 0x-prefixed 20-byte address',
      'Copy the PoR feed proxy address from data.chain.link.',
    );
  }
  const chain = isString(e.chain) ? e.chain.toLowerCase() : '';
  const rpc = e.rpc ?? DEFAULT_EVM_RPC[chain];
  if (!isHttpsUrl(rpc)) {
    return invalid(
      `Chainlink feed chain "${chain}" has no https RPC endpoint`,
      `Use one of ${Object.keys(DEFAULT_EVM_RPC).join(', ')} or set rpc = "https://...".`,
    );
  }
  const heartbeat = e.heartbeat ?? MAX_HEARTBEAT_SECONDS;
  if (typeof heartbeat !== 'number' || !Number.isInteger(heartbeat) || heartbeat <= 0) {
    return invalid('Chainlink heartbeat must be a positive integer of seconds', 'E.g. 86400.');
  }
  if (heartbeat > MAX_HEARTBEAT_SECONDS) {
    return invalid(
      `Chainlink heartbeat ${heartbeat}s exceeds the ${MAX_HEARTBEAT_SECONDS}s maximum`,
      'Reserves older than 24 hours cannot prove real-time solvency; use the feed heartbeat.',
    );
  }
  return { path: decl.path, asset, chain, aggregator: e.aggregator, rpc: rpc as string, heartbeat };
}

export class ChainlinkPorVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: ChainlinkPorOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<ChainlinkPorResult> {
    const diagnostics: Diagnostic[] = [];
    const feeds: PorFeedReport[] = [];
    const push = diagnosticSink(diagnostics, SPEC, this.options.rules);
    for (const decl of collectPorFeeds(doc)) {
      const feed = validateFeed(doc, decl, push);
      if (feed === undefined) continue;
      const report: PorFeedReport = {
        path: feed.path,
        aggregator: feed.aggregator,
        chain: feed.chain,
      };
      feeds.push(report);
      if (this.options.probe) await this.probe(doc, feed, report, push);
    }
    return { diagnostics, feeds };
  }

  private async probe(
    doc: Record<string, unknown>,
    feed: PorFeed,
    report: PorFeedReport,
    push: Push,
  ): Promise<void> {
    let decimals: number;
    let round: PorRound | undefined;
    try {
      const call = (data: string): Promise<Uint8Array> =>
        ethCall(this.fetchImpl, feed.rpc, feed.aggregator, data, this.options);
      decimals = Number(abiWords(await call(SELECTOR_DECIMALS))[0] ?? 0n);
      round = decodeLatestRoundData(await call(SELECTOR_LATEST_ROUND));
    } catch (error) {
      push(
        RPC_RULE,
        'warning',
        `Could not read Chainlink feed ${feed.aggregator} on ${feed.chain} (${errorMessage(error)})`,
        feed.path,
        'Check the RPC endpoint and aggregator address, or retry later if rate limited.',
      );
      return;
    }
    if (round === undefined || decimals > 36) {
      push(
        ANSWER_RULE,
        'error',
        'latestRoundData() returned malformed data',
        feed.path,
        'Check that the aggregator address implements AggregatorV3Interface.',
      );
      return;
    }
    if (round.answer <= 0n) {
      push(
        ANSWER_RULE,
        'error',
        `Chainlink feed reports a non-positive reserve (${round.answer})`,
        feed.path,
        'A zero or negative answer means the reserve is unreported; do not rely on this feed.',
      );
      return;
    }
    if (round.updatedAt === 0n || round.answeredInRound < round.roundId) {
      push(
        ROUND_RULE,
        'warning',
        `Chainlink round ${round.roundId} is incomplete (answeredInRound ${round.answeredInRound})`,
        feed.path,
        'The answer was carried over from an earlier round; treat it as stale.',
      );
    }
    const now = Math.floor((this.options.now ?? Date.now()) / 1000);
    const age = now - Number(round.updatedAt);
    report.ageSeconds = age;
    if (age < -FUTURE_SKEW_SECONDS) {
      push(
        STALE_RULE,
        'error',
        `Chainlink feed updatedAt is ${-age}s in the future`,
        feed.path,
        'Check the aggregator address; a future timestamp is not a real update.',
      );
    } else if (age > feed.heartbeat) {
      push(
        STALE_RULE,
        'error',
        `Chainlink feed was last updated ${age}s ago, beyond its ${feed.heartbeat}s heartbeat`,
        feed.path,
        'The aggregator may be obsolete; point the declaration at the live PoR feed proxy.',
      );
    }
    report.reserve = formatUnits(round.answer, decimals);
    await this.compareSupply(doc, feed, round.answer, decimals, report, push);
  }

  private async compareSupply(
    doc: Record<string, unknown>,
    feed: PorFeed,
    reserve: bigint,
    decimals: number,
    report: PorFeedReport,
    push: Push,
  ): Promise<void> {
    const asset = feed.asset as StellarAsset;
    let supply: bigint;
    try {
      const horizon = horizonFor(doc, this.options.horizonUrl);
      supply = await stellarSupply(
        this.fetchImpl,
        horizon,
        asset,
        this.options.supplies,
        this.options.timeoutMs,
      );
    } catch (error) {
      push(
        SUPPLY_RULE,
        'warning',
        `Could not read the Stellar supply of ${asset.code} (${errorMessage(error)})`,
        feed.path,
        'Check HORIZON_URL; collateralization cannot be computed without the issued supply.',
      );
      return;
    }
    report.supply = formatUnits(supply, AMOUNT_SCALE);
    if (supply === 0n) return;
    const ratio = formatBps(ratioBps(reserve, decimals, supply, AMOUNT_SCALE));
    report.collateralRatio = ratio;
    if (!covers(reserve, decimals, supply, AMOUNT_SCALE)) {
      push(
        UNDER_RULE,
        'error',
        `${asset.code} is undercollateralized: reserve ${report.reserve} covers ${ratio} of supply ${report.supply}`,
        feed.path,
        'Issued supply exceeds the attested reserve; pause issuance until reserves are restored.',
      );
    } else {
      push(
        RATIO_RULE,
        'info',
        `${asset.code} collateralization ${ratio} (reserve ${report.reserve}, supply ${report.supply})`,
        feed.path,
        'No action needed.',
      );
    }
  }
}

export async function verifyPorFeeds(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ChainlinkPorOptions = {},
): Promise<ChainlinkPorResult> {
  return new ChainlinkPorVerifier(fetchImpl, options).verify(doc);
}

export const chainlinkPorRules: Rule[] = [
  bridgeRule(INVALID_RULE, 'error', 'Chainlink PoR feed declarations must be well formed'),
  bridgeRule(RPC_RULE, 'warning', 'The Chainlink PoR aggregator must be readable over RPC'),
  bridgeRule(ANSWER_RULE, 'error', 'The Chainlink PoR answer must be a positive reserve'),
  bridgeRule(ROUND_RULE, 'warning', 'The latest Chainlink round must be complete'),
  bridgeRule(STALE_RULE, 'error', 'The Chainlink PoR feed must update within its heartbeat'),
  bridgeRule(SUPPLY_RULE, 'warning', 'The Stellar supply must be readable to check collateral'),
  bridgeRule(UNDER_RULE, 'error', 'The PoR reserve must cover the issued Stellar supply'),
  bridgeRule(RATIO_RULE, 'info', 'Reports the PoR collateralization ratio'),
];

export const chainlinkPorRuleIds: readonly string[] = chainlinkPorRules.map((r) => r.id);
