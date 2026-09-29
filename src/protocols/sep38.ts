/**
 * SEP-38 Anchor Quotes and RFQ Pricing Engine Simulator.
 *
 * Runs under opt-in --check-network --verify-sep38.
 *
 * `rules/sep38-endpoints.ts` proves the ANCHOR_QUOTE_SERVER routes answer;
 * this engine proves the numbers they answer with. A wallet pricing a transfer
 * reads `GET /info` for the assets and countries it may trade, `GET /prices`
 * for the rate on each pair the stellar.toml declares, and `POST /quote` for a
 * number it has to settle before `expires_at`. Every one of those can be live,
 * well-formed, and still wrong: a pair the file declares that `/prices` never
 * quotes, a reverse rate that disagrees with the forward one by more than a
 * real bid-ask spread, an expiration already in the past. Those failures
 * surface at settlement, days after the file that advertised the endpoint
 * passed lint, so they are checked while the server is in front of us.
 *
 * Endpoint liveness stays with the plain `--check-network` probe: an
 * unreachable server, a 5xx, or a body that is not JSON is `checkSep38`'s
 * finding, and repeating it here would only double the report. What this engine
 * reports is what a liveness probe cannot see: the semantics of a response the
 * server was happy to send.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { currenciesOf } from '../rules/currencies.js';
import { sellAssetsOf } from '../rules/sep38-endpoints.js';

export const INFO_SCHEMA_INVALID_RULE = 'sep38/info-schema-invalid';
export const PRICES_MISSING_DECLARED_ASSET_RULE = 'sep38/prices-missing-declared-asset';
export const ABNORMAL_EXCHANGE_RATE_SPREAD_RULE = 'sep38/abnormal-exchange-rate-spread';
export const INVALID_QUOTE_EXPIRATION_RULE = 'sep38/invalid-quote-expiration';

/** The widest reverse-rate disagreement still read as an ordinary bid-ask spread. */
export const MAX_QUOTE_SPREAD_PERCENT = 15;

const SEP38_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md';

/** ISO 3166-1 alpha-2, optionally carrying an ISO 3166-2 subdivision (`US-NY`). */
const COUNTRY_CODE = /^[A-Za-z]{2}(-[A-Za-z0-9]{1,3})?$/;

/** The two quote kinds a client asks `POST /quote` for. */
const QUOTE_TYPES = ['firm', 'indicative'] as const;

export interface Sep38QuoteOptions {
  rules?: RuleOverrides;
}

/** One engine run: the endpoint under test, the transport, and what it found. */
interface Run {
  base: string;
  fetchImpl: typeof fetch;
  options: Sep38QuoteOptions;
  diagnostics: Diagnostic[];
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function report(
  run: Run,
  rule: string,
  fallback: 'error' | 'warning',
  path: string,
  message: string,
  suggestion: string,
): void {
  const severity = severityFor(rule, fallback, run.options.rules);
  if (severity === undefined) return;
  run.diagnostics.push({
    rule,
    severity,
    category: 'network',
    message,
    path,
    helpUri: SEP38_SPEC,
    suggestion,
  });
}

/**
 * The SEP-38 Asset Identification Format ids the file declares.
 *
 * Both legs of a quote have to be written down somewhere in the file: the
 * stellar asset comes from `[[CURRENCIES]]` as `stellar:CODE:ISSUER`, and a
 * fiat-anchored currency declares its off-chain leg through `anchor_asset`,
 * which is the `iso4217` side a quote server pairs it with.
 */
function declaredAssets(doc: Record<string, unknown>): string[] {
  const ids = new Set(sellAssetsOf(doc));
  for (const entry of currenciesOf(doc)) {
    if (entry.toml !== undefined) continue;
    if (entry.anchor_asset_type === 'fiat' && isString(entry.anchor_asset)) {
      ids.add(`iso4217:${entry.anchor_asset}`);
    }
  }
  return [...ids];
}

function pairKey(sell: string, buy: string): string {
  return `${sell} ${buy}`;
}

/**
 * `GET /info`: the assets the anchor quotes and the countries it quotes them
 * in. Both are what a wallet reads before it decides a pair can be offered at
 * all, so a malformed `assets` array or a country code no ISO 3166 registry
 * would recognise leaves the mapping unusable.
 *
 * Returns the asset to country-code map, or `null` when the response could not
 * be read at all.
 */
async function checkInfo(run: Run): Promise<Map<string, string[]> | null> {
  const url = `${run.base}/info`;

  let response: Response;
  try {
    response = await run.fetchImpl(url, { redirect: 'follow' });
  } catch (error) {
    report(
      run,
      INFO_SCHEMA_INVALID_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER',
      `Could not reach ANCHOR_QUOTE_SERVER /info at ${url}: ${errorMessage(error)}`,
      'Confirm ANCHOR_QUOTE_SERVER points at a live SEP-38 server and is reachable.',
    );
    return null;
  }

  if (!response.ok) {
    report(
      run,
      INFO_SCHEMA_INVALID_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER',
      `ANCHOR_QUOTE_SERVER /info returned HTTP ${response.status}`,
      'SEP-38 requires GET /info to answer 200 with an `assets` array.',
    );
    return null;
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    report(
      run,
      INFO_SCHEMA_INVALID_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER',
      'ANCHOR_QUOTE_SERVER /info did not return valid JSON',
      'Return application/json: a wallet cannot read quotable assets from HTML or plain text.',
    );
    return null;
  }

  if (!isRecord(body) || !Array.isArray(body.assets)) {
    report(
      run,
      INFO_SCHEMA_INVALID_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER',
      'ANCHOR_QUOTE_SERVER /info is missing the `assets` array',
      'Respond with a JSON object whose `assets` array lists every asset the anchor quotes.',
    );
    return null;
  }

  const countryCodes = new Map<string, string[]>();

  for (const [index, entry] of body.assets.entries()) {
    if (!isRecord(entry)) {
      report(
        run,
        INFO_SCHEMA_INVALID_RULE,
        'error',
        'ANCHOR_QUOTE_SERVER',
        `ANCHOR_QUOTE_SERVER /info assets[${index}] must be an object`,
        'Each assets entry describes one quotable asset with an `asset` identifier.',
      );
      continue;
    }

    if (!isString(entry.asset) || entry.asset.length === 0) {
      report(
        run,
        INFO_SCHEMA_INVALID_RULE,
        'error',
        'ANCHOR_QUOTE_SERVER',
        `ANCHOR_QUOTE_SERVER /info assets[${index}] is missing its \`asset\` identifier`,
        'Give every assets entry a SEP-38 Asset Identification Format id such as `iso4217:USD`.',
      );
      continue;
    }

    const codes: string[] = [];
    if (entry.country_codes !== undefined) {
      if (!Array.isArray(entry.country_codes)) {
        report(
          run,
          INFO_SCHEMA_INVALID_RULE,
          'error',
          'ANCHOR_QUOTE_SERVER',
          `ANCHOR_QUOTE_SERVER /info declares country_codes for "${entry.asset}" that are not an array`,
          'country_codes must be an array of ISO 3166 codes, e.g. ["BR"] or ["US-NY"].',
        );
      } else {
        let invalid: string | undefined;
        for (const [position, code] of entry.country_codes.entries()) {
          if (!isString(code) || !COUNTRY_CODE.test(code)) {
            invalid = isString(code) ? `"${code}"` : `entry ${position}`;
            break;
          }
          codes.push(code.toUpperCase());
        }
        if (invalid !== undefined) {
          report(
            run,
            INFO_SCHEMA_INVALID_RULE,
            'error',
            'ANCHOR_QUOTE_SERVER',
            `ANCHOR_QUOTE_SERVER /info lists ${invalid} in the country_codes of "${entry.asset}", which is not an ISO 3166 country code`,
            'Use ISO 3166-1 alpha-2 codes, optionally with an ISO 3166-2 subdivision (e.g. "BR", "US-NY").',
          );
          codes.length = 0;
        }
      }
    }

    countryCodes.set(entry.asset, codes);
  }

  return countryCodes;
}

/**
 * `GET /prices?sell_asset=...` for every asset the file declares, collecting
 * the rates it answers with and asserting each declared counterpart is quoted.
 *
 * Transport and shape failures are silence: `checkSep38` probes the same URLs
 * under plain `--check-network` and already reports them.
 */
async function collectRates(run: Run, declared: string[]): Promise<Map<string, number>> {
  const rates = new Map<string, number>();

  for (const sell of declared) {
    const url = `${run.base}/prices?sell_asset=${encodeURIComponent(sell)}&sell_amount=1`;

    let response: Response;
    try {
      response = await run.fetchImpl(url);
    } catch {
      continue;
    }
    if (response.status !== 200) continue;

    const body = await response.json().catch(() => null);
    if (!isRecord(body) || !Array.isArray(body.buy_assets)) continue;

    const quotes = new Map<string, number>();
    let usable = true;
    for (const entry of body.buy_assets) {
      if (!isRecord(entry) || !isString(entry.asset) || !isString(entry.price)) {
        usable = false;
        break;
      }
      const price = Number(entry.price);
      if (!Number.isFinite(price)) {
        usable = false;
        break;
      }
      quotes.set(entry.asset, price);
    }
    if (!usable) continue;

    const missing = declared.filter((asset) => asset !== sell && !quotes.has(asset));
    if (missing.length > 0) {
      report(
        run,
        PRICES_MISSING_DECLARED_ASSET_RULE,
        'error',
        'CURRENCIES',
        `GET /prices for ${sell} does not quote ${missing.join(', ')}, declared in [[CURRENCIES]] but absent from buy_assets`,
        'Quote every declared pair from /prices, or drop the asset the anchor does not trade from [[CURRENCIES]].',
      );
    }

    for (const [buy, price] of quotes) {
      if (price <= 0) {
        report(
          run,
          ABNORMAL_EXCHANGE_RATE_SPREAD_RULE,
          'warning',
          'ANCHOR_QUOTE_SERVER',
          `GET /prices exchanges ${sell} for ${buy} at ${price}, which is not a positive number`,
          'Quote rates greater than zero: a wallet cannot size an order from a zero or negative price.',
        );
        continue;
      }
      rates.set(pairKey(sell, buy), price);
    }
  }

  return rates;
}

/**
 * The reverse of each declared pair must land inside a bid-ask spread of the
 * forward rate's inverse: quoting `A` for `B` at one rate and `B` for `A` at
 * another that implies a different number means one of the two directions is
 * priced wrong, or the anchor is widening the spread past what a remittance
 * flow can absorb.
 */
function checkSpread(run: Run, declared: string[], rates: Map<string, number>): void {
  for (const [index, sell] of declared.entries()) {
    for (const buy of declared.slice(index + 1)) {
      const forward = rates.get(pairKey(sell, buy));
      const reverse = rates.get(pairKey(buy, sell));
      if (forward === undefined || reverse === undefined) continue;

      const spread = Math.abs(forward * reverse - 1) * 100;
      if (spread <= MAX_QUOTE_SPREAD_PERCENT) continue;

      report(
        run,
        ABNORMAL_EXCHANGE_RATE_SPREAD_RULE,
        'warning',
        'ANCHOR_QUOTE_SERVER',
        `Reverse rates for ${sell} and ${buy} disagree by ${spread.toFixed(1)}% (${forward} one way, ${reverse} the other), past the ${MAX_QUOTE_SPREAD_PERCENT}% bid-ask spread wallets accept`,
        `Quote both directions within ${MAX_QUOTE_SPREAD_PERCENT}% of each other's inverse, or state the margin as a fee.`,
      );
    }
  }
}

function expirationProblem(value: unknown): string | undefined {
  if (!isString(value) || value.length === 0) return 'without an `expires_at`';
  const expiresAt = Date.parse(value);
  if (Number.isNaN(expiresAt)) {
    return `with an \`expires_at\` of "${value}", which is not a UTC ISO 8601 timestamp`;
  }
  if (expiresAt <= Date.now()) {
    return `with an \`expires_at\` of "${value}", which is already in the past`;
  }
  return undefined;
}

function firstCountry(codes: Map<string, string[]> | null, asset: string): string | undefined {
  return codes?.get(asset)?.[0];
}

/**
 * `POST /quote`, once for each quote kind, asserting the answer expires in the
 * future.
 *
 * An unauthenticated request earns 401 or 403 on any server that enforces the
 * mandatory SEP-10 token, and a 400 when the pair needs delivery details a
 * lint run cannot supply; neither says anything about the quote math, so both
 * are silence. A 2xx, on the other hand, is a quote the server stands behind,
 * and a wallet that cannot tell how long it lasts will either tie up dead
 * funds or refuse a perfectly good rate.
 */
async function checkQuotes(
  run: Run,
  pair: readonly [string, string] | null,
  info: Map<string, string[]> | null,
): Promise<void> {
  if (pair === null) return;
  const [sell, buy] = pair;
  const country = firstCountry(info, sell) ?? firstCountry(info, buy);

  for (const type of QUOTE_TYPES) {
    const payload: Record<string, unknown> = {
      sell_asset: sell,
      buy_asset: buy,
      sell_amount: '1',
      type,
      ...(country === undefined ? {} : { country_code: country }),
    };

    let response: Response;
    try {
      response = await run.fetchImpl(`${run.base}/quote`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        redirect: 'follow',
      });
    } catch {
      continue;
    }
    if (!response.ok) continue;

    const body = await response.json().catch(() => null);
    const problem = expirationProblem(isRecord(body) ? body.expires_at : undefined);
    if (problem === undefined) continue;

    report(
      run,
      INVALID_QUOTE_EXPIRATION_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER',
      `POST /quote returned ${type === 'indicative' ? 'an' : 'a'} ${type} quote ${problem}`,
      'Return a UTC ISO 8601 `expires_at` in the future so the wallet knows how long the quote holds.',
    );
  }
}

/**
 * The pair the quote probes use: the first two assets the file declares, or
 * the first two the anchor's own `/info` offers when the file names only one.
 */
function quotePair(
  declared: string[],
  info: Map<string, string[]> | null,
): readonly [string, string] | null {
  if (declared.length >= 2) {
    const [first, second] = declared;
    if (first !== undefined && second !== undefined) return [first, second];
  }
  if (info !== null && info.size >= 2) {
    const [first, second] = [...info.keys()];
    if (first !== undefined && second !== undefined) return [first, second];
  }
  return null;
}

/**
 * Verifies the SEP-38 quote server's answers against the file it is advertised
 * in: `/info` assets and country mappings, `/prices` coverage of every
 * declared pair plus the mathematical validity of its rates, and `POST /quote`
 * expirations for firm and indicative quotes.
 *
 * Silent when the file declares no usable `ANCHOR_QUOTE_SERVER`, since
 * `general/https-endpoints` reports that offline.
 */
export async function verifySep38(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep38QuoteOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.ANCHOR_QUOTE_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const run: Run = {
    base: server.replace(/\/+$/, ''),
    fetchImpl,
    options,
    diagnostics: [],
  };

  const info = await checkInfo(run);
  const declared = declaredAssets(doc);
  const rates = declared.length >= 2 ? await collectRates(run, declared) : new Map();
  checkSpread(run, declared, rates);
  await checkQuotes(run, quotePair(declared, info), info);

  return run.diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep38QuoteRules: Rule[] = [
  {
    id: INFO_SCHEMA_INVALID_RULE,
    category: 'network',
    severity: 'error',
    description:
      'ANCHOR_QUOTE_SERVER GET /info must list quotable assets with well-formed ISO 3166 country codes',
    run() {},
  },
  {
    id: PRICES_MISSING_DECLARED_ASSET_RULE,
    category: 'network',
    severity: 'error',
    description: 'GET /prices must quote every asset pair the stellar.toml declares',
    run() {},
  },
  {
    id: ABNORMAL_EXCHANGE_RATE_SPREAD_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'GET /prices rates must be positive, and reverse pairs must agree within a 15% bid-ask spread',
    run() {},
  },
  {
    id: INVALID_QUOTE_EXPIRATION_RULE,
    category: 'network',
    severity: 'error',
    description: 'POST /quote must return an expires_at timestamp still in the future',
    run() {},
  },
];

/** Rule ids emitted by {@link verifySep38}. */
export const sep38QuoteRuleIds: readonly string[] = sep38QuoteRules.map((rule) => rule.id);
