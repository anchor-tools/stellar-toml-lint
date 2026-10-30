import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isInteger, isString, isUrl } from '../predicates.js';

/**
 * Opt-in validation of the SEP-38 `ANCHOR_QUOTE_SERVER` endpoints.
 *
 * When a file declares `ANCHOR_QUOTE_SERVER`, wallets GET `/prices` and
 * `/quote` to negotiate exchange rates before building a transaction. A
 * server that answers 500, or that returns HTML/`{}` where a price object
 * belongs, leaves the wallet unable to calculate transaction amounts — the
 * failure surfaces days later as an abandoned transfer, not as a lint error
 * in the file that advertised the endpoint. The check is network-bound: it
 * only runs when the caller asks for `--check-network`, and the rule objects
 * registered alongside it exist so `--list-rules` and `--off` know about the
 * diagnostics the async audit emits.
 */

const PRICES_ERROR_RULE = 'sep38/prices-endpoint-error';
const PRICES_MALFORMED_RULE = 'sep38/malformed-price-response';
const QUOTE_ERROR_RULE = 'sep38/quote-endpoint-error';
const QUOTE_MALFORMED_RULE = 'sep38/malformed-quote-response';

const SEP38_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md';

interface AuditOptions {
  rules?: RuleOverrides;
}

function sep38Url(anchor: string): string {
  return `${SEP38_SPEC_URL}#${anchor}`;
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
      category: 'network',
      message: detail,
      path,
      helpUri,
      suggestion,
    },
  ];
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/** Reads `[[CURRENCIES]]` as a list of tables, ignoring malformed entries. */
function currenciesOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  return currencies.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

/** True for an entry describing XLM — `code="native"`, or `XLM` with no issuer. */
function isNativeEntry(entry: Record<string, unknown>): boolean {
  if (!isString(entry.code)) return false;
  const code = entry.code.toLowerCase();
  if (code === 'native') return true;
  return code === 'xlm' && entry.issuer === undefined && entry.contract === undefined;
}

/**
 * SEP-38 Asset Identification Format ids for the classic assets the file
 * declares, deduplicated and in declaration order.
 *
 * `toml` pointer entries are skipped: the real definition lives in another
 * file this check does not fetch. Contract-only entries are skipped too —
 * SEP-38 pairs are overwhelmingly classic assets and `iso4217` fiat, and the
 * SEP-11 identifier for a contract token is not settled enough to guess at.
 */
function sellAssetsOf(doc: Record<string, unknown>): string[] {
  const assets = new Set<string>();
  for (const entry of currenciesOf(doc)) {
    if (entry.toml !== undefined) continue;
    if (!isString(entry.code)) continue;
    if (isNativeEntry(entry)) {
      assets.add('stellar:XLM');
      continue;
    }
    if (isString(entry.issuer)) {
      assets.add(`stellar:${entry.code}:${entry.issuer}`);
    }
  }
  return [...assets];
}

/** A `buy_assets`/`sell_assets` entry: `{ asset, price, decimals? }`. */
function priceObjectProblem(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'expected an object';
  }
  const entry = value as Record<string, unknown>;
  if (!isString(entry.asset) || entry.asset.length === 0) {
    return 'missing a string `asset`';
  }
  if (!isString(entry.price) || !Number.isFinite(Number(entry.price))) {
    return 'missing a numeric-string `price`';
  }
  if (entry.decimals !== undefined && !isInteger(entry.decimals)) {
    return 'declaring a non-integer `decimals`';
  }
  return undefined;
}

/**
 * GETs `ANCHOR_QUOTE_SERVER/prices?sell_asset=...` for each classic asset the
 * file declares and asserts the answer is a 200 whose body carries a
 * `buy_assets` array of valid price objects.
 *
 * Silent when the file has no `ANCHOR_QUOTE_SERVER`, when the value is not a
 * parseable URL — `general/https-endpoints` already reports that offline — or
 * when no classic asset is declared to sell, since there would be no
 * `sell_asset` to ask about.
 */
async function checkPrices(
  base: string,
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch,
  options: AuditOptions,
): Promise<Diagnostic[]> {
  const sellAssets = sellAssetsOf(doc);
  if (sellAssets.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  for (const sellAsset of sellAssets) {
    const url = `${base}/prices?sell_asset=${encodeURIComponent(sellAsset)}`;

    let response: Response;
    try {
      response = await fetchImpl(url);
    } catch (error) {
      diagnostics.push(
        ...finding(
          PRICES_ERROR_RULE,
          'error',
          `Could not reach ANCHOR_QUOTE_SERVER /prices at ${url}: ${errorMessage(error)}`,
          'ANCHOR_QUOTE_SERVER',
          sep38Url('get-prices'),
          'Confirm ANCHOR_QUOTE_SERVER points at a live SEP-38 server and that it is reachable.',
          options.rules,
        ),
      );
      continue;
    }

    if (response.status !== 200) {
      diagnostics.push(
        ...finding(
          PRICES_ERROR_RULE,
          'error',
          `ANCHOR_QUOTE_SERVER /prices for ${sellAsset} returned HTTP ${response.status}`,
          'ANCHOR_QUOTE_SERVER',
          sep38Url('get-prices'),
          'SEP-38 requires GET /prices to answer 200 with a price object for supported assets.',
          options.rules,
        ),
      );
      continue;
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      diagnostics.push(
        ...finding(
          PRICES_MALFORMED_RULE,
          'error',
          `ANCHOR_QUOTE_SERVER /prices for ${sellAsset} did not return valid JSON`,
          'ANCHOR_QUOTE_SERVER',
          sep38Url('get-prices'),
          'Return application/json: wallets cannot parse a price list served as HTML or plain text.',
          options.rules,
        ),
      );
      continue;
    }

    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      diagnostics.push(
        ...finding(
          PRICES_MALFORMED_RULE,
          'error',
          `ANCHOR_QUOTE_SERVER /prices for ${sellAsset} did not return a price object`,
          'ANCHOR_QUOTE_SERVER',
          sep38Url('get-prices'),
          'Respond with a JSON object carrying the `buy_assets` array SEP-38 defines.',
          options.rules,
        ),
      );
      continue;
    }

    const buyAssets = (body as Record<string, unknown>).buy_assets;
    if (!Array.isArray(buyAssets)) {
      diagnostics.push(
        ...finding(
          PRICES_MALFORMED_RULE,
          'error',
          `ANCHOR_QUOTE_SERVER /prices for ${sellAsset} is missing the buy_assets array`,
          'ANCHOR_QUOTE_SERVER',
          sep38Url('get-prices'),
          'When sell_asset is provided the response must include `buy_assets` — wallets read it to price the trade.',
          options.rules,
        ),
      );
      continue;
    }

    for (const [index, entry] of buyAssets.entries()) {
      const problem = priceObjectProblem(entry);
      if (problem === undefined) continue;
      diagnostics.push(
        ...finding(
          PRICES_MALFORMED_RULE,
          'error',
          `ANCHOR_QUOTE_SERVER /prices buy_assets[${index}] for ${sellAsset} is ${problem}`,
          'ANCHOR_QUOTE_SERVER',
          sep38Url('get-prices'),
          'Each buy_assets entry needs a string `asset`, a numeric-string `price`, and an optional integer `decimals`.',
          options.rules,
        ),
      );
      break; // one clear finding per request is enough to act on
    }
  }

  return diagnostics;
}

/**
 * GETs `ANCHOR_QUOTE_SERVER/quote` as an unauthenticated liveness probe.
 *
 * Creating a real quote needs SEP-10 auth and a POST body, and fetching one
 * by id needs an id the linter does not have — so the probe only asserts the
 * route does not crash: a 5xx or an unreachable server means every wallet
 * quote flow fails, while the 400/401/404 a bare GET legitimately earns is
 * silence. A 200 must still be a JSON object, since a captive portal answering
 * the route is the same class of breakage as malformed `/prices` output.
 */
async function checkQuote(
  base: string,
  fetchImpl: typeof fetch,
  options: AuditOptions,
): Promise<Diagnostic[]> {
  const url = `${base}/quote`;

  let response: Response;
  try {
    response = await fetchImpl(url);
  } catch (error) {
    return finding(
      QUOTE_ERROR_RULE,
      'error',
      `Could not reach ANCHOR_QUOTE_SERVER /quote at ${url}: ${errorMessage(error)}`,
      'ANCHOR_QUOTE_SERVER',
      sep38Url('post-quote'),
      'Confirm ANCHOR_QUOTE_SERVER points at a live SEP-38 server and that it is reachable.',
      options.rules,
    );
  }

  if (response.status >= 500) {
    return finding(
      QUOTE_ERROR_RULE,
      'error',
      `ANCHOR_QUOTE_SERVER /quote returned HTTP ${response.status}`,
      'ANCHOR_QUOTE_SERVER',
      sep38Url('post-quote'),
      'A 5xx from /quote means firm quotes fail for every client — fix the server before shipping the endpoint.',
      options.rules,
    );
  }

  if (!response.ok) return []; // 400/401/404 are expected without auth or a quote id

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return finding(
      QUOTE_MALFORMED_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER /quote did not return valid JSON',
      'ANCHOR_QUOTE_SERVER',
      sep38Url('post-quote'),
      'Return application/json: wallets cannot read a quote served as HTML or plain text.',
      options.rules,
    );
  }

  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return finding(
      QUOTE_MALFORMED_RULE,
      'error',
      'ANCHOR_QUOTE_SERVER /quote did not return a quote object',
      'ANCHOR_QUOTE_SERVER',
      sep38Url('post-quote'),
      'Respond with the JSON quote object SEP-38 defines, carrying id, price, and amounts.',
      options.rules,
    );
  }

  return [];
}

/** Runs both SEP-38 endpoint audits against the advertised quote server. */
export async function checkSep38(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.ANCHOR_QUOTE_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const base = server.replace(/\/+$/, '');
  return [
    ...(await checkPrices(base, doc, fetchImpl, options)),
    ...(await checkQuote(base, fetchImpl, options)),
  ];
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep38Rules: Rule[] = [
  {
    id: PRICES_ERROR_RULE,
    category: 'network',
    severity: 'error',
    description: 'ANCHOR_QUOTE_SERVER GET /prices must answer 200 with a SEP-38 price object',
    run() {},
  },
  {
    id: PRICES_MALFORMED_RULE,
    category: 'network',
    severity: 'error',
    description: 'ANCHOR_QUOTE_SERVER GET /prices must return JSON carrying a buy_assets array',
    run() {},
  },
  {
    id: QUOTE_ERROR_RULE,
    category: 'network',
    severity: 'error',
    description: 'ANCHOR_QUOTE_SERVER /quote must not answer with a 5xx server error',
    run() {},
  },
  {
    id: QUOTE_MALFORMED_RULE,
    category: 'network',
    severity: 'error',
    description: 'ANCHOR_QUOTE_SERVER /quote must return a JSON quote object when it answers 200',
    run() {},
  },
];

/** Rule ids emitted by {@link checkSep38}. */
export const sep38RuleIds: readonly string[] = sep38Rules.map((rule) => rule.id);
