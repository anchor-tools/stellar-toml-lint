/**
 * Opt-in validation of the SEP-6 `TRANSFER_SERVER` `/info` endpoint.
 *
 * SEP-6 predates SEP-24 and is still how many anchors expose programmatic
 * deposit and withdrawal. Wallets GET `<TRANSFER_SERVER>/info` to learn which
 * assets the anchor supports; an endpoint that is unreachable, returns HTML,
 * or omits an asset the file advertises leaves the wallet advertising a
 * deposit it cannot complete. The check is network-bound, so it only runs when
 * the caller asks for `--domain` or `--check-network`, and the rule objects
 * registered alongside it exist so `--list-rules` and `--off` know about the
 * diagnostics the async audit emits.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

const INFO_ERROR_RULE = 'network/sep6-info-error';
const INFO_MALFORMED_RULE = 'network/sep6-info-malformed';
const MISSING_ASSET_RULE = 'network/sep6-missing-asset';

const SEP6_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0006.md';

interface AuditOptions {
  rules?: RuleOverrides;
}

/** A `[[CURRENCIES]]` entry, as the file declares it. */
export interface CurrencyEntry {
  code?: unknown;
  issuer?: unknown;
  contract?: unknown;
  toml?: unknown;
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

/**
 * The [SEP-6][sep6] `/info` response keys an asset may appear under. SEP-6 lets
 * an anchor key the `deposit`/`withdraw` maps by bare asset code (`USD`) or by
 * the `CODE:issuer` form (`USD:G...`), so a declared currency is satisfied by
 * either spelling.
 */
function assetKeys(entry: CurrencyEntry): string[] {
  if (!isString(entry.code)) return [];
  const code = entry.code;
  if (isString(entry.issuer)) return [code, `${code}:${entry.issuer}`];
  return [code];
}

/** True for an entry describing XLM — `code="native"`, or `XLM` with no issuer. */
function isNativeEntry(entry: CurrencyEntry): boolean {
  if (!isString(entry.code)) return false;
  const code = entry.code.toLowerCase();
  if (code === 'native') return true;
  return code === 'xlm' && entry.issuer === undefined && entry.contract === undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  path: string,
  helpUri: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [{ rule, severity, category: 'network', message, path, helpUri, suggestion }];
}

/**
 * GETs `<TRANSFER_SERVER>/info` and validates the asset maps it returns.
 *
 * The requirements SEP-6 imposes are checked in order, and the first failure
 * short-circuits: there is no point cross-referencing assets against a document
 * that never arrived. Network failures degrade to a warning rather than
 * throwing, so a flaky endpoint never turns the lint run itself into a failure.
 */
export async function verifySep6Info(
  transferServerUrl: string,
  currencies: CurrencyEntry[],
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const base = transferServerUrl.replace(/\/+$/, '');
  const url = `${base}/info`;

  let response: Response;
  try {
    response = await fetchImpl(url, { redirect: 'follow' });
  } catch (error) {
    return finding(
      INFO_ERROR_RULE,
      'warning',
      `Could not reach TRANSFER_SERVER /info at ${url}: ${errorMessage(error)}`,
      'TRANSFER_SERVER',
      SEP6_SPEC,
      'Confirm TRANSFER_SERVER points at a live SEP-6 server and that /info is reachable.',
      options.rules,
    );
  }

  if (response.status !== 200) {
    return finding(
      INFO_ERROR_RULE,
      'warning',
      `TRANSFER_SERVER /info returned HTTP ${response.status}`,
      'TRANSFER_SERVER',
      SEP6_SPEC,
      'SEP-6 requires GET /info to answer 200 with the asset deposit and withdraw maps.',
      options.rules,
    );
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return finding(
      INFO_MALFORMED_RULE,
      'warning',
      `TRANSFER_SERVER /info did not return application/json${
        contentType ? ` (got "${contentType}")` : ''
      }`,
      'TRANSFER_SERVER',
      SEP6_SPEC,
      'Wallets parse /info as JSON; serve it with a `Content-Type: application/json` header.',
      options.rules,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return finding(
      INFO_MALFORMED_RULE,
      'warning',
      'TRANSFER_SERVER /info did not return valid JSON',
      'TRANSFER_SERVER',
      SEP6_SPEC,
      'Return application/json: wallets cannot read the asset maps from HTML or plain text.',
      options.rules,
    );
  }

  if (!isRecord(body)) {
    return finding(
      INFO_MALFORMED_RULE,
      'warning',
      'TRANSFER_SERVER /info did not return a JSON object',
      'TRANSFER_SERVER',
      SEP6_SPEC,
      'Respond with the JSON object SEP-6 defines, carrying the `deposit` and `withdraw` maps.',
      options.rules,
    );
  }

  const deposit = body.deposit;
  const withdraw = body.withdraw;
  if (!isRecord(deposit) && !isRecord(withdraw)) {
    return finding(
      INFO_MALFORMED_RULE,
      'warning',
      'TRANSFER_SERVER /info is missing both the deposit and withdraw maps',
      'TRANSFER_SERVER',
      SEP6_SPEC,
      'SEP-6 requires `deposit` and `withdraw` objects keyed by the assets the anchor supports.',
      options.rules,
    );
  }

  const diagnostics: Diagnostic[] = [];
  for (const currency of currencies) {
    if (isNativeEntry(currency)) continue;
    const keys = assetKeys(currency);
    if (keys.length === 0) continue;

    const listed = (map: unknown): boolean =>
      isRecord(map) && keys.some((key) => Object.prototype.hasOwnProperty.call(map, key));
    if (listed(deposit) || listed(withdraw)) continue;

    diagnostics.push(
      ...finding(
        MISSING_ASSET_RULE,
        'warning',
        `Currency "${keys[0]}" is declared in [[CURRENCIES]] but missing from TRANSFER_SERVER /info`,
        'CURRENCIES',
        SEP6_SPEC,
        `Add "${keys[0]}" to the deposit or withdraw map at /info, or remove it from [[CURRENCIES]].`,
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/** Reads `[[CURRENCIES]]` as a list of tables, ignoring malformed entries. */
function currenciesOf(doc: Record<string, unknown>): CurrencyEntry[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  return currencies.filter(isRecord) as CurrencyEntry[];
}

/**
 * Validates the SEP-6 `/info` of the `TRANSFER_SERVER` the file advertises.
 *
 * Silent when the file declares no usable `TRANSFER_SERVER` — `general/https-endpoints`
 * already reports a malformed one offline — so an offline lint never opens a
 * connection.
 */
export async function checkSep6(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.TRANSFER_SERVER;
  if (!isString(server) || !isUrl(server)) return [];
  return verifySep6Info(server, currenciesOf(doc), fetchImpl, options);
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep6Rules: Rule[] = [
  {
    id: INFO_ERROR_RULE,
    category: 'network',
    severity: 'warning',
    description: 'TRANSFER_SERVER GET /info should answer 200 and be reachable',
    run() {},
  },
  {
    id: INFO_MALFORMED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'TRANSFER_SERVER GET /info should return a JSON object with asset maps',
    run() {},
  },
  {
    id: MISSING_ASSET_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Every non-native [[CURRENCIES]] asset should appear in the /info maps',
    run() {},
  },
];

/** Rule ids emitted by {@link checkSep6}. */
export const sep6RuleIds: readonly string[] = sep6Rules.map((rule) => rule.id);
