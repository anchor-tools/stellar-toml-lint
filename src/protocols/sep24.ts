/**
 * SEP-24 Hosted Deposit and Withdrawal Flow Validator.
 *
 * Runs under opt-in --check-network --verify-sep24.
 *
 * A wallet reading a stellar.toml advertises `TRANSFER_SERVER_SEP0024` (or
 * the older `TRANSFER_SERVER`) as the endpoint it will open deposit and
 * withdrawal sessions against. Every one of those calls has to be usable
 * while the file is still being reviewed, not weeks after it ships: the
 * `/info` response has to list each anchored currency the file declares, the
 * fee objects wallets read to size a transfer have to carry numeric
 * `fixed`/`percent`/`minimum` values, and an interactive session has to come
 * back with an HTTPS URL and an id rather than a scheme a browser will refuse.
 *
 * Endpoint liveness stays with the plain `--check-network` probe where it
 * exists; an outage here is reported as a warning rather than an error, so a
 * transient transfer-server blip does not fail a build over a file defect
 * that was never the file's fault.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { currenciesOf } from '../rules/currencies.js';

export const INFO_ENDPOINT_UNREACHABLE_RULE = 'sep24/info-endpoint-unreachable';
export const CURRENCY_NOT_SUPPORTED_IN_INFO_RULE = 'sep24/currency-not-supported-in-info';
export const INVALID_FEE_SCHEMA_RULE = 'sep24/invalid-fee-schema';
export const INTERACTIVE_URL_INSECURE_RULE = 'sep24/interactive-url-insecure';

const SEP24_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md';

/** A test JWT the interactive probe presents; never a real credential. */
const TEST_INTERACTIVE_JWT = 'sep24.lint.test.jwt';

export interface Sep24Options {
  rules?: RuleOverrides;
}

/** One engine run: the transfer server under test, the transport, and what it found. */
interface Run {
  base: string;
  fetchImpl: typeof fetch;
  options: Sep24Options;
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
    helpUri: SEP24_SPEC,
    suggestion,
  });
}

/** A fee component is usable when it is a finite number, or a string that parses as one. */
function feeValueProblem(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'number') {
    return Number.isFinite(value) ? undefined : 'not a finite number';
  }
  if (typeof value === 'string') {
    if (value.trim() === '') return 'an empty string';
    const parsed = Number(value);
    return Number.isFinite(parsed) ? undefined : `"${value}", which is not numeric`;
  }
  return `of type ${typeof value}, which is not numeric`;
}

/**
 * `GET /info`: the deposit and withdraw maps wallets read before opening a
 * session, plus the fee objects each currency entry carries.
 *
 * Returns the parsed body, or `null` when the response could not be used.
 */
async function checkInfo(run: Run): Promise<Record<string, unknown> | null> {
  const url = `${run.base}/info`;

  let response: Response;
  try {
    response = await run.fetchImpl(url, { redirect: 'follow' });
  } catch (error) {
    // An outage is not a file defect: report it as a warning so a transient
    // transfer-server blip does not fail a run that the file itself would pass.
    report(
      run,
      INFO_ENDPOINT_UNREACHABLE_RULE,
      'warning',
      'TRANSFER_SERVER_SEP0024',
      `Could not reach TRANSFER_SERVER_SEP0024 /info at ${url}: ${errorMessage(error)}`,
      'Confirm TRANSFER_SERVER_SEP0024 points at a live SEP-24 server and is reachable.',
    );
    return null;
  }

  if (!response.ok) {
    report(
      run,
      INFO_ENDPOINT_UNREACHABLE_RULE,
      'warning',
      'TRANSFER_SERVER_SEP0024',
      `TRANSFER_SERVER_SEP0024 /info returned HTTP ${response.status}`,
      'SEP-24 requires GET /info to answer 200 with `deposit` and `withdraw` maps.',
    );
    return null;
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    report(
      run,
      INFO_ENDPOINT_UNREACHABLE_RULE,
      'error',
      'TRANSFER_SERVER_SEP0024',
      'TRANSFER_SERVER_SEP0024 /info did not return valid JSON',
      'Return application/json: a wallet cannot read deposit and withdraw maps from HTML or plain text.',
    );
    return null;
  }

  if (!isRecord(body) || !isRecord(body.deposit) || !isRecord(body.withdraw)) {
    report(
      run,
      INFO_ENDPOINT_UNREACHABLE_RULE,
      'error',
      'TRANSFER_SERVER_SEP0024',
      'TRANSFER_SERVER_SEP0024 /info is missing the `deposit` or `withdraw` map',
      'Respond with a JSON object whose `deposit` and `withdraw` maps list every supported currency.',
    );
    return null;
  }

  return body;
}

/**
 * Cross-references every anchored `[[CURRENCIES]]` entry against the `/info`
 * deposit and withdraw maps, keyed by bare code or `CODE:issuer`.
 */
function checkCurrencies(
  run: Run,
  doc: Record<string, unknown>,
  info: Record<string, unknown>,
): void {
  const deposit = info.deposit as Record<string, unknown>;
  const withdraw = info.withdraw as Record<string, unknown>;

  for (const currency of currenciesOf(doc)) {
    if (currency.is_asset_anchored !== true) continue;
    if (!isString(currency.code) || currency.code.length === 0) continue;
    const code = currency.code;

    const listed =
      Object.hasOwn(deposit, code) ||
      Object.hasOwn(withdraw, code) ||
      (isString(currency.issuer) &&
        (Object.hasOwn(deposit, `${code}:${currency.issuer}`) ||
          Object.hasOwn(withdraw, `${code}:${currency.issuer}`)));

    if (listed) continue;

    report(
      run,
      CURRENCY_NOT_SUPPORTED_IN_INFO_RULE,
      'warning',
      'CURRENCIES',
      `Anchored currency "${code}" is declared in [[CURRENCIES]] but missing from TRANSFER_SERVER_SEP0024 /info deposit and withdraw maps`,
      `Add "${code}" to the /info deposit or withdraw map, or drop it from [[CURRENCIES]].`,
    );
  }
}

/**
 * Every fee object wallets read — a nested `fee` block on a currency entry,
 * or the flat `fee_fixed`/`fee_percent`/`fee_minimum` fields — must carry
 * numeric `fixed`, `percent`, and `minimum` values. A string fee a client
 * cannot parse stalls the transfer at settlement rather than at lint.
 */
function checkFees(run: Run, info: Record<string, unknown>): void {
  const maps: Array<[string, Record<string, unknown>]> = [
    ['deposit', info.deposit as Record<string, unknown>],
    ['withdraw', info.withdraw as Record<string, unknown>],
  ];

  for (const [mapName, map] of maps) {
    for (const [code, entry] of Object.entries(map)) {
      if (!isRecord(entry)) continue;

      const feeFields: Array<[string, unknown]> = [
        ['fee.fixed', isRecord(entry.fee) ? entry.fee.fixed : undefined],
        ['fee.percent', isRecord(entry.fee) ? entry.fee.percent : undefined],
        ['fee.minimum', isRecord(entry.fee) ? entry.fee.minimum : undefined],
        ['fee_fixed', entry.fee_fixed],
        ['fee_percent', entry.fee_percent],
        ['fee_minimum', entry.fee_minimum],
      ];

      for (const [field, value] of feeFields) {
        const problem = feeValueProblem(value);
        if (problem === undefined) continue;
        report(
          run,
          INVALID_FEE_SCHEMA_RULE,
          'error',
          'TRANSFER_SERVER_SEP0024',
          `TRANSFER_SERVER_SEP0024 /info ${mapName} entry for "${code}" has an invalid ${field}: ${problem}`,
          'Give every fee field a finite number, or a string that parses as one (e.g. "1.5").',
        );
      }
    }
  }
}

/**
 * `POST /transactions/deposit/interactive` with a test JWT: the response must
 * carry an `id` and a `url`, and that URL must be HTTPS so a browser wallet
 * will open it.
 *
 * Transport failures and auth rejections are silence — a server that enforces
 * a real SEP-10 token will never answer a lint probe, and that says nothing
 * about the interactive URL itself.
 */
async function checkInteractive(run: Run, doc: Record<string, unknown>): Promise<void> {
  const currencies = currenciesOf(doc).filter(
    (entry) => entry.is_asset_anchored === true && isString(entry.code) && entry.code.length > 0,
  );
  const assetCode = currencies[0]?.code;
  if (!isString(assetCode)) return;

  let response: Response;
  try {
    response = await run.fetchImpl(`${run.base}/transactions/deposit/interactive`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${TEST_INTERACTIVE_JWT}`,
      },
      body: JSON.stringify({
        asset_code: assetCode,
        type: 'bank_account',
        amount: '10',
      }),
      redirect: 'follow',
    });
  } catch {
    return;
  }
  if (!response.ok) return;

  const body = await response.json().catch(() => null);
  if (!isRecord(body)) return;

  const id = body.id;
  const url = body.url;

  if (!isString(id) || id.length === 0) {
    report(
      run,
      INFO_ENDPOINT_UNREACHABLE_RULE,
      'error',
      'TRANSFER_SERVER_SEP0024',
      'TRANSFER_SERVER_SEP0024 interactive deposit response is missing an `id`',
      'Return a transaction id so the wallet can poll /transactions for the session status.',
    );
  }

  if (!isString(url) || url.length === 0) {
    report(
      run,
      INFO_ENDPOINT_UNREACHABLE_RULE,
      'error',
      'TRANSFER_SERVER_SEP0024',
      'TRANSFER_SERVER_SEP0024 interactive deposit response is missing a `url`',
      'Return the interactive session URL so the wallet can open the deposit flow.',
    );
    return;
  }

  if (!url.startsWith('https://')) {
    report(
      run,
      INTERACTIVE_URL_INSECURE_RULE,
      'error',
      'TRANSFER_SERVER_SEP0024',
      `TRANSFER_SERVER_SEP0024 interactive deposit returned a non-HTTPS url "${url}"`,
      'Serve interactive sessions over HTTPS; browsers refuse to open insecure deposit flows.',
    );
  }
}

/**
 * Verifies the SEP-24 hosted deposit/withdrawal flow against the transfer
 * server the file declares: `/info` deposit/withdraw coverage of every
 * anchored currency, numeric fee schemas, and an interactive session that
 * answers with an HTTPS URL and an id.
 *
 * Silent when the file declares no usable `TRANSFER_SERVER_SEP0024` (or the
 * older `TRANSFER_SERVER`), since `general/https-endpoints` reports that
 * offline.
 */
export async function verifySep24(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep24Options = {},
): Promise<Diagnostic[]> {
  const preferred = doc.TRANSFER_SERVER_SEP0024;
  const fallback = doc.TRANSFER_SERVER;
  const server = isString(preferred) && isUrl(preferred) ? preferred : fallback;
  if (!isString(server) || !isUrl(server)) return [];

  const run: Run = {
    base: server.replace(/\/+$/, ''),
    fetchImpl,
    options,
    diagnostics: [],
  };

  const info = await checkInfo(run);
  if (info !== null) {
    checkCurrencies(run, doc, info);
    checkFees(run, info);
  }
  await checkInteractive(run, doc);

  return run.diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep24Rules: Rule[] = [
  {
    id: INFO_ENDPOINT_UNREACHABLE_RULE,
    category: 'network',
    severity: 'error',
    description:
      'TRANSFER_SERVER_SEP0024 GET /info must answer 200 with deposit and withdraw maps',
    run() {},
  },
  {
    id: CURRENCY_NOT_SUPPORTED_IN_INFO_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Every anchored [[CURRENCIES]] entry must appear in SEP-24 /info deposit or withdraw',
    run() {},
  },
  {
    id: INVALID_FEE_SCHEMA_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-24 /info fee objects must carry numeric fixed, percent, and minimum fields',
    run() {},
  },
  {
    id: INTERACTIVE_URL_INSECURE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-24 interactive deposit sessions must return an HTTPS url',
    run() {},
  },
];

/** Rule ids emitted by {@link verifySep24}. */
export const sep24RuleIds: readonly string[] = sep24Rules.map((rule) => rule.id);
