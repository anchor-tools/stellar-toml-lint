import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

export const INSECURE_POSTMESSAGE_WILDCARD_RULE = 'sep24/insecure-postmessage-wildcard';
export const MALFORMED_POSTMESSAGE_PAYLOAD_RULE = 'sep24/malformed-postmessage-payload';

const SEP24_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md';
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_CAPTURED_MESSAGES = 200;
const RECORDER_KEY = '__stellarTomlLintPostMessages';
const SEP24_MESSAGE_TYPES = new Set([
  'stellar:transaction_completed',
  'stellar:fee_acknowledged',
  'stellar:transaction_updated',
]);

const RECORDER_SCRIPT = `
(() => {
  const key = '${RECORDER_KEY}';
  const captured = [];
  Object.defineProperty(window, key, { value: captured, configurable: true });

  const record = (targetOrigin, payload) => {
    try {
      captured.push({ direction: 'sent', targetOrigin: String(targetOrigin), payload });
    } catch (_) {}
  };

  const wrap = (owner) => {
    if (!owner || typeof owner.postMessage !== 'function') return;
    try {
      const original = owner.postMessage;
      owner.postMessage = function (message, targetOrigin, transfer) {
        record(targetOrigin, message);
        return original.call(owner, message, targetOrigin, transfer);
      };
    } catch (_) {}
  };

  wrap(window);

  try {
    const proto = window.Window && window.Window.prototype;
    if (proto && typeof proto.postMessage === 'function') {
      const original = proto.postMessage;
      proto.postMessage = function (message, targetOrigin, transfer) {
        record(targetOrigin, message);
        return original.call(this, message, targetOrigin, transfer);
      };
    }
  } catch (_) {}

  try {
    if (window.opener && window.opener !== window) wrap(window.opener);
  } catch (_) {}
  try {
    if (window.parent && window.parent !== window) wrap(window.parent);
  } catch (_) {}

  window.addEventListener('message', function (event) {
    try {
      captured.push({ direction: 'received', targetOrigin: event.origin, payload: event.data });
    } catch (_) {}
  });
})();
`;

export type PostMessageDirection = 'sent' | 'received';

export interface CapturedPostMessage {
  direction?: PostMessageDirection;
  targetOrigin?: string;
  payload: unknown;
}

export interface PostMessageCaptureOptions {
  url: string;
  timeoutMs: number;
}

export interface Sep24PostMessageLauncher {
  capture(options: PostMessageCaptureOptions): Promise<readonly CapturedPostMessage[]>;
}

export interface Sep24PostMessageOptions {
  rules?: RuleOverrides;
  url?: string;
  timeoutMs?: number;
  launcher?: Sep24PostMessageLauncher;
  authToken?: string;
}

interface PlaywrightPage {
  addInitScript(script: string): Promise<unknown>;
  goto(url: string, options: { waitUntil: string; timeout: number }): Promise<unknown>;
  evaluate(expression: string): Promise<unknown>;
}

interface PlaywrightContext {
  newPage(): Promise<PlaywrightPage>;
  close(): Promise<void>;
}

interface PlaywrightBrowser {
  newContext(): Promise<PlaywrightContext>;
  close(): Promise<void>;
}

interface PlaywrightModule {
  chromium: {
    launch(options: { headless: boolean }): Promise<PlaywrightBrowser>;
  };
}

interface PuppeteerPage {
  evaluateOnNewDocument(script: string): Promise<unknown>;
  goto(url: string, options: { waitUntil: string; timeout: number }): Promise<unknown>;
  evaluate(expression: string): Promise<unknown>;
}

interface PuppeteerBrowser {
  newPage(): Promise<PuppeteerPage>;
  close(): Promise<void>;
}

interface PuppeteerModule {
  launch(options: { headless: boolean }): Promise<PuppeteerBrowser>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
  message: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];

  return [
    {
      rule,
      severity,
      category: 'sep24',
      message,
      path: 'TRANSFER_SERVER_SEP0024',
      helpUri: SEP24_SPEC,
      suggestion,
    },
  ];
}

function normalizeCaptured(value: unknown): CapturedPostMessage[] {
  if (!Array.isArray(value)) return [];

  const events: CapturedPostMessage[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    events.push({
      direction: entry.direction === 'received' ? 'received' : 'sent',
      ...(isString(entry.targetOrigin) ? { targetOrigin: entry.targetOrigin } : {}),
      payload: entry.payload,
    });
    if (events.length >= MAX_CAPTURED_MESSAGES) break;
  }
  return events;
}

function payloadProblem(payload: unknown): string | undefined {
  let value = payload;

  if (isString(payload)) {
    try {
      value = JSON.parse(payload) as unknown;
    } catch {
      return 'is a string that is not valid JSON';
    }
  }

  if (!isRecord(value)) return 'is not a JSON object';

  const type = value.type;
  if (!isString(type) || type.length === 0) return 'is missing a string `type`';
  if (!type.startsWith('stellar:')) return `uses non-SEP-24 type "${type}"`;
  if (!SEP24_MESSAGE_TYPES.has(type)) return `uses unsupported SEP-24 type "${type}"`;

  if (value.transaction !== undefined && !isRecord(value.transaction)) {
    return 'has a non-object `transaction`';
  }
  if (value.transaction_id !== undefined && !isString(value.transaction_id)) {
    return 'has a non-string `transaction_id`';
  }
  if (value.status !== undefined && !isString(value.status)) {
    return 'has a non-string `status`';
  }
  if (isRecord(value.transaction)) {
    if (value.transaction.id !== undefined && !isString(value.transaction.id)) {
      return 'has a non-string `transaction.id`';
    }
    if (value.transaction.status !== undefined && !isString(value.transaction.status)) {
      return 'has a non-string `transaction.status`';
    }
  }

  return undefined;
}

function describePayload(payload: unknown): string {
  let text: string;
  try {
    text = isString(payload) ? payload : JSON.stringify(payload);
  } catch {
    text = String(payload);
  }
  if (text === undefined) return 'undefined';
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}

export function analyzeSep24PostMessages(
  events: readonly CapturedPostMessage[],
  options: Pick<Sep24PostMessageOptions, 'rules'> = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  for (const event of events) {
    if (event.direction === 'received') continue;

    if (event.targetOrigin === '*') {
      diagnostics.push(
        ...finding(
          INSECURE_POSTMESSAGE_WILDCARD_RULE,
          'warning',
          'SEP-24 postMessage dispatches with targetOrigin "*", allowing any embedding page to read the transaction payload',
          'Send the callback to the wallet origin explicitly instead of using "*".',
          options.rules,
        ),
      );
    }

    const problem = payloadProblem(event.payload);
    if (problem !== undefined) {
      diagnostics.push(
        ...finding(
          MALFORMED_POSTMESSAGE_PAYLOAD_RULE,
          'error',
          `SEP-24 postMessage payload ${problem}: ${describePayload(event.payload)}`,
          'Emit a JSON object whose `type` is a supported SEP-24 event, such as "stellar:transaction_completed".',
          options.rules,
        ),
      );
    }
  }

  return diagnostics;
}

async function fetchJson(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
): Promise<unknown | undefined> {
  try {
    const response = await fetchImpl(url, init);
    if (!response.ok) return undefined;
    return (await response.json()) as unknown;
  } catch {
    return undefined;
  }
}

function firstAssetCode(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  for (const [code, entry] of Object.entries(value)) {
    if (isRecord(entry) && entry.enabled === false) continue;
    if (code.length > 0) return code;
  }
  return undefined;
}

async function discoverInteractiveUrl(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch,
  options: Sep24PostMessageOptions,
): Promise<string | undefined> {
  if (isString(options.url) && isUrl(options.url)) return options.url;

  const server = isString(doc.TRANSFER_SERVER_SEP0024)
    ? doc.TRANSFER_SERVER_SEP0024
    : doc.TRANSFER_SERVER;
  if (!isString(server) || !isUrl(server)) return undefined;

  const base = server.replace(/\/+$/, '');
  const info = await fetchJson(`${base}/info`, {}, fetchImpl);
  if (!isRecord(info)) return undefined;

  const assetCode = firstAssetCode(info.deposit) ?? firstAssetCode(info.withdraw);
  if (assetCode === undefined) return undefined;

  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (isString(options.authToken)) headers.authorization = `Bearer ${options.authToken}`;

  const session = await fetchJson(
    `${base}/transactions/deposit/interactive`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({ asset_code: assetCode, amount: '10' }),
    },
    fetchImpl,
  );
  if (!isRecord(session) || !isString(session.url) || !isUrl(session.url)) return undefined;

  return session.url;
}

async function optionalImport(name: string): Promise<unknown> {
  try {
    return await import(name);
  } catch {
    return undefined;
  }
}

function isPlaywrightModule(value: unknown): value is PlaywrightModule {
  if (!isRecord(value) || !isRecord(value.chromium)) return false;
  return typeof value.chromium.launch === 'function';
}

function isPuppeteerModule(value: unknown): value is PuppeteerModule {
  if (!isRecord(value)) return false;
  return typeof value.launch === 'function';
}

async function captureWithPlaywright(
  browserModule: PlaywrightModule,
  options: PostMessageCaptureOptions,
): Promise<CapturedPostMessage[]> {
  const browser = await browserModule.chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      await page.addInitScript(RECORDER_SCRIPT);
      await page.goto(options.url, {
        waitUntil: 'domcontentloaded',
        timeout: options.timeoutMs,
      });
      await sleep(options.timeoutMs);
      return normalizeCaptured(await page.evaluate(`window.${RECORDER_KEY} ?? []`));
    } finally {
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

async function captureWithPuppeteer(
  browserModule: PuppeteerModule,
  options: PostMessageCaptureOptions,
): Promise<CapturedPostMessage[]> {
  const browser = await browserModule.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(RECORDER_SCRIPT);
    await page.goto(options.url, {
      waitUntil: 'domcontentloaded',
      timeout: options.timeoutMs,
    });
    await sleep(options.timeoutMs);
    return normalizeCaptured(await page.evaluate(`window.${RECORDER_KEY} ?? []`));
  } finally {
    await browser.close();
  }
}

async function createDefaultLauncher(): Promise<Sep24PostMessageLauncher> {
  const playwright = await optionalImport('playwright');
  if (isPlaywrightModule(playwright)) {
    return { capture: (options) => captureWithPlaywright(playwright, options) };
  }

  const puppeteer = await optionalImport('puppeteer');
  if (isPuppeteerModule(puppeteer)) {
    return { capture: (options) => captureWithPuppeteer(puppeteer, options) };
  }

  throw new Error(
    'SEP-24 postMessage verification needs Playwright or Puppeteer. Install playwright and run `npx playwright install chromium`, or install puppeteer.',
  );
}

export async function checkSep24PostMessage(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep24PostMessageOptions = {},
): Promise<Diagnostic[]> {
  const url = await discoverInteractiveUrl(doc, fetchImpl, options);
  if (url === undefined) return [];

  const launcher = options.launcher ?? (await createDefaultLauncher());
  const events = await launcher.capture({
    url,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });

  return analyzeSep24PostMessages(events, { rules: options.rules });
}

export const verifySep24PostMessage = checkSep24PostMessage;

export const sep24PostMessageRules: Rule[] = [
  {
    id: INSECURE_POSTMESSAGE_WILDCARD_RULE,
    category: 'sep24',
    severity: 'warning',
    description: 'SEP-24 postMessage callbacks must target an explicit wallet origin, not "*"',
    run() {},
  },
  {
    id: MALFORMED_POSTMESSAGE_PAYLOAD_RULE,
    category: 'sep24',
    severity: 'error',
    description: 'SEP-24 postMessage callbacks must carry a valid stellar:* event payload',
    run() {},
  },
];

export const sep24PostMessageRuleIds: readonly string[] = sep24PostMessageRules.map(
  (rule) => rule.id,
);
