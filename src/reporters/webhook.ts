/**
 * Webhook reporters — Slack Block Kit cards and Discord embeds.
 *
 * A lint run is summarised into one payload per channel so a single `POST`
 * covers the whole run, rather than one notification per file.
 *
 * Delivery never throws. The caller gets one {@link WebhookDelivery} per
 * endpoint and decides what to do with it: an alerting tool that dies because
 * the alert endpoint is unreachable is worse than the problem it was reporting.
 *
 * Both payload builders are pure functions of the run, which is what makes them
 * testable without a network — see `test/webhook.test.ts`.
 */

import type { Diagnostic, LintResult, Severity } from '../types.js';

/** One linted file and its result. The shape `cli.ts` already collects. */
export interface LintRunEntry {
  name: string;
  result: LintResult;
}

export type LintRun = LintRunEntry[];

export type WebhookChannel = 'slack' | 'discord';

export interface WebhookTargets {
  slack?: string;
  discord?: string;
}

export interface WebhookDelivery {
  channel: WebhookChannel;
  url: string;
  ok: boolean;
  /** Number of POSTs made, including retries. */
  attempts: number;
  status?: number;
  error?: string;
}

export interface WebhookOptions {
  /** Per-request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Retries *after* the first attempt. Default 2. */
  retries?: number;
  /** Base delay between retries in milliseconds; doubles per attempt. Default 250. */
  backoffMs?: number;
  /** Injected for tests. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Injected for tests so retries need not sleep for real. */
  sleepImpl?: (ms: number) => Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_RETRIES = 2;
const DEFAULT_BACKOFF_MS = 250;
/** Statuses worth another attempt: the endpoint may recover. 4xx will not. */
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

/** Slack's own traffic-light palette. */
const SLACK_COLORS = { error: '#E01E5A', warning: '#ECB22E', info: '#2EB67D' } as const;
/** The same hues as Discord's decimal embed colours. */
const DISCORD_COLORS = { error: 0xe01e5a, warning: 0xecb22e, info: 0x2eb67d } as const;

/** Only `http:` and `https:` endpoints are accepted, and only those with a body. */
export function isSupportedWebhookUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname !== '';
}

/** Traffic-light level for a run: any error → red, warnings → yellow, else green. */
export function runLevel(counts: Record<Severity, number>): Severity {
  if (counts.error > 0) return 'error';
  if (counts.warning > 0) return 'warning';
  return 'info';
}

function totals(run: LintRun): Record<Severity, number> {
  const acc: Record<Severity, number> = { error: 0, warning: 0, info: 0 };
  for (const { result } of run) {
    acc.error += result.counts.error;
    acc.warning += result.counts.warning;
    acc.info += result.counts.info;
  }
  return acc;
}

interface RuleGroup {
  rule: string;
  count: number;
  severity: Severity;
  helpUri?: string;
  message: string;
  line?: number;
}

/**
 * Groups findings by rule and orders them by count, so the card leads with the
 * problem that actually dominates the run. Ties break on rule id to keep the
 * payload stable between runs (and therefore comparable in tests).
 */
function groupByRule(diagnostics: Diagnostic[], limit: number): RuleGroup[] {
  const groups = new Map<string, RuleGroup>();

  for (const diagnostic of diagnostics) {
    const existing = groups.get(diagnostic.rule);
    if (existing) {
      existing.count += 1;
      if (diagnostic.severity === 'error') existing.severity = 'error';
      continue;
    }
    groups.set(diagnostic.rule, {
      rule: diagnostic.rule,
      count: 1,
      severity: diagnostic.severity,
      message: diagnostic.message,
      ...(diagnostic.helpUri !== undefined ? { helpUri: diagnostic.helpUri } : {}),
      ...(diagnostic.position !== undefined ? { line: diagnostic.position.line } : {}),
    });
  }

  return [...groups.values()]
    .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule))
    .slice(0, limit);
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

function describeFiles(run: LintRun): string {
  if (run.length === 1) return run[0]?.name ?? 'stellar.toml';
  return `${run.length} files`;
}

// ── Slack ────────────────────────────────────────────────────────────────────

export interface SlackPayload {
  text: string;
  attachments: {
    color: string;
    blocks: Record<string, unknown>[];
  }[];
}

/**
 * Builds one Slack message using an attachment (for the colour bar) plus Block
 * Kit blocks for the numbers, the worst rules, and links into SEP-1.
 */
export function formatSlackPayload(run: LintRun, limit = 5): SlackPayload {
  const counts = totals(run);
  const level = runLevel(counts);
  const summary = `${describeFiles(run)}: ${plural(counts.error, 'error')}, ${plural(
    counts.warning,
    'warning',
  )}`;

  const blocks: Record<string, unknown>[] = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `stellar.toml compliance — ${level}`, emoji: false },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Errors*\n${counts.error}` },
        { type: 'mrkdwn', text: `*Warnings*\n${counts.warning}` },
        { type: 'mrkdwn', text: `*Info*\n${counts.info}` },
        { type: 'mrkdwn', text: `*Scope*\n${describeFiles(run)}` },
      ],
    },
  ];

  const diagnostics = run.flatMap(({ result }) => result.diagnostics);
  const groups = groupByRule(diagnostics, limit);

  if (groups.length > 0) {
    const lines = groups.map((group) => {
      const location = group.line === undefined ? '' : ` (line ${group.line})`;
      const link = group.helpUri === undefined ? '' : ` — <${group.helpUri}|spec>`;
      return `• *${group.rule}* ×${group.count}${location}${link}`;
    });
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `*Most frequent findings*\n${lines.join('\n')}` },
    });
  } else {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: 'No findings — the file matches SEP-1.' },
    });
  }

  const specLinks = [
    ...new Set(groups.map((group) => group.helpUri).filter((uri): uri is string => !!uri)),
  ].slice(0, 3);

  if (specLinks.length > 0) {
    blocks.push({
      type: 'actions',
      elements: specLinks.map((url, index) => ({
        type: 'button',
        text: { type: 'plain_text', text: index === 0 ? 'Open SEP-1' : `Spec ${index + 1}` },
        url,
      })),
    });
  }

  return {
    text: summary,
    attachments: [{ color: SLACK_COLORS[level], blocks }],
  };
}

// ── Discord ──────────────────────────────────────────────────────────────────

export interface DiscordPayload {
  embeds: {
    title: string;
    description: string;
    color: number;
    fields: { name: string; value: string; inline: boolean }[];
    footer: { text: string };
  }[];
}

/**
 * Builds one Discord Rich Embed. Discord cannot attach a button to a webhook, so
 * the spec links go inline in the field values instead.
 *
 * No `timestamp`: it would make otherwise identical runs produce different
 * payloads, which is exactly what the delivery tests compare.
 */
export function formatDiscordPayload(run: LintRun, limit = 5): DiscordPayload {
  const counts = totals(run);
  const level = runLevel(counts);
  const diagnostics = run.flatMap(({ result }) => result.diagnostics);
  const groups = groupByRule(diagnostics, limit);

  const fields = [
    { name: 'Errors', value: String(counts.error), inline: true },
    { name: 'Warnings', value: String(counts.warning), inline: true },
    { name: 'Info', value: String(counts.info), inline: true },
  ];

  if (groups.length > 0) {
    fields.push({
      name: 'Most frequent findings',
      // Discord field values cap at 1024 characters.
      value: groups
        .map((group) => {
          const location = group.line === undefined ? '' : ` (line ${group.line})`;
          const link = group.helpUri === undefined ? '' : ` ([spec](${group.helpUri}))`;
          return `\`${group.rule}\` ×${group.count}${location}${link}`;
        })
        .join('\n')
        .slice(0, 1024),
      inline: false,
    });
  } else {
    fields.push({
      name: 'Result',
      value: 'No findings — the file matches SEP-1.',
      inline: false,
    });
  }

  return {
    embeds: [
      {
        title: `stellar.toml compliance — ${level}`,
        description: `${describeFiles(run)}: ${plural(counts.error, 'error')}, ${plural(
          counts.warning,
          'warning',
        )}`,
        color: DISCORD_COLORS[level],
        fields,
        footer: { text: 'stellar-toml-lint' },
      },
    ],
  };
}

// ── Delivery ─────────────────────────────────────────────────────────────────

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function defaultSleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * POSTs a payload, retrying only failures that another attempt could plausibly
 * fix: network errors, timeouts, and 408/425/429/5xx. A 4xx is returned as-is —
 * retrying a rejected payload just multiplies the mistake.
 */
async function postWithRetry(
  url: string,
  payload: unknown,
  options: Required<Pick<WebhookOptions, 'timeoutMs' | 'retries' | 'backoffMs'>> &
    Pick<WebhookOptions, 'fetchImpl' | 'sleepImpl'>,
): Promise<{ ok: boolean; attempts: number; status?: number; error?: string }> {
  const send = options.fetchImpl ?? fetch;
  const sleep = options.sleepImpl ?? defaultSleep;
  let lastError: string | undefined;
  let lastStatus: number | undefined;

  for (let attempt = 1; attempt <= options.retries + 1; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    try {
      const response = await send(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (response.ok) return { ok: true, attempts: attempt, status: response.status };

      lastStatus = response.status;
      lastError = `HTTP ${response.status}`;
      if (!RETRYABLE_STATUS.has(response.status)) {
        return { ok: false, attempts: attempt, status: response.status, error: lastError };
      }

      if (response.status === 429) {
        const retryAfterHeader = response.headers?.get?.('retry-after');
        if (retryAfterHeader) {
          const delaySec = parseFloat(retryAfterHeader);
          if (!isNaN(delaySec) && delaySec > 0 && attempt <= options.retries) {
            clearTimeout(timer);
            await sleep(delaySec * 1000);
            continue;
          }
        }
      }
    } catch (error) {
      lastError = message(error);
    } finally {
      clearTimeout(timer);
    }

    if (attempt <= options.retries) {
      await sleep(options.backoffMs * 2 ** (attempt - 1));
    }
  }

  return {
    ok: false,
    attempts: options.retries + 1,
    ...(lastStatus !== undefined ? { status: lastStatus } : {}),
    ...(lastError !== undefined ? { error: lastError } : {}),
  };
}

/**
 * Delivers the run to every configured endpoint. Endpoints are independent: one
 * failing does not stop the other, and the returned list is in a stable order
 * (Slack, then Discord) so callers can report on it deterministically.
 */
export async function deliverWebhooks(
  run: LintRun,
  targets: WebhookTargets,
  options: WebhookOptions = {},
): Promise<WebhookDelivery[]> {
  const settings = {
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    retries: options.retries ?? DEFAULT_RETRIES,
    backoffMs: options.backoffMs ?? DEFAULT_BACKOFF_MS,
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.sleepImpl !== undefined ? { sleepImpl: options.sleepImpl } : {}),
  };

  const deliveries: WebhookDelivery[] = [];
  const plan: { channel: WebhookChannel; url: string | undefined; payload: unknown }[] = [
    { channel: 'slack', url: targets.slack, payload: formatSlackPayload(run) },
    { channel: 'discord', url: targets.discord, payload: formatDiscordPayload(run) },
  ];

  for (const { channel, url, payload } of plan) {
    if (!url) continue;
    if (!isSupportedWebhookUrl(url)) {
      deliveries.push({
        channel,
        url,
        ok: false,
        attempts: 0,
        error: 'unsupported webhook URL (expected http or https)',
      });
      continue;
    }
    const outcome = await postWithRetry(url, payload, settings);
    deliveries.push({ channel, url, ...outcome });
  }

  return deliveries;
}
