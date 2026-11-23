/**
 * Incident response webhook dispatcher.
 *
 * A monitoring daemon that finds an anchor outage, an expiring TLS certificate,
 * or a reserve deficit needs to say so once, in the shape each operations
 * channel expects: Slack Block Kit cards, Discord embeds, and PagerDuty Events
 * API v2. Severity decides where a finding goes — a critical reserve deficit
 * pages, a warning only posts to chat — and a dedup key plus a throttle window
 * keeps a recurring failure from paging on every poll.
 *
 * When a later health check is green, {@link IncidentWebhookDispatcher.resolve}
 * sends the matching `resolve` event so the incident actually closes.
 *
 * Delivery never throws: one unreachable endpoint must not stop the others, and
 * an alerting tool that dies while alerting is worse than the alert.
 */

export type IncidentChannel = 'slack' | 'discord' | 'pagerduty';
export type IncidentSeverity = 'critical' | 'error' | 'warning' | 'info';
export type IncidentStatus = 'triggered' | 'resolved';

export interface Incident {
  /** Stable identity used for dedup when `dedupKey` is omitted. */
  id?: string;
  title: string;
  summary?: string;
  severity: IncidentSeverity;
  /** The anchor domain, file, or monitor that observed the problem. */
  source?: string;
  /** Rule or check id, e.g. `security/dnssec-not-enabled`. */
  rule?: string;
  details?: Record<string, string | number | boolean>;
  dedupKey?: string;
  status?: IncidentStatus;
  /** ISO-8601 or epoch milliseconds; omitted payloads stay deterministic. */
  timestamp?: string | number;
}

export interface IncidentTargets {
  slack?: string;
  discord?: string;
  pagerduty?: string;
  /** PagerDuty Events API v2 integration key. */
  pagerdutyRoutingKey?: string;
}

export interface IncidentDelivery {
  channel: IncidentChannel;
  url: string;
  ok: boolean;
  attempts: number;
  /** True when the throttle window suppressed an identical alert. */
  deduplicated?: boolean;
  status?: number;
  error?: string;
}

export interface DispatcherOptions {
  fetchImpl?: typeof fetch;
  sleepImpl?: (ms: number) => Promise<void>;
  /** Injected clock so throttle tests need not sleep. */
  now?: () => number;
  /** Suppress a repeated dedup key for this long. Default 5 minutes. */
  throttleMs?: number;
  /** Retries after the first attempt. Default 2. */
  retries?: number;
  backoffMs?: number;
  timeoutMs?: number;
}

export interface SlackIncidentPayload {
  text: string;
  attachments: { color: string; blocks: Record<string, unknown>[] }[];
}

export interface DiscordIncidentPayload {
  embeds: {
    title: string;
    description: string;
    color: number;
    fields: { name: string; value: string; inline: boolean }[];
    footer: { text: string };
    timestamp?: string;
  }[];
}

export interface PagerDutyIncidentPayload {
  routing_key: string;
  event_action: 'trigger' | 'resolve';
  dedup_key: string;
  payload: {
    summary: string;
    source: string;
    severity: IncidentSeverity;
    timestamp?: string;
    custom_details: Record<string, string | number | boolean>;
  };
}

const DEFAULT_THROTTLE_MS = 5 * 60 * 1000;
const DEFAULT_RETRIES = 2;
const DEFAULT_BACKOFF_MS = 250;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_ROUTING_KEY = 'stellar-toml-lint';

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

const SLACK_COLORS: Record<IncidentSeverity | IncidentStatus, string> = {
  critical: '#E01E5A',
  error: '#E01E5A',
  warning: '#ECB22E',
  info: '#2EB67D',
  triggered: '#E01E5A',
  resolved: '#2EB67D',
};

const DISCORD_COLORS: Record<IncidentSeverity | IncidentStatus, number> = {
  critical: 0xe01e5a,
  error: 0xe01e5a,
  warning: 0xecb22e,
  info: 0x2eb67d,
  triggered: 0xe01e5a,
  resolved: 0x2eb67d,
};

/**
 * Severity-based routing. Critical findings page; warnings stay in chat so an
 * operator is not woken by a warning that a scheduled job can fix.
 */
export const SEVERITY_ROUTES: Record<IncidentSeverity, readonly IncidentChannel[]> = {
  critical: ['pagerduty', 'slack', 'discord'],
  error: ['pagerduty', 'slack'],
  warning: ['slack', 'discord'],
  info: ['slack', 'discord'],
};

export function routesFor(severity: IncidentSeverity): readonly IncidentChannel[] {
  return SEVERITY_ROUTES[severity];
}

export function dedupKeyFor(incident: Incident): string {
  if (incident.dedupKey !== undefined && incident.dedupKey !== '') return incident.dedupKey;
  return [incident.source ?? 'unknown', incident.rule ?? incident.title, incident.id ?? ''].join(
    ':',
  );
}

function statusOf(incident: Incident): IncidentStatus {
  return incident.status ?? 'triggered';
}

function timestampOf(incident: Incident): string | undefined {
  if (incident.timestamp === undefined) return undefined;
  const date =
    typeof incident.timestamp === 'number'
      ? new Date(incident.timestamp)
      : new Date(incident.timestamp);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function detailEntries(incident: Incident): [string, string][] {
  return Object.entries(incident.details ?? {}).map(([key, value]) => [key, String(value)]);
}

// ── Formatters ───────────────────────────────────────────────────────────────

export function formatSlackIncident(incident: Incident): SlackIncidentPayload {
  const status = statusOf(incident);
  const level = status === 'resolved' ? 'resolved' : incident.severity;
  const headline =
    status === 'resolved' ? `✅ Resolved: ${incident.title}` : `🚨 ${incident.title}`;

  const blocks: Record<string, unknown>[] = [
    {
      type: 'header',
      text: { type: 'plain_text', text: headline, emoji: true },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Severity*\n${incident.severity}` },
        { type: 'mrkdwn', text: `*Status*\n${status}` },
        { type: 'mrkdwn', text: `*Source*\n${incident.source ?? 'stellar-toml-lint'}` },
        { type: 'mrkdwn', text: `*Rule*\n${incident.rule ?? '—'}` },
      ],
    },
  ];

  if (incident.summary !== undefined && incident.summary !== '') {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: incident.summary } });
  }

  const details = detailEntries(incident);
  if (details.length > 0) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: details.map(([key, value]) => `• *${key}*: ${value}`).join('\n'),
      },
    });
  }

  blocks.push({
    type: 'context',
    elements: [{ type: 'mrkdwn', text: `dedup: \`${dedupKeyFor(incident)}\`` }],
  });

  return {
    text: `${incident.title} (${incident.severity}, ${status})`,
    attachments: [{ color: SLACK_COLORS[level], blocks }],
  };
}

export function formatDiscordIncident(incident: Incident): DiscordIncidentPayload {
  const status = statusOf(incident);
  const level = status === 'resolved' ? 'resolved' : incident.severity;

  const fields = [
    { name: 'Severity', value: incident.severity, inline: true },
    { name: 'Status', value: status, inline: true },
    { name: 'Source', value: incident.source ?? 'stellar-toml-lint', inline: true },
  ];
  if (incident.rule !== undefined) {
    fields.push({ name: 'Rule', value: `\`${incident.rule}\``, inline: true });
  }
  for (const [key, value] of detailEntries(incident)) {
    fields.push({ name: key, value: value.slice(0, 1024), inline: true });
  }

  const timestamp = timestampOf(incident);
  return {
    embeds: [
      {
        title: status === 'resolved' ? `Resolved: ${incident.title}` : incident.title,
        description: incident.summary ?? '',
        color: DISCORD_COLORS[level],
        fields,
        footer: { text: `stellar-toml-lint • ${dedupKeyFor(incident)}` },
        ...(timestamp !== undefined ? { timestamp } : {}),
      },
    ],
  };
}

export function formatPagerDutyIncident(
  incident: Incident,
  routingKey: string,
): PagerDutyIncidentPayload {
  const status = statusOf(incident);
  // Events API v2 maps `error` onto `critical`: it has no `error` severity.
  const severity: IncidentSeverity = incident.severity === 'error' ? 'critical' : incident.severity;
  const timestamp = timestampOf(incident);

  return {
    routing_key: routingKey,
    event_action: status === 'resolved' ? 'resolve' : 'trigger',
    dedup_key: dedupKeyFor(incident),
    payload: {
      summary:
        incident.summary !== undefined ? `${incident.title}: ${incident.summary}` : incident.title,
      source: incident.source ?? 'stellar-toml-lint',
      severity,
      ...(timestamp !== undefined ? { timestamp } : {}),
      custom_details: {
        ...(incident.rule !== undefined ? { rule: incident.rule } : {}),
        ...(incident.details ?? {}),
      },
    },
  };
}

/** Payload for a channel, or `undefined` when the channel is not applicable. */
export function formatIncident(
  incident: Incident,
  channel: IncidentChannel,
  routingKey = DEFAULT_ROUTING_KEY,
): unknown {
  switch (channel) {
    case 'slack':
      return formatSlackIncident(incident);
    case 'discord':
      return formatDiscordIncident(incident);
    case 'pagerduty':
      return formatPagerDutyIncident(incident, routingKey);
  }
}

// ── Delivery ─────────────────────────────────────────────────────────────────

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function isSupportedIncidentUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname !== '';
  } catch {
    return false;
  }
}

export class IncidentWebhookDispatcher {
  private readonly options: Required<
    Pick<DispatcherOptions, 'throttleMs' | 'retries' | 'backoffMs' | 'timeoutMs'>
  > &
    Pick<DispatcherOptions, 'fetchImpl' | 'sleepImpl' | 'now'>;
  /** dedup key → when it was last sent, and the status sent. */
  private readonly sent = new Map<string, { at: number; status: IncidentStatus }>();

  constructor(options: DispatcherOptions = {}) {
    this.options = {
      throttleMs: options.throttleMs ?? DEFAULT_THROTTLE_MS,
      retries: options.retries ?? DEFAULT_RETRIES,
      backoffMs: options.backoffMs ?? DEFAULT_BACKOFF_MS,
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.sleepImpl !== undefined ? { sleepImpl: options.sleepImpl } : {}),
      ...(options.now !== undefined ? { now: options.now } : {}),
    };
  }

  /**
   * True when the incident should be delivered now. A resolution always is;
   * a repeated trigger inside the throttle window is not.
   */
  shouldDispatch(incident: Incident, now = this.now()): boolean {
    if (statusOf(incident) === 'resolved') return true;
    const previous = this.sent.get(dedupKeyFor(incident));
    if (previous === undefined) return true;
    return now - previous.at >= this.options.throttleMs;
  }

  /** Forgets all throttle state; used by tests and by a restart. */
  reset(): void {
    this.sent.clear();
  }

  /**
   * Delivers one incident to the channels its severity routes to. Channels in
   * `targets` that are not in the route are skipped, so a critical finding
   * cannot be muted by only configuring chat.
   */
  async dispatch(
    incident: Incident,
    targets: IncidentTargets,
    options: { force?: boolean } = {},
  ): Promise<IncidentDelivery[]> {
    const now = this.now();
    const route = routesFor(incident.severity);
    const key = dedupKeyFor(incident);
    const suppressed =
      statusOf(incident) === 'triggered' && !options.force && !this.shouldDispatch(incident, now);

    const plan = route
      .map((channel) => ({ channel, url: targets[channel] }))
      .filter(
        (entry): entry is { channel: IncidentChannel; url: string } =>
          typeof entry.url === 'string',
      );

    if (suppressed) {
      return plan.map(({ channel, url }) => ({
        channel,
        url,
        ok: true,
        attempts: 0,
        deduplicated: true,
      }));
    }

    const deliveries: IncidentDelivery[] = [];
    for (const { channel, url } of plan) {
      deliveries.push(await this.deliver(incident, channel, url, targets));
    }

    if (deliveries.some((delivery) => delivery.ok) || plan.length === 0) {
      this.sent.set(key, { at: now, status: statusOf(incident) });
      if (statusOf(incident) === 'resolved') this.sent.delete(key);
    }
    return deliveries;
  }

  /** Sends the matching resolve event and clears the dedup window. */
  resolve(incident: Incident, targets: IncidentTargets): Promise<IncidentDelivery[]> {
    return this.dispatch({ ...incident, status: 'resolved' }, targets, { force: true });
  }

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  private async deliver(
    incident: Incident,
    channel: IncidentChannel,
    url: string,
    targets: IncidentTargets,
  ): Promise<IncidentDelivery> {
    if (!isSupportedIncidentUrl(url)) {
      return {
        channel,
        url,
        ok: false,
        attempts: 0,
        error: 'unsupported webhook URL (expected http or https)',
      };
    }

    const routingKey = targets.pagerdutyRoutingKey ?? DEFAULT_ROUTING_KEY;
    const payload = formatIncident(incident, channel, routingKey);
    const send = this.options.fetchImpl ?? fetch;
    const sleep = this.options.sleepImpl ?? defaultSleep;
    let lastError: string | undefined;
    let lastStatus: number | undefined;

    for (let attempt = 1; attempt <= this.options.retries + 1; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.options.timeoutMs);
      try {
        const response = await send(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        if (response.ok) {
          return { channel, url, ok: true, attempts: attempt, status: response.status };
        }

        lastStatus = response.status;
        lastError = `HTTP ${response.status}`;
        if (!RETRYABLE_STATUS.has(response.status)) {
          return {
            channel,
            url,
            ok: false,
            attempts: attempt,
            status: response.status,
            error: lastError,
          };
        }

        if (response.status === 429) {
          const retryAfter = Number.parseFloat(response.headers?.get?.('retry-after') ?? '');
          if (Number.isFinite(retryAfter) && retryAfter > 0 && attempt <= this.options.retries) {
            clearTimeout(timer);
            await sleep(retryAfter * 1000);
            continue;
          }
        }
      } catch (error) {
        lastError = messageOf(error);
      } finally {
        clearTimeout(timer);
      }

      if (attempt <= this.options.retries) {
        await sleep(this.options.backoffMs * 2 ** (attempt - 1));
      }
    }

    return {
      channel,
      url,
      ok: false,
      attempts: this.options.retries + 1,
      ...(lastStatus !== undefined ? { status: lastStatus } : {}),
      ...(lastError !== undefined ? { error: lastError } : {}),
    };
  }
}

export function renderIncidentReport(deliveries: readonly IncidentDelivery[]): string {
  if (deliveries.length === 0) return 'No channels configured for this severity.\n';
  return `${deliveries
    .map((delivery) => {
      if (delivery.deduplicated === true) {
        return `  ${delivery.channel}: suppressed (deduplicated)`;
      }
      const marker = delivery.ok ? '✔' : '✖';
      const detail = delivery.error ?? `HTTP ${delivery.status ?? 'unknown'}`;
      return `  ${marker} ${delivery.channel}: ${detail} (${delivery.attempts} attempt${
        delivery.attempts === 1 ? '' : 's'
      })`;
    })
    .join('\n')}\n`;
}
