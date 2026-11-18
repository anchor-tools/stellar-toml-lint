import { describe, expect, it } from 'vitest';
import {
  IncidentWebhookDispatcher,
  dedupKeyFor,
  formatDiscordIncident,
  formatPagerDutyIncident,
  formatSlackIncident,
  isSupportedIncidentUrl,
  routesFor,
  type Incident,
} from '../src/gitops/incidentDispatcher.js';

const incident: Incident = {
  title: 'Anchor reserve deficit',
  summary: 'Reserve account is 12% below liabilities',
  severity: 'critical',
  source: 'anchor.example.com',
  rule: 'currencies/issuance-exclusive',
  details: { deficit: '12%', asset: 'USDC' },
  dedupKey: 'reserve:anchor.example.com',
};

function jsonResponse(status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
  } as unknown as Response;
}

describe('payload formatters', () => {
  it('builds a Slack card with severity, details and dedup key', () => {
    const payload = formatSlackIncident(incident);
    expect(payload.text).toContain('Anchor reserve deficit');
    expect(payload.attachments[0]?.color).toBe('#E01E5A');
    const blocks = JSON.stringify(payload.attachments[0]?.blocks);
    expect(blocks).toContain('critical');
    expect(blocks).toContain('reserve:anchor.example.com');
    expect(blocks).toContain('deficit');
  });

  it('builds a Discord embed and marks resolutions green', () => {
    const resolved = formatDiscordIncident({ ...incident, status: 'resolved' });
    expect(resolved.embeds[0]?.title).toBe('Resolved: Anchor reserve deficit');
    expect(resolved.embeds[0]?.color).toBe(0x2eb67d);
    expect(resolved.embeds[0]?.timestamp).toBeUndefined();
  });

  it('builds a PagerDuty Events v2 trigger with the routing key', () => {
    const payload = formatPagerDutyIncident(incident, 'routing-key');
    expect(payload.routing_key).toBe('routing-key');
    expect(payload.event_action).toBe('trigger');
    expect(payload.dedup_key).toBe('reserve:anchor.example.com');
    expect(payload.payload.severity).toBe('critical');
    expect(payload.payload.custom_details).toEqual({ rule: incident.rule, deficit: '12%', asset: 'USDC' });
  });

  it('maps error severity onto PagerDuty critical', () => {
    expect(formatPagerDutyIncident({ ...incident, severity: 'error' }, 'k').payload.severity).toBe(
      'critical',
    );
  });

  it('derives a stable dedup key when none is supplied', () => {
    expect(dedupKeyFor({ title: 'T', severity: 'warning', source: 'a', rule: 'r' })).toBe('a:r:');
  });

  it('routes critical findings to paging and warnings to chat', () => {
    expect(routesFor('critical')).toContain('pagerduty');
    expect(routesFor('warning')).not.toContain('pagerduty');
  });

  it('validates webhook URLs', () => {
    expect(isSupportedIncidentUrl('https://hooks.slack.com/x')).toBe(true);
    expect(isSupportedIncidentUrl('ftp://example.com')).toBe(false);
    expect(isSupportedIncidentUrl('nope')).toBe(false);
  });
});

describe('IncidentWebhookDispatcher', () => {
  it('only delivers to channels the severity routes to', async () => {
    const calls: string[] = [];
    const dispatcher = new IncidentWebhookDispatcher({
      retries: 0,
      fetchImpl: async (url) => {
        calls.push(String(url));
        return jsonResponse();
      },
    });
    const deliveries = await dispatcher.dispatch(incident, {
      pagerduty: 'https://pd.example.com',
      slack: 'https://slack.example.com',
      discord: 'https://discord.example.com',
    });
    expect(deliveries.map((delivery) => delivery.channel)).toEqual([
      'pagerduty',
      'slack',
      'discord',
    ]);
    expect(calls).toHaveLength(3);
  });

  it('throttles repeated alerts for the same dedup key', async () => {
    let now = 1_000;
    let sends = 0;
    const dispatcher = new IncidentWebhookDispatcher({
      throttleMs: 60_000,
      now: () => now,
      retries: 0,
      fetchImpl: async () => {
        sends++;
        return jsonResponse();
      },
    });
    const targets = { slack: 'https://slack.example.com' };

    await dispatcher.dispatch(incident, targets);
    now += 30_000;
    const second = await dispatcher.dispatch(incident, targets);
    expect(sends).toBe(1);
    expect(second[0]?.deduplicated).toBe(true);

    now += 31_000;
    await dispatcher.dispatch(incident, targets);
    expect(sends).toBe(2);
  });

  it('sends a resolve event and clears the throttle window', async () => {
    const bodies: Record<string, unknown>[] = [];
    const dispatcher = new IncidentWebhookDispatcher({
      retries: 0,
      fetchImpl: async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        return jsonResponse();
      },
    });
    const targets = { pagerduty: 'https://pd.example.com', pagerdutyRoutingKey: 'key' };

    await dispatcher.dispatch(incident, targets);
    const deliveries = await dispatcher.resolve(incident, targets);

    expect(deliveries[0]?.ok).toBe(true);
    expect(bodies[1]?.event_action).toBe('resolve');
    expect(bodies[1]?.routing_key).toBe('key');
  });

  it('retries a 429 after the Retry-After delay', async () => {
    const sleeps: number[] = [];
    let attempt = 0;
    const dispatcher = new IncidentWebhookDispatcher({
      retries: 2,
      sleepImpl: async (ms) => {
        sleeps.push(ms);
      },
      fetchImpl: async () => {
        attempt++;
        if (attempt === 1) {
          return {
            ok: false,
            status: 429,
            headers: { get: (name: string) => (name === 'retry-after' ? '2' : null) },
          } as unknown as Response;
        }
        return jsonResponse();
      },
    });

    const deliveries = await dispatcher.dispatch(incident, { slack: 'https://slack.example.com' });
    expect(deliveries[0]?.ok).toBe(true);
    expect(deliveries[0]?.attempts).toBe(2);
    expect(sleeps).toContain(2000);
  });

  it('does not retry a 400', async () => {
    let attempts = 0;
    const dispatcher = new IncidentWebhookDispatcher({
      retries: 3,
      fetchImpl: async () => {
        attempts++;
        return jsonResponse(400);
      },
    });
    const deliveries = await dispatcher.dispatch(incident, { slack: 'https://slack.example.com' });
    expect(attempts).toBe(1);
    expect(deliveries[0]?.error).toBe('HTTP 400');
  });

  it('reports an unsupported URL without calling fetch', async () => {
    let called = false;
    const dispatcher = new IncidentWebhookDispatcher({
      fetchImpl: async () => {
        called = true;
        return jsonResponse();
      },
    });
    const deliveries = await dispatcher.dispatch(incident, { slack: 'not-a-url' });
    expect(called).toBe(false);
    expect(deliveries[0]?.ok).toBe(false);
  });
});
