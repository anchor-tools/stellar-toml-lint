import crypto from 'node:crypto';
import { isSupportedWebhookUrl } from '../reporters/webhook.js';

export interface DiffResult {
  added: string[];
  modified: string[];
  deleted: string[];
  timestamp: string;
  url: string;
}

export interface MonitorDaemonOptions {
  url: string;
  interval?: number;
  webhookUrl?: string;
}

const DEFAULT_INTERVAL = 300;
const MAX_BACKOFF_MS = 30000;
const BASE_BACKOFF_MS = 1000;
const DEFAULT_WEBHOOK_TIMEOUT_MS = 5000;
const DEFAULT_WEBHOOK_RETRIES = 2;
const DEFAULT_WEBHOOK_BACKOFF_MS = 250;

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class MonitorDaemon {
  readonly url: string;
  readonly interval: number;
  readonly webhookUrl: string | undefined;
  lastHash: string | undefined;
  private lastBody: string | undefined;
  private backoffMs: number = BASE_BACKOFF_MS;
  private timer: NodeJS.Timeout | null = null;
  private running: boolean = false;

  constructor(options: MonitorDaemonOptions) {
    this.url = options.url;
    this.interval = options.interval ?? DEFAULT_INTERVAL;
    this.webhookUrl = options.webhookUrl;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.backoffMs = BASE_BACKOFF_MS;
    await this.poll();
  }

  stop(): void {
    this.running = false;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  async poll(): Promise<void> {
    try {
      const response = await fetch(this.url);
      const body = await response.text();
      const hash = this.computeHash(body);

      if (this.lastHash !== undefined && hash !== this.lastHash) {
        const diff = this.computeDiff(this.lastBody ?? '', body);
        if (this.webhookUrl !== undefined && isSupportedWebhookUrl(this.webhookUrl)) {
          await this.sendWebhook(diff);
        }
      }

      this.lastHash = hash;
      this.lastBody = body;
      this.backoffMs = BASE_BACKOFF_MS;

      if (this.running) {
        this.timer = setTimeout(() => this.poll(), this.interval);
      }
    } catch {
      if (this.running) {
        this.timer = setTimeout(() => this.poll(), this.backoffMs);
        this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
      }
    }
  }

  computeHash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  computeDiff(oldData: string, newData: string): DiffResult {
    const oldLines = oldData.split('\n').filter((line) => line.trim() !== '');
    const newLines = newData.split('\n').filter((line) => line.trim() !== '');

    const parseLine = (line: string): string => line.split('=')[0]?.trim() ?? line.trim();

    const oldKeys = new Map(oldLines.map((line) => [parseLine(line), line]));
    const newKeys = new Map(newLines.map((line) => [parseLine(line), line]));

    const added: string[] = [];
    const deleted: string[] = [];
    const modified: string[] = [];

    for (const [key, line] of newKeys) {
      if (!oldKeys.has(key)) {
        added.push(key);
      } else if (oldKeys.get(key) !== line) {
        modified.push(key);
      }
    }
    for (const [key] of oldKeys) {
      if (!newKeys.has(key)) {
        deleted.push(key);
      }
    }

    return {
      added,
      modified,
      deleted,
      timestamp: new Date().toISOString(),
      url: this.url,
    };
  }

  async sendWebhook(diff: DiffResult): Promise<boolean> {
    if (this.webhookUrl === undefined || !isSupportedWebhookUrl(this.webhookUrl)) {
      return false;
    }

    const payload = {
      timestamp: diff.timestamp,
      url: diff.url,
      added_fields: diff.added,
      modified_fields: diff.modified,
      deleted_fields: diff.deleted,
    };

    const send = fetch;

    for (let attempt = 1; attempt <= DEFAULT_WEBHOOK_RETRIES + 1; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), DEFAULT_WEBHOOK_TIMEOUT_MS);
      try {
        const response = await send(this.webhookUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        if (response.ok) return true;
        if (!RETRYABLE_STATUS.has(response.status)) {
          return false;
        }

        if (response.status === 429) {
          const retryAfterHeader = response.headers?.get?.('retry-after');
          if (retryAfterHeader) {
            const delaySec = parseFloat(retryAfterHeader);
            if (!isNaN(delaySec) && delaySec > 0 && attempt <= DEFAULT_WEBHOOK_RETRIES) {
              clearTimeout(timer);
              await defaultSleep(delaySec * 1000);
              continue;
            }
          }
        }
      } catch {
        // Network error; retry will follow
      } finally {
        clearTimeout(timer);
      }

      if (attempt <= DEFAULT_WEBHOOK_RETRIES) {
        await defaultSleep(DEFAULT_WEBHOOK_BACKOFF_MS * 2 ** (attempt - 1));
      }
    }

    return false;
  }
}
