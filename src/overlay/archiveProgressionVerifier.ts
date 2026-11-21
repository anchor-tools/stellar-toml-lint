import { parse as parseToml } from 'smol-toml';
import type { StellarToml } from '../types.js';

export const CHECKPOINT_FREQUENCY = 64;
export const DEFAULT_MAX_LAG_CHECKPOINTS = 2;
export const DEFAULT_TIMEOUT_MS = 10_000;
export const MANIFEST_PATH = '.well-known/stellar-history.json';

export interface StellarHistoryJson {
  version: number;
  server?: string;
  currentLedger?: number;
  networkPassphrase?: string;
  [key: string]: unknown;
}

export interface ArchiveProgressionStatus {
  archiveUrl: string;
  manifestUrl: string;
  version?: number;
  server?: string;
  currentLedger?: number;
  checkpointLedger?: number;
  checkpointHeight?: number;
  bucketListHash?: string;
  liveLedger?: number;
  liveCheckpointHeight?: number;
  checkpointLag?: number;
  ledgerLag?: number;
  isLagging: boolean;
  ok: boolean;
  error?: string;
}

export interface ArchiveProgressionReport {
  ok: boolean;
  hasLaggingArchives: boolean;
  liveLedger?: number;
  horizonUrl?: string;
  archives: ArchiveProgressionStatus[];
  warnings: string[];
  errors: string[];
}

export interface ArchiveProgressionVerifierOptions {
  fetchImpl?: typeof fetch;
  horizonUrl?: string;
  liveLedger?: number;
  checkpointFrequency?: number;
  maxLagCheckpoints?: number;
  timeoutMs?: number;
}

/**
 * Calculates hex path components for a ledger sequence in history archive format.
 * E.g. ledger 63 -> 00/00/00/history-0000003f.json
 */
export function formatCheckpointLedgerHex(ledger: number): string {
  const hex = ledger.toString(16).padStart(8, '0');
  const p1 = hex.slice(0, 2);
  const p2 = hex.slice(2, 4);
  const p3 = hex.slice(4, 6);
  return `${p1}/${p2}/${p3}/history-${hex}.json`;
}

export class ArchiveProgressionVerifier {
  private readonly fetchImpl: typeof fetch;
  private readonly horizonUrl?: string;
  private readonly liveLedgerOverride?: number;
  private readonly checkpointFrequency: number;
  private readonly maxLagCheckpoints: number;
  private readonly timeoutMs: number;

  constructor(options: ArchiveProgressionVerifierOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.horizonUrl = options.horizonUrl;
    this.liveLedgerOverride = options.liveLedger;
    this.checkpointFrequency = options.checkpointFrequency ?? CHECKPOINT_FREQUENCY;
    this.maxLagCheckpoints = options.maxLagCheckpoints ?? DEFAULT_MAX_LAG_CHECKPOINTS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /**
   * Calculates the latest checkpoint ledger sequence and height for a given ledger.
   * In Stellar, checkpoints occur every 64 ledgers at (k * 64) - 1 (63, 127, 191...).
   */
  public calculateCheckpoint(
    ledger: number,
    frequency: number = this.checkpointFrequency,
  ): { checkpointLedger: number; checkpointHeight: number } {
    if (ledger <= 0) {
      return { checkpointLedger: 0, checkpointHeight: 0 };
    }
    const checkpointHeight = Math.floor((ledger + 1) / frequency);
    const checkpointLedger = Math.max(0, checkpointHeight * frequency - 1);
    return { checkpointLedger, checkpointHeight };
  }

  /**
   * Extracts HISTORY archive URLs declared in stellar.toml.
   */
  public parseHistoryUrls(input: string | StellarToml | Record<string, unknown>): string[] {
    let doc: Record<string, unknown> = {};
    if (typeof input === 'string') {
      try {
        doc = parseToml(input) as Record<string, unknown>;
      } catch (err) {
        throw new Error(`Failed to parse TOML: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
      }
    } else if (typeof input === 'object' && input !== null) {
      doc = input as Record<string, unknown>;
    }

    const urls = new Set<string>();

    // Inspect [[VALIDATORS]]
    const validators = (doc['VALIDATORS'] ?? doc['validators']) as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(validators)) {
      for (const val of validators) {
        const history = val['HISTORY'] ?? val['history'];
        if (typeof history === 'string' && history.trim().length > 0) {
          urls.add(history.trim().replace(/\/+$/, ''));
        }
      }
    }

    // Inspect top-level HISTORY or HISTORY_ARCHIVES
    const topHistory = doc['HISTORY'] ?? doc['history'];
    if (typeof topHistory === 'string' && topHistory.trim().length > 0) {
      urls.add(topHistory.trim().replace(/\/+$/, ''));
    } else if (Array.isArray(topHistory)) {
      for (const h of topHistory) {
        if (typeof h === 'string' && h.trim().length > 0) {
          urls.add(h.trim().replace(/\/+$/, ''));
        }
      }
    }

    const historyArchives = doc['HISTORY_ARCHIVES'] ?? doc['history_archives'];
    if (Array.isArray(historyArchives)) {
      for (const h of historyArchives) {
        if (typeof h === 'string' && h.trim().length > 0) {
          urls.add(h.trim().replace(/\/+$/, ''));
        }
      }
    }

    return Array.from(urls).sort();
  }

  /**
   * Fetches the current live ledger from Horizon or returns injected override.
   */
  public async fetchLiveLedger(horizonUrl?: string): Promise<number | undefined> {
    if (this.liveLedgerOverride !== undefined) {
      return this.liveLedgerOverride;
    }

    const targetUrl = horizonUrl ?? this.horizonUrl;
    if (!targetUrl) return undefined;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const url = targetUrl.replace(/\/+$/, '');
      const response = await this.fetchImpl(url, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`Horizon responded with HTTP ${response.status}`);
      }
      const data = (await response.json()) as Record<string, unknown>;
      const live =
        data['history_latest_ledger'] ??
        data['core_latest_ledger'] ??
        data['latest_ledger'] ??
        data['current_ledger'];

      if (typeof live === 'number') {
        return live;
      }

      // Try /ledgers endpoint if root didn't contain ledger sequence
      const ledgersResp = await this.fetchImpl(`${url}/ledgers?order=desc&limit=1`, {
        signal: controller.signal,
      });
      if (ledgersResp.ok) {
        const ledgersData = (await ledgersResp.json()) as {
          _embedded?: { records?: Array<{ sequence?: number }> };
        };
        const seq = ledgersData._embedded?.records?.[0]?.sequence;
        if (typeof seq === 'number') return seq;
      }
    } catch (err) {
      throw new Error(`Failed to query Horizon live ledger: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
    } finally {
      clearTimeout(timer);
    }

    return undefined;
  }

  /**
   * Verifies an archive's manifest state, calculates checkpoint ledger, and evaluates lag.
   */
  public async verifyArchive(
    archiveUrl: string,
    liveLedger?: number,
  ): Promise<ArchiveProgressionStatus> {
    const cleanUrl = archiveUrl.replace(/\/+$/, '');
    const manifestUrl = `${cleanUrl}/${MANIFEST_PATH}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(manifestUrl, { signal: controller.signal });
      if (!response.ok) {
        return {
          archiveUrl: cleanUrl,
          manifestUrl,
          isLagging: false,
          ok: false,
          error: `HTTP ${response.status} fetching ${MANIFEST_PATH}`,
        };
      }

      const manifest = (await response.json()) as StellarHistoryJson;
      const currentLedger = typeof manifest.currentLedger === 'number' ? manifest.currentLedger : undefined;

      if (currentLedger === undefined) {
        return {
          archiveUrl: cleanUrl,
          manifestUrl,
          version: manifest.version,
          server: manifest.server,
          isLagging: false,
          ok: false,
          error: `Manifest missing "currentLedger" property`,
        };
      }

      const { checkpointLedger, checkpointHeight } = this.calculateCheckpoint(currentLedger);

      // Attempt to inspect bucketListHash from the checkpoint history JSON if accessible
      let bucketListHash: string | undefined;
      try {
        const historyJsonRelPath = formatCheckpointLedgerHex(checkpointLedger);
        const historyFileUrl = `${cleanUrl}/history/${historyJsonRelPath}`;
        const histResp = await this.fetchImpl(historyFileUrl, { signal: controller.signal });
        if (histResp.ok) {
          const histData = (await histResp.json()) as Record<string, unknown>;
          if (typeof histData['bucketListHash'] === 'string') {
            bucketListHash = histData['bucketListHash'];
          }
        }
      } catch {
        // bucketListHash is optional progression metadata
      }

      let liveCheckpointHeight: number | undefined;
      let checkpointLag: number | undefined;
      let ledgerLag: number | undefined;
      let isLagging = false;

      if (liveLedger !== undefined) {
        const liveCp = this.calculateCheckpoint(liveLedger);
        liveCheckpointHeight = liveCp.checkpointHeight;
        checkpointLag = Math.max(0, liveCheckpointHeight - checkpointHeight);
        ledgerLag = Math.max(0, liveLedger - currentLedger);
        isLagging = checkpointLag > this.maxLagCheckpoints;
      }

      return {
        archiveUrl: cleanUrl,
        manifestUrl,
        version: manifest.version,
        server: manifest.server,
        currentLedger,
        checkpointLedger,
        checkpointHeight,
        bucketListHash,
        liveLedger,
        liveCheckpointHeight,
        checkpointLag,
        ledgerLag,
        isLagging,
        ok: !isLagging,
      };
    } catch (err) {
      return {
        archiveUrl: cleanUrl,
        manifestUrl,
        isLagging: false,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Verifies all declared HISTORY archives in stellar.toml or array of URLs.
   */
  public async verify(
    input: string | StellarToml | Record<string, unknown> | string[],
    options: { horizonUrl?: string; liveLedger?: number } = {},
  ): Promise<ArchiveProgressionReport> {
    const urls: string[] = Array.isArray(input)
      ? input.map((u) => u.replace(/\/+$/, ''))
      : this.parseHistoryUrls(input);

    const targetHorizon = options.horizonUrl ?? this.horizonUrl;
    let liveLedger = options.liveLedger ?? this.liveLedgerOverride;

    const warnings: string[] = [];
    const errors: string[] = [];

    if (liveLedger === undefined && targetHorizon) {
      try {
        liveLedger = await this.fetchLiveLedger(targetHorizon);
      } catch (err) {
        warnings.push(`Could not fetch live ledger from Horizon (${targetHorizon}): ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (urls.length === 0) {
      warnings.push('No HISTORY archives declared.');
      return {
        ok: true,
        hasLaggingArchives: false,
        liveLedger,
        horizonUrl: targetHorizon,
        archives: [],
        warnings,
        errors,
      };
    }

    const archives: ArchiveProgressionStatus[] = [];
    for (const url of urls) {
      const status = await this.verifyArchive(url, liveLedger);
      archives.push(status);
      if (status.isLagging) {
        errors.push(
          `History archive ${url} is lagging by ${status.checkpointLag} checkpoints (${status.ledgerLag} ledgers) behind live ledger ${liveLedger}.`,
        );
      } else if (!status.ok && status.error) {
        errors.push(`History archive ${url} error: ${status.error}`);
      }
    }

    const hasLaggingArchives = archives.some((a) => a.isLagging);
    const ok = !hasLaggingArchives && archives.every((a) => a.ok);

    return {
      ok,
      hasLaggingArchives,
      liveLedger,
      horizonUrl: targetHorizon,
      archives,
      warnings,
      errors,
    };
  }
}
