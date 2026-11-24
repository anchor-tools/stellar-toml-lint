import { describe, expect, it } from 'vitest';
import {
  ArchiveProgressionVerifier,
  formatCheckpointLedgerHex,
} from '../../src/overlay/archiveProgressionVerifier.js';

describe('ArchiveProgressionVerifier', () => {
  describe('Checkpoint Ledger Calculations', () => {
    const verifier = new ArchiveProgressionVerifier();

    it('calculates checkpoint ledgers accurately for 64-ledger frequency', () => {
      // Ledger 63 is the 1st checkpoint (height 1)
      expect(verifier.calculateCheckpoint(63)).toEqual({
        checkpointLedger: 63,
        checkpointHeight: 1,
      });

      // Ledger 64 is still in checkpoint 1 interval
      expect(verifier.calculateCheckpoint(64)).toEqual({
        checkpointLedger: 63,
        checkpointHeight: 1,
      });

      // Ledger 127 is checkpoint 2
      expect(verifier.calculateCheckpoint(127)).toEqual({
        checkpointLedger: 127,
        checkpointHeight: 2,
      });

      // Ledger 191 is checkpoint 3
      expect(verifier.calculateCheckpoint(191)).toEqual({
        checkpointLedger: 191,
        checkpointHeight: 3,
      });
    });

    it('formats hex history file path correctly', () => {
      // 63 in hex is 0x3f -> 00/00/00/history-0000003f.json
      expect(formatCheckpointLedgerHex(63)).toBe('00/00/00/history-0000003f.json');
      // 127 in hex is 0x7f -> 00/00/00/history-0000007f.json
      expect(formatCheckpointLedgerHex(127)).toBe('00/00/00/history-0000007f.json');
      // 50123455 in hex is 0x02fcd2bf
      expect(formatCheckpointLedgerHex(50123455)).toBe('02/fc/d2/history-02fcd2bf.json');
    });
  });

  describe('parseHistoryUrls from stellar.toml', () => {
    it('extracts unique history URLs from [[VALIDATORS]] and cleans trailing slashes', () => {
      const verifier = new ArchiveProgressionVerifier();
      const toml = `
[[VALIDATORS]]
ALIAS = "val1"
PUBLIC_KEY = "GVAL1"
HISTORY = "https://history.example.com/prd/001/"

[[VALIDATORS]]
ALIAS = "val2"
PUBLIC_KEY = "GVAL2"
HISTORY = "https://history.example.com/prd/002"

[[VALIDATORS]]
ALIAS = "val3"
PUBLIC_KEY = "GVAL3"
HISTORY = "https://history.example.com/prd/001" # duplicate
`;
      const urls = verifier.parseHistoryUrls(toml);
      expect(urls).toHaveLength(2);
      expect(urls).toEqual([
        'https://history.example.com/prd/001',
        'https://history.example.com/prd/002',
      ]);
    });

    it('extracts top-level HISTORY and HISTORY_ARCHIVES arrays', () => {
      const verifier = new ArchiveProgressionVerifier();
      const toml = `
HISTORY_ARCHIVES = [
  "https://archive1.stellar.org",
  "https://archive2.stellar.org/"
]
`;
      const urls = verifier.parseHistoryUrls(toml);
      expect(urls).toEqual(['https://archive1.stellar.org', 'https://archive2.stellar.org']);
    });
  });

  describe('Live Lag Verification against Horizon', () => {
    it('passes when archive lag is <= 2 checkpoints', async () => {
      // Archive currentLedger = 127 (checkpoint height 2)
      // Live ledger = 191 (checkpoint height 3)
      // Lag = 3 - 2 = 1 checkpoint <= 2 checkpoints (OK)
      const mockFetch: typeof fetch = async (url) => {
        const u = url.toString();
        if (u.includes('.well-known/stellar-history.json')) {
          return new Response(
            JSON.stringify({
              version: 1,
              server: 'v20.0.0',
              currentLedger: 127,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (u.includes('/history/')) {
          return new Response(JSON.stringify({ bucketListHash: '0x112233' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response('Not found', { status: 404 });
      };

      const verifier = new ArchiveProgressionVerifier({ fetchImpl: mockFetch });
      const status = await verifier.verifyArchive('https://history.stellar.org', 191);

      expect(status.ok).toBe(true);
      expect(status.isLagging).toBe(false);
      expect(status.currentLedger).toBe(127);
      expect(status.checkpointHeight).toBe(2);
      expect(status.liveCheckpointHeight).toBe(3);
      expect(status.checkpointLag).toBe(1);
      expect(status.bucketListHash).toBe('0x112233');
    });

    it('detects lag > 2 checkpoints and marks as lagging error', async () => {
      // Archive currentLedger = 63 (checkpoint height 1)
      // Live ledger = 319 (checkpoint height 5)
      // Lag = 5 - 1 = 4 checkpoints > 2 checkpoints!
      const mockFetch: typeof fetch = async (url) => {
        const u = url.toString();
        if (u.includes('.well-known/stellar-history.json')) {
          return new Response(
            JSON.stringify({
              version: 1,
              server: 'v20.0.0',
              currentLedger: 63,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response('Not found', { status: 404 });
      };

      const verifier = new ArchiveProgressionVerifier({
        fetchImpl: mockFetch,
        maxLagCheckpoints: 2,
      });

      const report = await verifier.verify(['https://lagging-archive.stellar.org'], {
        liveLedger: 319,
      });

      expect(report.ok).toBe(false);
      expect(report.hasLaggingArchives).toBe(true);
      expect(report.archives[0]!.isLagging).toBe(true);
      expect(report.archives[0]!.checkpointLag).toBe(4);
      expect(report.errors[0]).toContain('lagging by 4 checkpoints');
    });

    it('fetches live ledger from Horizon endpoint and runs full audit', async () => {
      const mockFetch: typeof fetch = async (url) => {
        const u = url.toString();
        if (u === 'https://horizon.stellar.org') {
          return new Response(
            JSON.stringify({
              core_latest_ledger: 500,
              history_latest_ledger: 500,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (u.includes('.well-known/stellar-history.json')) {
          return new Response(
            JSON.stringify({
              version: 1,
              currentLedger: 480,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response('Not found', { status: 404 });
      };

      const verifier = new ArchiveProgressionVerifier({
        fetchImpl: mockFetch,
        horizonUrl: 'https://horizon.stellar.org',
      });

      const report = await verifier.verify(['https://archive.stellar.org']);
      expect(report.liveLedger).toBe(500);
      expect(report.archives).toHaveLength(1);
      // 500 ledgers: cp height = floor(501/64) = 7
      // 480 ledgers: cp height = floor(481/64) = 7
      // lag = 0
      expect(report.ok).toBe(true);
      expect(report.archives[0]!.checkpointLag).toBe(0);
    });

    it('handles HTTP error on archive manifest gracefully', async () => {
      const mockFetch: typeof fetch = async () => new Response('Internal error', { status: 500 });
      const verifier = new ArchiveProgressionVerifier({ fetchImpl: mockFetch });

      const status = await verifier.verifyArchive('https://broken.stellar.org', 100);
      expect(status.ok).toBe(false);
      expect(status.error).toContain('HTTP 500');
    });
  });
});
