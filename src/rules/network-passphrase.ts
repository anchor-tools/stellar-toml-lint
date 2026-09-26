import type { Rule } from '../types.js';
import { KNOWN_PASSPHRASES } from '../predicates.js';

const TYPO_RULE = 'general/network-passphrase-typo';
const UNRECOGNIZED_RULE = 'general/unrecognized-network-passphrase';

/** Levenshtein distance between two strings — cheap for short passphrase strings. */
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const m = a.length;
  const n = b.length;
  const prev = Array.from({ length: n + 1 }, (_, i) => i);
  const curr = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min((prev[j] ?? m) + 1, (curr[j - 1] ?? m) + 1, (prev[j - 1] ?? m) + cost);
    }
    prev.length = 0;
    prev.push(...curr);
  }
  return prev[n] ?? m;
}

/**
 * The closest known passphrase to `input`, or `undefined` when nothing is
 * within a reasonable edit distance (half the shortest known passphrase).
 */
function nearestPassphrase(input: string): { name: string; distance: number } | undefined {
  let best: { name: string; distance: number } | undefined;
  for (const [canonical, name] of Object.entries(KNOWN_PASSPHRASES)) {
    const distance = levenshtein(input, canonical);
    if (!best || distance < best.distance) {
      best = { name, distance };
    }
  }
  if (
    best &&
    best.distance <=
      Math.floor(Math.min(...Object.keys(KNOWN_PASSPHRASES).map((k) => k.length)) / 2)
  ) {
    return best;
  }
  return undefined;
}

/**
 * Validates `NETWORK_PASSPHRASE` against recognized Stellar network
 * passphrases and detects likely typos.
 *
 * Two diagnostics:
 *   - `general/network-passphrase-typo` (error) — the value is within
 *     Levenshtein distance of a known passphrase, meaning it is almost
 *     certainly a transcription error.
 *   - `general/unrecognized-network-passphrase` (warning) — the value does
 *     not match any known passphrase and is too far from all of them to
 *     be a simple typo.
 */
export const networkPassphraseRules: Rule[] = [
  {
    id: TYPO_RULE,
    category: 'general',
    severity: 'error',
    description: 'NETWORK_PASSPHRASE contains a likely typo of a known Stellar network passphrase',
    run(ctx) {
      const passphrase = ctx.doc.NETWORK_PASSPHRASE;
      if (typeof passphrase !== 'string') return;
      if (KNOWN_PASSPHRASES[passphrase]) return;

      // First try the whitespace-normalization shortcut the existing rule uses.
      const normalized = passphrase.trim().replace(/\s*;\s*/, ' ; ');
      if (KNOWN_PASSPHRASES[normalized]) return;

      const nearest = nearestPassphrase(passphrase);
      if (!nearest) return;

      ctx.report({
        rule: TYPO_RULE,
        category: 'general',
        message: `NETWORK_PASSPHRASE is a likely typo of the ${nearest.name} passphrase (edit distance ${nearest.distance})`,
        path: 'NETWORK_PASSPHRASE',
        position: ctx.locate('NETWORK_PASSPHRASE'),
        helpUri: 'https://developers.stellar.org/docs/networks',
        suggestion: `Replace it with exactly: ${Object.entries(KNOWN_PASSPHRASES).find(([, n]) => n === nearest.name)![0]}`,
      });
    },
  },
  {
    id: UNRECOGNIZED_RULE,
    category: 'general',
    severity: 'warning',
    description: 'NETWORK_PASSPHRASE does not match any recognized Stellar network',
    run(ctx) {
      const passphrase = ctx.doc.NETWORK_PASSPHRASE;
      if (typeof passphrase !== 'string') return;
      if (KNOWN_PASSPHRASES[passphrase]) return;

      // If the whitespace-normalized form matches, the existing
      // network/passphrase rule already handles it — skip to avoid a
      // redundant diagnostic.
      const normalized = passphrase.trim().replace(/\s*;\s*/, ' ; ');
      if (KNOWN_PASSPHRASES[normalized]) return;

      // If it is close to a known passphrase, the typo rule handles it.
      if (nearestPassphrase(passphrase)) return;

      ctx.report({
        rule: UNRECOGNIZED_RULE,
        category: 'general',
        message: `NETWORK_PASSPHRASE "${passphrase}" does not match any known Stellar network`,
        path: 'NETWORK_PASSPHRASE',
        position: ctx.locate('NETWORK_PASSPHRASE'),
        helpUri: 'https://developers.stellar.org/docs/networks',
        suggestion:
          'Use the Public, Testnet, or Futurenet passphrase exactly as published. Custom passphrases are supported but may confuse wallets and exchanges.',
      });
    },
  },
];
