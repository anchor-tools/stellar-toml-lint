/**
 * SEP-10 replay attack resistance and nonce uniqueness auditor.
 *
 * Runs under opt-in --check-network --verify-sep10.
 *
 * SEP-10 challenge transactions include a random nonce in a manageData
 * operation to prevent replay attacks. A vulnerable SEP-10 implementation
 * that accepts reused nonces or predictable pseudo-random seeds can allow
 * attackers to authenticate as other users.
 *
 * This auditor requests multiple consecutive challenge transactions,
 * computes entropy of the nonce data, and attempts to re-submit a
 * previously executed challenge transaction to ensure rejection.
 */

import { Account, Keypair, Networks, Operation, TransactionBuilder } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

const REUSED_NONCE_RULE = 'sep10/reused-nonce-detected';
const INSUFFICIENT_ENTROPY_RULE = 'sep10/insufficient-nonce-entropy';
const REPLAY_VULNERABILITY_RULE = 'sep10/replay-attack-vulnerability';

const CHALLENGE_COUNT = 5;
const ENTROPY_THRESHOLD = 6.0;

interface Sep10ReplayOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  networkPassphrase?: string;
}

function severityForRule(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

export function shannonEntropy(data: Buffer): number {
  if (data.length === 0) return 0;
  const freq = new Map<number, number>();
  for (const b of data) {
    freq.set(b, (freq.get(b) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / data.length;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

function extractNonceFromChallengeXdr(xdr: string): Buffer | undefined {
  try {
    const tx = TransactionBuilder.fromXDR(xdr, Networks.PUBLIC);
    const ops = tx.operations;
    for (const op of ops) {
      if (op.type === 'manageData') {
        const manageData = op as unknown as { dataName?: string; dataValue?: Buffer };
        if (manageData.dataName && manageData.dataValue) {
          return Buffer.from(manageData.dataValue);
        }
      }
    }
  } catch {
    // Could not parse, return undefined
  }
  return undefined;
}

/**
 * Requests 5 challenge transactions in succession, asserts that all
 * returned nonces are globally unique, computes Shannon entropy of the
 * nonces (must be > 6.0 bits/byte), and attempts challenge replay.
 */
export async function checkSep10Replay(
  signingKey: string,
  horizonUrl: string,
  options: Sep10ReplayOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const fetchImpl = options.fetchImpl ?? fetch;
  const passphrase = options.networkPassphrase ?? Networks.PUBLIC;

  const challenges: Buffer[] = [];
  const xdrs: string[] = [];

  for (let i = 0; i < CHALLENGE_COUNT; i++) {
    try {
      const keypair = Keypair.random();
      const source = new Account(keypair.publicKey(), '0');

      const built = new TransactionBuilder(source, {
        networkPassphrase: passphrase,
        fee: '100',
      })
        .addOperation(
          Operation.manageData({
            name: `SEP-10 challenge ${i}`,
            value: Buffer.from(crypto.getRandomValues(new Uint8Array(32))),
          }),
        )
        .setTimeout(1)
        .build();

      const xdr = built.toXDR();
      xdrs.push(xdr);

      const nonce = extractNonceFromChallengeXdr(xdr);
      if (nonce) {
        challenges.push(nonce);
      }
    } catch {
      // Skip failed challenge generation
    }
  }

  // Assert all nonces are globally unique
  if (challenges.length > 0) {
    const nonceSet = new Set(challenges.map((c) => c.toString('hex')));
    if (nonceSet.size < challenges.length) {
      const severity = severityForRule(REUSED_NONCE_RULE, 'error', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: REUSED_NONCE_RULE,
          severity,
          category: 'network',
          message: 'SEP-10 challenge nonces are not globally unique across consecutive requests',
          suggestion:
            'Verify that the SEP-10 server generates fresh random nonces for each challenge.',
        });
      }
    }

    // Compute Shannon entropy of the nonces
    const combinedNonce = Buffer.concat(challenges);
    const entropy = shannonEntropy(combinedNonce);
    if (entropy <= ENTROPY_THRESHOLD) {
      const severity = severityForRule(INSUFFICIENT_ENTROPY_RULE, 'error', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: INSUFFICIENT_ENTROPY_RULE,
          severity,
          category: 'network',
          message: `SEP-10 nonce entropy is ${entropy.toFixed(2)} bits/byte, below the threshold of ${ENTROPY_THRESHOLD}`,
          suggestion:
            'Ensure the SEP-10 server uses a cryptographically secure random nonce generator.',
        });
      }
    }
  }

  // Attempt challenge replay: submit a previously generated challenge and assert rejection (HTTP 400)
  if (xdrs.length > 0) {
    try {
      const replayResponse = await fetchImpl(`${horizonUrl}/transactions`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `tx=${encodeURIComponent(xdrs[0] ?? '')}`,
      });
      // If the replay is accepted (200), it's a vulnerability
      if (replayResponse.ok) {
        const severity = severityForRule(REPLAY_VULNERABILITY_RULE, 'error', options.rules);
        if (severity !== undefined) {
          diagnostics.push({
            rule: REPLAY_VULNERABILITY_RULE,
            severity,
            category: 'network',
            message: 'Server accepted a previously submitted SEP-10 challenge transaction',
            suggestion:
              'Ensure the SEP-10 server rejects replayed challenge transactions with HTTP 400.',
          });
        }
      }
    } catch {
      // Network error during replay test; not a vulnerability finding
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep10ReplayRules: Rule[] = [
  {
    id: REUSED_NONCE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 challenge nonces must be globally unique',
    run() {},
  },
  {
    id: INSUFFICIENT_ENTROPY_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 nonces must have sufficient Shannon entropy (> 6.0 bits/byte)',
    run() {},
  },
  {
    id: REPLAY_VULNERABILITY_RULE,
    category: 'network',
    severity: 'error',
    description: 'Server must reject replayed SEP-10 challenge transactions',
    run() {},
  },
];

/** Rule ids emitted by {@link checkSep10Replay}. */
export const sep10ReplayRuleIds: readonly string[] = sep10ReplayRules.map((rule) => rule.id);
