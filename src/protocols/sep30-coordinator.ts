/**
 * SEP-30 Automated Multi-Party Recovery Server Threshold Signature Coordinator.
 *
 * Connects to declared RECOVERY_SERVER endpoints, coordinates mock/test recovery
 * signing requests, verifies Ed25519 cryptographic signatures on returned
 * transaction envelopes, and asserts that combined signatures satisfy the
 * required on-chain account threshold.
 *
 * Runs under opt-in `--check-network --verify-sep30`.
 */

import {
  Account,
  Keypair,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { horizonUrlFor } from '../network-checks.js';

export const INSUFFICIENT_RECOVERY_SIGNATURES_RULE = 'sep30/insufficient-recovery-signatures';
export const SIGNATURE_COORDINATION_TIMEOUT_RULE = 'sep30/signature-coordination-timeout';

export const SEP30_SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md';

export interface Sep30CoordinatorOptions {
  rules?: RuleOverrides;
  servers?: string[];
  timeoutMs?: number;
  networkPassphrase?: string;
  targetAccount?: string;
  requiredThreshold?: number;
  signerWeights?: Record<string, number>;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTimeoutError(err: unknown, status?: number): boolean {
  if (status === 408 || status === 504) return true;
  if (!err) return false;
  if (err instanceof Error) {
    if (err.name === 'AbortError' || err.name === 'TimeoutError') return true;
    const msg = err.message.toLowerCase();
    if (msg.includes('timeout') || msg.includes('timed out')) return true;
  }
  return false;
}

/**
 * Extracts all unique recovery server URLs declared in stellar.toml.
 */
export function extractRecoveryServers(doc: Record<string, unknown>): string[] {
  const servers: string[] = [];
  if (typeof doc.RECOVERY_SERVER === 'string') {
    for (const part of doc.RECOVERY_SERVER.split(',')) {
      const s = part.trim();
      if (s && isUrl(s)) servers.push(s.replace(/\/+$/, ''));
    }
  } else if (Array.isArray(doc.RECOVERY_SERVER)) {
    for (const s of doc.RECOVERY_SERVER) {
      if (typeof s === 'string' && isUrl(s)) servers.push(s.replace(/\/+$/, ''));
    }
  }

  if (Array.isArray(doc.RECOVERY_SERVERS)) {
    for (const s of doc.RECOVERY_SERVERS) {
      if (typeof s === 'string' && isUrl(s)) servers.push(s.replace(/\/+$/, ''));
    }
  }

  if (Array.isArray(doc.SERVERS)) {
    for (const entry of doc.SERVERS) {
      if (
        isRecord(entry) &&
        typeof entry.RECOVERY_SERVER === 'string' &&
        isUrl(entry.RECOVERY_SERVER)
      ) {
        servers.push(entry.RECOVERY_SERVER.replace(/\/+$/, ''));
      }
    }
  }

  return [...new Set(servers)];
}

/**
 * Coordinates automated recovery signing across declared RECOVERY_SERVER endpoints
 * and verifies threshold compliance of combined cryptographic Ed25519 signatures.
 */
export async function coordinateSep30Recovery(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep30CoordinatorOptions = {},
): Promise<Diagnostic[]> {
  const servers =
    options.servers && options.servers.length > 0
      ? options.servers.map((s) => s.replace(/\/+$/, ''))
      : extractRecoveryServers(doc);

  if (servers.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  const timeoutMs = options.timeoutMs ?? 10_000;
  const passphrase =
    options.networkPassphrase ??
    (isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : Networks.PUBLIC);

  // 1. Prepare test account and transaction envelope with low-threshold operation (bumpSequence)
  const testKeypair = Keypair.random();
  const accountAddress = options.targetAccount ?? testKeypair.publicKey();
  const sourceAccount = new Account(accountAddress, '0');

  const testTx = new TransactionBuilder(sourceAccount, {
    fee: '100',
    networkPassphrase: passphrase,
  })
    .addOperation(
      Operation.bumpSequence({
        bumpTo: '1',
      }),
    )
    .setTimeout(300)
    .build();

  const txHash = testTx.hash();
  const txXdr = testTx.toXDR();

  // Known / registered signers and weights
  const serverSigners = new Map<string, { signerKey?: string; weight: number }>();
  let reportedThreshold: number | undefined;

  // 2. Register test recovery identity on recovery servers
  for (const server of servers) {
    const regUrl = `${server}/accounts/${accountAddress}`;
    const payload = {
      identities: [
        {
          role: 'owner',
          auth_methods: [{ type: 'email', value: 'recovery-coordinator@example.com' }],
        },
      ],
    };

    let regResponse: Response | undefined;
    try {
      regResponse = await fetchImpl(regUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined,
      });
    } catch (err) {
      if (isTimeoutError(err)) {
        const sev = severityFor(SIGNATURE_COORDINATION_TIMEOUT_RULE, 'warning', options.rules);
        if (sev) {
          diagnostics.push({
            rule: SIGNATURE_COORDINATION_TIMEOUT_RULE,
            severity: sev,
            category: 'network',
            message: `Recovery server registration timed out at ${server}`,
            path: 'RECOVERY_SERVER',
            helpUri: SEP30_SPEC,
            suggestion: 'Ensure RECOVERY_SERVER responds within the coordination timeout window.',
          });
        }
      }
      continue;
    }

    if (isTimeoutError(null, regResponse.status)) {
      const sev = severityFor(SIGNATURE_COORDINATION_TIMEOUT_RULE, 'warning', options.rules);
      if (sev) {
        diagnostics.push({
          rule: SIGNATURE_COORDINATION_TIMEOUT_RULE,
          severity: sev,
          category: 'network',
          message: `Recovery server registration timed out at ${server} (HTTP ${regResponse.status})`,
          path: 'RECOVERY_SERVER',
          helpUri: SEP30_SPEC,
          suggestion: 'Ensure RECOVERY_SERVER is responsive and does not time out.',
        });
      }
      continue;
    }

    let signerKey: string | undefined;
    let weight = 1;

    try {
      const data = await regResponse.json();
      if (isRecord(data)) {
        if (typeof data.signer === 'string' && StrKey.isValidEd25519PublicKey(data.signer)) {
          signerKey = data.signer;
        } else if (Array.isArray(data.signers)) {
          for (const s of data.signers) {
            if (typeof s === 'string' && StrKey.isValidEd25519PublicKey(s)) {
              signerKey = s;
              break;
            } else if (
              isRecord(s) &&
              typeof s.key === 'string' &&
              StrKey.isValidEd25519PublicKey(s.key)
            ) {
              signerKey = s.key;
              if (typeof s.weight === 'number') weight = s.weight;
              break;
            }
          }
        }
        if (typeof data.weight === 'number') weight = data.weight;
        if (typeof data.threshold === 'number') reportedThreshold = data.threshold;
        if (isRecord(data.thresholds) && typeof data.thresholds.low_threshold === 'number') {
          reportedThreshold = data.thresholds.low_threshold;
        }
      }
    } catch {
      // Non-JSON or registration failure
    }

    serverSigners.set(server, { signerKey, weight });
  }

  // 3. Dispatch signing requests to recovery servers
  const verifiedSigners = new Map<string, number>();

  for (const server of servers) {
    const signerInfo = serverSigners.get(server);
    const signUrl = signerInfo?.signerKey
      ? `${server}/accounts/${accountAddress}/sign/${signerInfo.signerKey}`
      : `${server}/accounts/${accountAddress}/sign`;

    let signRes: Response | undefined;
    try {
      signRes = await fetchImpl(signUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transaction: txXdr }),
        signal: AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined,
      });
    } catch (err) {
      if (isTimeoutError(err)) {
        const sev = severityFor(SIGNATURE_COORDINATION_TIMEOUT_RULE, 'warning', options.rules);
        if (sev) {
          diagnostics.push({
            rule: SIGNATURE_COORDINATION_TIMEOUT_RULE,
            severity: sev,
            category: 'network',
            message: `Recovery server signing coordination timed out for ${server}`,
            path: 'RECOVERY_SERVER',
            helpUri: SEP30_SPEC,
            suggestion: 'Ensure RECOVERY_SERVER responds within the coordination timeout window.',
          });
        }
      }
      continue;
    }

    if (isTimeoutError(null, signRes.status)) {
      const sev = severityFor(SIGNATURE_COORDINATION_TIMEOUT_RULE, 'warning', options.rules);
      if (sev) {
        diagnostics.push({
          rule: SIGNATURE_COORDINATION_TIMEOUT_RULE,
          severity: sev,
          category: 'network',
          message: `Recovery server signing coordination timed out for ${server} (HTTP ${signRes.status})`,
          path: 'RECOVERY_SERVER',
          helpUri: SEP30_SPEC,
          suggestion: 'Ensure RECOVERY_SERVER does not time out during transaction signing.',
        });
      }
      continue;
    }

    if (!signRes.ok) continue;

    // 4. Verify Ed25519 cryptographic signatures on returned envelope
    try {
      const body = await signRes.json();
      if (!isRecord(body)) continue;

      if (typeof body.transaction === 'string') {
        const returnedTx = TransactionBuilder.fromXDR(body.transaction, passphrase);
        for (const sig of returnedTx.signatures) {
          // Verify signature against candidate signer public keys
          const candidateKeys = new Set<string>();
          if (signerInfo?.signerKey) candidateKeys.add(signerInfo.signerKey);
          for (const s of serverSigners.values()) {
            if (s.signerKey) candidateKeys.add(s.signerKey);
          }
          if (options.signerWeights) {
            for (const k of Object.keys(options.signerWeights)) candidateKeys.add(k);
          }

          for (const pubKey of candidateKeys) {
            try {
              const kp = Keypair.fromPublicKey(pubKey);
              if (kp.signatureHint().equals(sig.hint())) {
                if (kp.verify(txHash, sig.signature())) {
                  const weight = options.signerWeights?.[pubKey] ?? signerInfo?.weight ?? 1;
                  verifiedSigners.set(pubKey, weight);
                }
              }
            } catch {
              // Not a match for this key
            }
          }
        }
      } else if (typeof body.signature === 'string' && signerInfo?.signerKey) {
        try {
          const sigBuffer = Buffer.from(body.signature, 'base64');
          const kp = Keypair.fromPublicKey(signerInfo.signerKey);
          if (kp.verify(txHash, sigBuffer)) {
            const weight = options.signerWeights?.[signerInfo.signerKey] ?? signerInfo.weight ?? 1;
            verifiedSigners.set(signerInfo.signerKey, weight);
          }
        } catch {
          // Invalid signature
        }
      }
    } catch {
      // Unparseable response
    }
  }

  // 5. Determine on-chain account threshold (or configured/reported threshold)
  let requiredThreshold = options.requiredThreshold ?? reportedThreshold;

  // If targetAccount was provided and exists on Horizon, attempt to read account thresholds
  if (requiredThreshold === undefined && options.targetAccount) {
    try {
      const horizonUrl = horizonUrlFor(passphrase);
      const accRes = await fetchImpl(`${horizonUrl}/accounts/${options.targetAccount}`);
      if (accRes.ok) {
        const accData = await accRes.json();
        if (
          isRecord(accData) &&
          isRecord(accData.thresholds) &&
          typeof accData.thresholds.low_threshold === 'number'
        ) {
          requiredThreshold = accData.thresholds.low_threshold;
        }
      }
    } catch {
      // Non-blocking fallback
    }
  }

  // Default threshold: for multiple recovery servers, requires all servers or default 2
  if (requiredThreshold === undefined) {
    requiredThreshold = servers.length > 1 ? servers.length : 1;
  }

  // 6. Assert combined signatures satisfy account threshold
  let totalWeight = 0;
  for (const weight of verifiedSigners.values()) {
    totalWeight += weight;
  }

  if (totalWeight < requiredThreshold) {
    const sev = severityFor(INSUFFICIENT_RECOVERY_SIGNATURES_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INSUFFICIENT_RECOVERY_SIGNATURES_RULE,
        severity: sev,
        category: 'network',
        message: `Combined recovery signatures weight (${totalWeight}) is below the required account threshold (${requiredThreshold})`,
        path: 'RECOVERY_SERVER',
        helpUri: SEP30_SPEC,
        suggestion:
          'Ensure all declared recovery servers return valid Ed25519 signatures that satisfy the account threshold.',
      });
    }
  }

  return diagnostics;
}

/** Registered rules for SEP-30 recovery coordinator */
export const sep30CoordinatorRules: Rule[] = [
  {
    id: INSUFFICIENT_RECOVERY_SIGNATURES_RULE,
    category: 'network',
    severity: 'error',
    description: 'Combined recovery signatures must satisfy the account threshold',
    run() {},
  },
  {
    id: SIGNATURE_COORDINATION_TIMEOUT_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Recovery server signing coordination must complete without timing out',
    run() {},
  },
];

export const sep30CoordinatorRuleIds: readonly string[] = sep30CoordinatorRules.map((r) => r.id);
