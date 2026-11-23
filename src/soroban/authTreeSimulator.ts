/**
 * XDR-driven Soroban authorization-tree simulator.
 *
 * `auth-tree-simulator.ts` audits the authorization recorded for a stellar.toml
 * document. This module answers the reviewer's question instead: given one
 * signed or simulated transaction envelope, what authorization hierarchy does
 * it carry, and does every credential bind that hierarchy to its signer?
 *
 * It parses the envelope and every `InvokeHostFunction` operation's
 * `SorobanAuthorizationEntry` list, checks the credential address, nonce,
 * signature and expiration, reuses the cross-contract scope checks from the
 * SEP-42 analyzer, and renders the call tree as ASCII/Unicode.
 */

import { Address, xdr } from '@stellar/stellar-base';
import type { Rule } from '../types.js';
import {
  analyzeAuthTree,
  authTreeSimulatorRules,
  canonicalIdentity,
  parseAuthEntry,
  type AuthTreeEntry,
  type AuthTreeFinding,
  type AuthTreeNode,
} from './auth-tree-simulator.js';

export const AUTH_CREDENTIAL_UNBOUND_RULE = 'soroban/auth-entry-credential-unbound';
export const AUTH_NONCE_REUSED_RULE = 'soroban/auth-entry-nonce-reused';
export const AUTH_SIGNATURE_MISSING_RULE = 'soroban/auth-entry-signature-missing';
export const AUTH_SIGNATURE_EXPIRED_RULE = 'soroban/auth-entry-signature-expired';
export const AUTH_EXPIRATION_UNBOUNDED_RULE = 'soroban/auth-entry-expiration-unbounded';

/** Roughly one day of ledgers: signatures valid longer than this need review. */
export const DEFAULT_MAX_AUTH_LIFETIME_LEDGERS = 17_280;

/** One `InvokeHostFunction` operation extracted from the envelope. */
export interface AuthTreeOperation {
  index: number;
  contract?: string;
  function?: string;
  /** Base64 XDR of each authorization entry the operation carries. */
  auth: string[];
}

export interface AuthTreeEnvelope {
  operations: AuthTreeOperation[];
  entries: AuthTreeEntry[];
}

export interface AuthTreeSimulatorOptions {
  /** Network passphrase the envelope was built for. Echoed in the report. */
  networkPassphrase?: string;
  /** Soroban RPC endpoint used to record missing authorizations. */
  rpcUrl?: string;
  /** Current ledger, when the caller already knows it. */
  latestLedger?: number;
  /** Signatures valid longer than this many ledgers are flagged. */
  maxAuthLifetimeLedgers?: number;
  /** Addresses the anchor controls and may authorize the root invocation. */
  authorizedIdentities?: readonly string[];
  /** Contracts the tree may delegate into, in addition to the invoked ones. */
  allowedContracts?: readonly string[];
  /** Account that signed the envelope. */
  sourceAccount?: string;
  /** Fetch implementation, injectable for tests. */
  fetchImpl?: typeof fetch;
}

export interface AuthTreeSimulationReport {
  valid: boolean;
  error?: string;
  networkPassphrase?: string;
  latestLedger?: number;
  operations: AuthTreeOperation[];
  entries: AuthTreeEntry[];
  findings: AuthTreeFinding[];
  /** ASCII/Unicode rendering of the call tree. */
  diagram: string;
  /** True when no finding is an error. */
  ok: boolean;
}

/** Reads the authorization hierarchy out of a transaction envelope. */
export class AuthTreeSimulator {
  constructor(private readonly options: AuthTreeSimulatorOptions = {}) {}

  /** Parses the envelope's invoke operations and their auth entries. */
  parseEnvelope(envelopeXdr: string): AuthTreeEnvelope | undefined {
    let envelope: xdr.TransactionEnvelope;
    try {
      envelope = xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64');
    } catch {
      return undefined;
    }
    const transaction = transactionOf(envelope);
    if (transaction === undefined) return undefined;

    const operations: AuthTreeOperation[] = [];
    const entries: AuthTreeEntry[] = [];
    for (const [index, operation] of transaction.operations().entries()) {
      if (operation.body().switch().name !== 'invokeHostFunction') continue;
      const invoke = operation.body().invokeHostFunctionOp();
      const hostFunction = invoke.hostFunction();
      const contractFunction =
        hostFunction.switch().name === 'hostFunctionTypeInvokeContract'
          ? hostFunction.invokeContract()
          : undefined;
      const auth = invoke.auth().map((entry) => entry.toXDR('base64'));
      operations.push({
        index,
        ...(contractFunction !== undefined
          ? { contract: scAddress(contractFunction.contractAddress()) }
          : {}),
        ...(contractFunction !== undefined
          ? { function: contractFunction.functionName().toString() }
          : {}),
        auth,
      });
      for (const entry of invoke.auth()) {
        try {
          entries.push(parseAuthEntry(entry));
        } catch {
          // An entry that cannot be read is reported by the credential checks.
        }
      }
    }

    return { operations, entries };
  }

  /** Checks credential binding and expiration on parsed entries. */
  auditCredentials(entries: readonly AuthTreeEntry[], latestLedger?: number): AuthTreeFinding[] {
    const findings: AuthTreeFinding[] = [];
    const maxLifetime = this.options.maxAuthLifetimeLedgers ?? DEFAULT_MAX_AUTH_LIFETIME_LEDGERS;

    for (const entry of entries) {
      if (entry.sourceAccount) continue;
      const label = entry.credentialAddress ?? 'the unnamed credential';

      if (entry.credentialAddress === undefined) {
        findings.push({
          rule: AUTH_CREDENTIAL_UNBOUND_RULE,
          severity: 'error',
          message:
            'An authorization entry uses address credentials that name no readable address, so no signer can be bound to the invocation',
          suggestion:
            'Use a valid account or contract address in the entry credentials and rebuild the transaction.',
        });
      }

      if (entry.credentialNonce === '0') {
        findings.push({
          rule: AUTH_NONCE_REUSED_RULE,
          severity: 'error',
          message: `The authorization for ${label} uses nonce 0, which is reused across otherwise identical signings and allows a captured entry to be replayed`,
          suggestion:
            'Use a fresh random or monotonically increasing nonce for every authorization entry.',
        });
      }

      if (entry.hasSignature !== true) {
        findings.push({
          rule: AUTH_SIGNATURE_MISSING_RULE,
          severity: 'warning',
          message: `The authorization for ${label} carries no signature, so the envelope has not been authorized yet`,
          suggestion:
            'Sign the entry with the credential address (or simulate with authMode=record and sign the returned entries).',
        });
      }

      const expiration = entry.signatureExpirationLedger;
      if (expiration !== undefined && latestLedger !== undefined) {
        if (expiration <= latestLedger) {
          findings.push({
            rule: AUTH_SIGNATURE_EXPIRED_RULE,
            severity: 'error',
            message: `The authorization for ${label} expired at ledger ${expiration}; the current ledger is ${latestLedger}`,
            suggestion:
              'Re-sign the authorization with a fresh expiration ledger before submitting.',
          });
        } else if (expiration > latestLedger + maxLifetime) {
          findings.push({
            rule: AUTH_EXPIRATION_UNBOUNDED_RULE,
            severity: 'warning',
            message: `The authorization for ${label} stays valid until ledger ${expiration}, more than ${maxLifetime} ledgers from the current ledger (${latestLedger})`,
            suggestion:
              'Keep signature expiration short (minutes, not days) so a leaked entry has a narrow replay window.',
          });
        }
      }
    }

    return findings;
  }

  /** Audits scope and credentials, then renders the tree. */
  async simulate(envelopeXdr: string): Promise<AuthTreeSimulationReport> {
    const parsed = this.parseEnvelope(envelopeXdr);
    const base = {
      ...(this.options.networkPassphrase !== undefined
        ? { networkPassphrase: this.options.networkPassphrase }
        : {}),
      ...(this.options.latestLedger !== undefined
        ? { latestLedger: this.options.latestLedger }
        : {}),
    };
    if (parsed === undefined) {
      return {
        ...base,
        valid: false,
        error:
          'The value is not a base64 TransactionEnvelope, or it carries no v0/v1/fee-bump transaction.',
        operations: [],
        entries: [],
        findings: [],
        diagram: '',
        ok: false,
      };
    }

    let entries = parsed.entries;
    let latestLedger = this.options.latestLedger;
    let recorded: { entries: AuthTreeEntry[]; latestLedger?: number } | undefined;
    if (entries.length === 0 && this.options.rpcUrl !== undefined) {
      recorded = await this.recordAuthorizations(envelopeXdr);
      if (recorded !== undefined) {
        entries = recorded.entries;
        latestLedger ??= recorded.latestLedger;
      }
    }
    if (latestLedger === undefined && this.options.rpcUrl !== undefined) {
      latestLedger = await this.fetchLatestLedger();
    }

    const invokedContracts = parsed.operations
      .map((operation) => operation.contract)
      .filter((contract): contract is string => contract !== undefined);
    const allowedContracts = [
      ...new Set([
        ...invokedContracts,
        ...(this.options.allowedContracts ?? []).map((value) => canonicalIdentity(value) ?? value),
      ]),
    ];

    // An envelope has no trust anchor by itself: without an explicit
    // `--signing-key`, the credential and boundary addresses are the only
    // identities we can compare against, so identity checks stay silent while
    // cross-contract scope checks still run.
    const authorizedIdentities =
      (this.options.authorizedIdentities ?? []).length > 0
        ? [...(this.options.authorizedIdentities ?? [])]
        : entries.flatMap((entry) => [
            ...(entry.credentialAddress !== undefined ? [entry.credentialAddress] : []),
            ...entry.requiredAddresses,
          ]);

    const scopeFindings = analyzeAuthTree(entries, {
      authorizedIdentities,
      allowedContracts,
      approvedContracts: this.options.allowedContracts ?? [],
      ...(this.options.sourceAccount !== undefined
        ? { sourceAccount: this.options.sourceAccount }
        : {}),
    });
    const findings = [...scopeFindings, ...this.auditCredentials(entries, latestLedger)];

    return {
      ...base,
      ...(latestLedger !== undefined ? { latestLedger } : {}),
      valid: true,
      operations: parsed.operations,
      entries,
      findings,
      diagram: renderAuthTreeDiagram(entries),
      ok: !findings.some((finding) => finding.severity === 'error'),
    };
  }

  private async recordAuthorizations(
    envelopeXdr: string,
  ): Promise<{ entries: AuthTreeEntry[]; latestLedger?: number } | undefined> {
    const fetchImpl = this.options.fetchImpl ?? globalThis.fetch;
    if (fetchImpl === undefined) return undefined;
    try {
      const response = await fetchImpl(this.options.rpcUrl as string, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'simulateTransaction',
          params: { transaction: envelopeXdr, authMode: 'record' },
        }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) return undefined;
      const body = (await response.json()) as {
        result?: { latestLedger?: number; auth?: unknown; results?: { auth?: unknown }[] };
      };
      const result = body.result;
      if (result === undefined) return undefined;
      const raw = result.results?.[0]?.auth ?? result.auth;
      if (!Array.isArray(raw)) return undefined;
      const entries: AuthTreeEntry[] = [];
      for (const item of raw) {
        if (typeof item !== 'string') continue;
        try {
          entries.push(parseAuthEntry(xdr.SorobanAuthorizationEntry.fromXDR(item, 'base64')));
        } catch {
          // Skip an entry the RPC returned undecodable.
        }
      }
      return {
        entries,
        ...(typeof result.latestLedger === 'number' ? { latestLedger: result.latestLedger } : {}),
      };
    } catch {
      return undefined;
    }
  }

  private async fetchLatestLedger(): Promise<number | undefined> {
    const fetchImpl = this.options.fetchImpl ?? globalThis.fetch;
    if (fetchImpl === undefined) return undefined;
    try {
      const response = await fetchImpl(this.options.rpcUrl as string, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getLatestLedger', params: {} }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) return undefined;
      const body = (await response.json()) as { result?: { sequence?: number } };
      return typeof body.result?.sequence === 'number' ? body.result.sequence : undefined;
    } catch {
      return undefined;
    }
  }
}

/** Renders parsed authorization entries as an ASCII/Unicode tree. */
export function renderAuthTreeDiagram(entries: readonly AuthTreeEntry[]): string {
  if (entries.length === 0) return '(no authorization entries)\n';
  const lines: string[] = [];
  entries.forEach((entry, index) => {
    const lastEntry = index === entries.length - 1;
    const marker = lastEntry ? '└─' : '├─';
    const continuation = lastEntry ? '   ' : '│  ';
    lines.push(`${marker} ${entryLabel(entry)}`);
    renderNode(entry.root, continuation, lines);
  });
  return `${lines.join('\n')}\n`;
}

/** Renders a full simulator report for the CLI. */
export function renderAuthTreeReport(report: AuthTreeSimulationReport): string {
  const lines: string[] = [];
  lines.push(
    `Auth tree: ${report.valid ? `${report.entries.length} entr${report.entries.length === 1 ? 'y' : 'ies'}` : 'INVALID'}`,
  );
  if (report.networkPassphrase !== undefined) {
    lines.push(`  Network: ${report.networkPassphrase}`);
  }
  if (report.latestLedger !== undefined) {
    lines.push(`  Latest ledger: ${report.latestLedger}`);
  }
  if (report.error !== undefined) lines.push(`  Error: ${report.error}`);
  for (const operation of report.operations) {
    const target =
      operation.contract === undefined
        ? 'host function'
        : `${operation.contract}::${operation.function ?? '?'}`;
    lines.push(
      `  Operation ${operation.index}: ${target} (${operation.auth.length} auth entr${operation.auth.length === 1 ? 'y' : 'ies'})`,
    );
  }
  if (report.valid) {
    lines.push('  Tree:');
    for (const line of report.diagram.trimEnd().split('\n')) lines.push(`    ${line}`);
  }

  if (report.findings.length === 0) {
    lines.push('  No authorization problems found.');
    return `${lines.join('\n')}\n`;
  }
  lines.push(`  Findings (${report.findings.length}):`);
  for (const finding of report.findings) {
    lines.push(`    ${finding.severity.toUpperCase()} ${finding.rule}`);
    lines.push(`      ${finding.message}`);
    if (finding.suggestion !== undefined) lines.push(`      Fix: ${finding.suggestion}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Credential rules plus the existing SEP-42 scope rules. */
export const authTreeCredentialRules: Rule[] = [
  {
    id: AUTH_CREDENTIAL_UNBOUND_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban authorization entry names no readable credential address',
    run() {},
  },
  {
    id: AUTH_NONCE_REUSED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban authorization entry uses a zero nonce and can be replayed',
    run() {},
  },
  {
    id: AUTH_SIGNATURE_MISSING_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban authorization entry carries no signature',
    run() {},
  },
  {
    id: AUTH_SIGNATURE_EXPIRED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban authorization signature expired before the current ledger',
    run() {},
  },
  {
    id: AUTH_EXPIRATION_UNBOUNDED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban authorization signature stays valid for an unusually long time',
    run() {},
  },
];

/** All auth-tree rule ids, for docs and CLI validation. */
export const authTreeRules: Rule[] = [...authTreeSimulatorRules, ...authTreeCredentialRules];

/** All auth-tree rule ids, for docs and CLI validation. */
export const authTreeRuleIds: readonly string[] = authTreeRules.map((rule) => rule.id);

function transactionOf(envelope: xdr.TransactionEnvelope): xdr.Transaction | undefined {
  const kind = envelope.switch().name;
  if (kind === 'envelopeTypeTx') return envelope.v1().tx();
  if (kind === 'envelopeTypeTxV0') {
    // A v0 transaction has the same operation list but a different envelope.
    return envelope.v0().tx() as unknown as xdr.Transaction;
  }
  if (kind === 'envelopeTypeTxFeeBump') {
    const inner = envelope.feeBump().tx().innerTx();
    return inner.switch().name === 'envelopeTypeTx' ? inner.v1().tx() : undefined;
  }
  return undefined;
}

function scAddress(address: xdr.ScAddress): string {
  try {
    return Address.fromScAddress(address).toString();
  } catch {
    return '(unreadable address)';
  }
}

function entryLabel(entry: AuthTreeEntry): string {
  const root = nodeLabel(entry.root);
  if (entry.sourceAccount) return `${root} [authorized by the transaction source account]`;
  const details: string[] = [];
  if (entry.credentialAddress !== undefined) details.push(entry.credentialAddress);
  if (entry.credentialNonce !== undefined) details.push(`nonce ${entry.credentialNonce}`);
  if (entry.signatureExpirationLedger !== undefined) {
    details.push(`expires ${entry.signatureExpirationLedger}`);
  }
  details.push(entry.hasSignature ? 'signed' : 'UNSIGNED');
  return `${root} [${details.join(', ')}]`;
}

function renderNode(node: AuthTreeNode, prefix: string, lines: string[]): void {
  node.children.forEach((child, index) => {
    const last = index === node.children.length - 1;
    lines.push(`${prefix}${last ? '└─' : '├─'} ${nodeLabel(child)}`);
    renderNode(child, `${prefix}${last ? '   ' : '│  '}`, lines);
  });
}

function nodeLabel(node: AuthTreeNode): string {
  if (node.authBoundary) {
    return node.addresses.length === 0
      ? 'require_auth() [no address]'
      : `require_auth(${node.addresses.join(', ')})`;
  }
  const target = node.contract === undefined ? 'call' : node.contract;
  return node.function === undefined ? target : `${target}::${node.function}`;
}
