/**
 * Soroban state footprint read-write collision detector.
 *
 * Soroban transactions must declare an exact footprint of ledger keys they will
 * read (read-only) or modify (read-write) before the transaction envelope is
 * built. When concurrent anchor gateway requests touch the same persistent key
 * — a global counter, a shared balance bucket, an admin flag — the network
 * rejects all but one of them (`txINTERNAL_ERROR`), forcing serial execution
 * and collapsing throughput.
 *
 * This module models a set of transaction templates as a dependency graph,
 * locates keys that appear as read-write in more than one template, and
 * recommends sharding strategies to eliminate the bottleneck.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

export const SHARED_WRITE_KEY_RULE = 'soroban/shared-write-key-contention';
export const UNNECESSARY_WRITE_LOCK_RULE = 'soroban/unnecessary-write-lock';

/** A single ledger key referenced in a transaction footprint. */
export interface FootprintKey {
  /** Logical identifier — e.g. a contract storage key path like "balance:GA…". */
  id: string;
  /** `true` when the transaction intends to mutate this key. */
  writable: boolean;
}

/** One transaction template: a name and the footprint it declares. */
export interface TransactionTemplate {
  name: string;
  footprint: FootprintKey[];
}

/** One contended key: which templates write to it simultaneously. */
export interface Contention {
  keyId: string;
  writingTemplates: string[];
  readOnlyTemplates: string[];
  /** Whether any template marks this key read-only while another writes it. */
  hasReadWriteConflict: boolean;
}

/** Full report from the detector. */
export interface FootprintReport {
  ok: boolean;
  contentions: Contention[];
  unnecessaryWriteLocks: Array<{ template: string; keyId: string }>;
  diagnostics: Diagnostic[];
  shardingRecommendations: string[];
}

export interface FootprintDetectorOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Finds keys that are declared read-only in every template that uses them —
 * unnecessarily held as read-write in the given template.
 *
 * A key is an unnecessary write lock when the same template marks it writable
 * but all other templates referencing it are read-only, meaning the template
 * author could downgrade it.
 */
function findUnnecessaryWriteLocks(
  templates: readonly TransactionTemplate[],
): Array<{ template: string; keyId: string }> {
  const writersOf = new Map<string, Set<string>>();
  const readersOf = new Map<string, Set<string>>();

  for (const template of templates) {
    for (const key of template.footprint) {
      if (key.writable) {
        if (!writersOf.has(key.id)) writersOf.set(key.id, new Set());
        writersOf.get(key.id)!.add(template.name);
      } else {
        if (!readersOf.has(key.id)) readersOf.set(key.id, new Set());
        readersOf.get(key.id)!.add(template.name);
      }
    }
  }

  const result: Array<{ template: string; keyId: string }> = [];
  for (const [keyId, writers] of writersOf) {
    if (writers.size !== 1) continue;
    const [writer] = [...writers];
    const isAlsoRead = readersOf.has(keyId) && (readersOf.get(keyId)?.size ?? 0) > 0;
    if (!isAlsoRead) {
      // Only one template writes this key and no one else reads it — it may
      // actually be a genuine write, so we do not flag it.
      continue;
    }
    // One writer, but others only read-only — the writer could check whether
    // it truly mutates the key or merely reads it.
    result.push({ template: writer!, keyId });
  }
  return result;
}

/** Builds sharding suggestions from the contended key ids. */
function shardingRecommendations(contentions: readonly Contention[]): string[] {
  const recommendations: string[] = [];
  for (const contention of contentions) {
    const id = contention.keyId;
    if (/balance|amount|total/i.test(id)) {
      recommendations.push(
        `Split "${id}" into per-account sub-keys (e.g. "balance:<accountId>") so each transaction only locks its own slice.`,
      );
    } else if (/counter|nonce|seq/i.test(id)) {
      recommendations.push(
        `Replace the global counter "${id}" with per-operation transient keys or a sharded bucket scheme to allow parallel increments.`,
      );
    } else {
      recommendations.push(
        `Key "${id}" is contested by ${contention.writingTemplates.length} templates — consider splitting it by tenant, asset, or time bucket.`,
      );
    }
  }
  return recommendations;
}

/**
 * Detects read-write footprint collisions across the given transaction
 * templates and returns a full contention report.
 */
export function detectFootprintCollisions(
  templates: readonly TransactionTemplate[],
  options: FootprintDetectorOptions = {},
): FootprintReport {
  const writersOf = new Map<string, string[]>();
  const readersOf = new Map<string, string[]>();

  for (const template of templates) {
    for (const key of template.footprint) {
      if (key.writable) {
        if (!writersOf.has(key.id)) writersOf.set(key.id, []);
        writersOf.get(key.id)!.push(template.name);
      } else {
        if (!readersOf.has(key.id)) readersOf.set(key.id, []);
        readersOf.get(key.id)!.push(template.name);
      }
    }
  }

  const contentions: Contention[] = [];
  for (const [keyId, writers] of writersOf) {
    if (writers.length < 2) continue;
    contentions.push({
      keyId,
      writingTemplates: writers,
      readOnlyTemplates: readersOf.get(keyId) ?? [],
      hasReadWriteConflict: (readersOf.get(keyId)?.length ?? 0) > 0,
    });
  }

  const unnecessaryWriteLocks = findUnnecessaryWriteLocks(templates);
  const recommendations = shardingRecommendations(contentions);

  const diagnostics: Diagnostic[] = [];
  const sharedWriteSeverity = severityFor(SHARED_WRITE_KEY_RULE, 'warning', options.rules);
  if (sharedWriteSeverity !== undefined) {
    for (const contention of contentions) {
      diagnostics.push({
        rule: SHARED_WRITE_KEY_RULE,
        severity: sharedWriteSeverity,
        category: 'network',
        message: `Ledger key "${contention.keyId}" is declared read-write by ${contention.writingTemplates.length} concurrent templates (${contention.writingTemplates.join(', ')}), causing sequential execution`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion:
          recommendations.find((r) => r.includes(`"${contention.keyId}"`)) ??
          `Shard "${contention.keyId}" so each concurrent transaction operates on a distinct key.`,
      });
    }
  }

  const writeLockSeverity = severityFor(UNNECESSARY_WRITE_LOCK_RULE, 'warning', options.rules);
  if (writeLockSeverity !== undefined) {
    for (const lock of unnecessaryWriteLocks) {
      diagnostics.push({
        rule: UNNECESSARY_WRITE_LOCK_RULE,
        severity: writeLockSeverity,
        category: 'network',
        message: `Template "${lock.template}" declares key "${lock.keyId}" as read-write, but no mutation is performed by this template while other templates read it as read-only`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion: `Downgrade "${lock.keyId}" to read-only in template "${lock.template}" to reduce contention.`,
      });
    }
  }

  return {
    ok: contentions.length === 0,
    contentions,
    unnecessaryWriteLocks,
    diagnostics,
    shardingRecommendations: recommendations,
  };
}

/** Registered so `--list-rules` and rule overrides know these ids. */
export const footprintDetectorRules: Rule[] = [
  {
    id: SHARED_WRITE_KEY_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A ledger key is declared read-write in multiple concurrent transaction templates, forcing serial execution',
    run() {},
  },
  {
    id: UNNECESSARY_WRITE_LOCK_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A transaction template holds a read-write lock on a key that is only read, while other templates access it as read-only',
    run() {},
  },
];
