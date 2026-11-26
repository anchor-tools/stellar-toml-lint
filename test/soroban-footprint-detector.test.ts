import { describe, expect, it } from 'vitest';
import {
  SHARED_WRITE_KEY_RULE,
  UNNECESSARY_WRITE_LOCK_RULE,
  detectFootprintCollisions,
  footprintDetectorRules,
} from '../src/soroban/footprintDetector.js';
import type { TransactionTemplate } from '../src/soroban/footprintDetector.js';

const BALANCE_KEY = 'balance:GCUSTOMER';
const COUNTER_KEY = 'counter:global';
const ADMIN_KEY = 'admin:config';

function makeTemplate(
  name: string,
  keys: Array<{ id: string; writable: boolean }>,
): TransactionTemplate {
  return { name, footprint: keys };
}

describe('detectFootprintCollisions', () => {
  it('returns ok with no contentions when all templates use disjoint keys', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('transfer-A', [{ id: 'balance:GA', writable: true }]),
      makeTemplate('transfer-B', [{ id: 'balance:GB', writable: true }]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.ok).toBe(true);
    expect(report.contentions).toHaveLength(0);
    expect(report.diagnostics).toHaveLength(0);
  });

  it('detects a shared write key contention between two templates', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('mint', [{ id: COUNTER_KEY, writable: true }]),
      makeTemplate('burn', [{ id: COUNTER_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.ok).toBe(false);
    expect(report.contentions).toHaveLength(1);
    expect(report.contentions[0]?.keyId).toBe(COUNTER_KEY);
    expect(report.contentions[0]?.writingTemplates).toContain('mint');
    expect(report.contentions[0]?.writingTemplates).toContain('burn');
  });

  it('reports a diagnostic with rule id for each contention', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('op1', [{ id: BALANCE_KEY, writable: true }]),
      makeTemplate('op2', [{ id: BALANCE_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates);
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(SHARED_WRITE_KEY_RULE);
  });

  it('detects a read-write conflict when one template reads and another writes', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('writer', [{ id: ADMIN_KEY, writable: true }]),
      makeTemplate('reader', [{ id: ADMIN_KEY, writable: false }]),
      makeTemplate('writer2', [{ id: ADMIN_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.contentions).toHaveLength(1);
    expect(report.contentions[0]?.hasReadWriteConflict).toBe(true);
    expect(report.contentions[0]?.readOnlyTemplates).toContain('reader');
  });

  it('provides sharding recommendations for balance keys', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('payment1', [{ id: BALANCE_KEY, writable: true }]),
      makeTemplate('payment2', [{ id: BALANCE_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.shardingRecommendations.length).toBeGreaterThan(0);
    expect(report.shardingRecommendations[0]).toContain(BALANCE_KEY);
  });

  it('provides sharding recommendations for counter keys', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('op1', [{ id: COUNTER_KEY, writable: true }]),
      makeTemplate('op2', [{ id: COUNTER_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.shardingRecommendations[0]).toContain('counter');
  });

  it('detects multiple contended keys across a large template set', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('a', [
        { id: BALANCE_KEY, writable: true },
        { id: COUNTER_KEY, writable: true },
      ]),
      makeTemplate('b', [
        { id: BALANCE_KEY, writable: true },
        { id: COUNTER_KEY, writable: true },
      ]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.contentions).toHaveLength(2);
    expect(report.ok).toBe(false);
  });

  it('suppresses diagnostics for a rule turned off', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('op1', [{ id: COUNTER_KEY, writable: true }]),
      makeTemplate('op2', [{ id: COUNTER_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates, {
      rules: { [SHARED_WRITE_KEY_RULE]: 'off' },
    });
    expect(report.diagnostics.filter((d) => d.rule === SHARED_WRITE_KEY_RULE)).toHaveLength(0);
  });

  it('escalates to error when rule is overridden', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('op1', [{ id: COUNTER_KEY, writable: true }]),
      makeTemplate('op2', [{ id: COUNTER_KEY, writable: true }]),
    ];
    const report = detectFootprintCollisions(templates, {
      rules: { [SHARED_WRITE_KEY_RULE]: 'error' },
    });
    expect(report.diagnostics[0]?.severity).toBe('error');
  });

  it('detects unnecessary write locks', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('needless-writer', [{ id: ADMIN_KEY, writable: true }]),
      makeTemplate('reader1', [{ id: ADMIN_KEY, writable: false }]),
      makeTemplate('reader2', [{ id: ADMIN_KEY, writable: false }]),
    ];
    const report = detectFootprintCollisions(templates);
    expect(report.unnecessaryWriteLocks).toHaveLength(1);
    expect(report.unnecessaryWriteLocks[0]?.template).toBe('needless-writer');
    expect(report.unnecessaryWriteLocks[0]?.keyId).toBe(ADMIN_KEY);
  });

  it('emits UNNECESSARY_WRITE_LOCK_RULE diagnostics for unnecessary write locks', () => {
    const templates: TransactionTemplate[] = [
      makeTemplate('needless-writer', [{ id: ADMIN_KEY, writable: true }]),
      makeTemplate('reader', [{ id: ADMIN_KEY, writable: false }]),
    ];
    const report = detectFootprintCollisions(templates);
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(UNNECESSARY_WRITE_LOCK_RULE);
  });

  it('handles an empty template list', () => {
    const report = detectFootprintCollisions([]);
    expect(report.ok).toBe(true);
    expect(report.contentions).toHaveLength(0);
    expect(report.diagnostics).toHaveLength(0);
  });

  it('handles a template with an empty footprint', () => {
    const report = detectFootprintCollisions([makeTemplate('empty', [])]);
    expect(report.ok).toBe(true);
  });

  it('exports the registered rule definitions', () => {
    const ids = footprintDetectorRules.map((r) => r.id);
    expect(ids).toContain(SHARED_WRITE_KEY_RULE);
    expect(ids).toContain(UNNECESSARY_WRITE_LOCK_RULE);
  });
});
