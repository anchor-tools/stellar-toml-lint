import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../../src/lint.js';
import { formatSonar } from '../../src/reporters.js';
import type { Diagnostic, LintResult, RuleCategory } from '../../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const CLEAN = readFileSync(join(here, '..', 'fixtures', 'valid.toml'), 'utf8');
const BROKEN = 'VERSION="two"\nSIGNING_KEY="nope"\n';

type SonarIssue = {
  engineId: string;
  ruleId: string;
  type: string;
  severity: string;
  primaryLocation: {
    filePath: string;
    message: string;
    textRange: {
      startLine: number;
      startColumn: number;
      endLine: number;
      endColumn: number;
    };
  };
};

const VALID_TYPES = ['BUG', 'VULNERABILITY', 'CODE_SMELL', 'SECURITY_HOTSPOT'] as const;
const VALID_SEVERITIES = ['INFO', 'MINOR', 'MAJOR', 'CRITICAL', 'BLOCKER'] as const;

function parseSonar(result: LintResult, filename?: string): SonarIssue[] {
  const parsed = JSON.parse(formatSonar(result, filename)) as { issues: unknown[] };
  expect(Array.isArray(parsed.issues)).toBe(true);
  return parsed.issues as SonarIssue[];
}

function assertIssueShape(issue: SonarIssue): void {
  expect(issue.engineId).toBe('stellar-toml-lint');
  expect(typeof issue.ruleId).toBe('string');
  expect(issue.ruleId.length).toBeGreaterThan(0);
  expect(VALID_TYPES).toContain(issue.type);
  expect(VALID_SEVERITIES).toContain(issue.severity);
  expect(typeof issue.primaryLocation.filePath).toBe('string');
  expect(typeof issue.primaryLocation.message).toBe('string');
  const range = issue.primaryLocation.textRange;
  for (const key of ['startLine', 'startColumn', 'endLine', 'endColumn'] as const) {
    const value = range[key];
    expect(Number.isInteger(value)).toBe(true);
    expect(value).toBeGreaterThanOrEqual(1);
  }
  expect(range.endLine).toBeGreaterThanOrEqual(range.startLine);
  expect(range.endColumn).toBeGreaterThanOrEqual(range.startColumn);
}

function diagnostic(overrides: Partial<Diagnostic> = {}): Diagnostic {
  return {
    rule: 'currencies/issuer-or-contract',
    severity: 'warning',
    category: 'currencies',
    message: 'Something is off.',
    ...overrides,
  };
}

describe('formatSonar', () => {
  it('emits the SonarQube Generic Issue Data shape', () => {
    const issues = parseSonar(lint(BROKEN));
    expect(issues.length).toBeGreaterThan(0);
    for (const issue of issues) assertIssueShape(issue);
  });

  it('names the stellar-toml-lint engine', () => {
    for (const issue of parseSonar(lint(BROKEN))) {
      expect(issue.engineId).toBe('stellar-toml-lint');
    }
  });

  it('maps security rules to VULNERABILITY', () => {
    const result: LintResult = {
      diagnostics: [
        diagnostic({
          rule: 'security/on-chain-toml-hash-mismatch',
          category: 'security' as RuleCategory,
          severity: 'error',
        }),
      ],
      ok: false,
      counts: { error: 1, warning: 0, info: 0 },
    };
    const [issue] = parseSonar(result);
    expect(issue).toBeDefined();
    expect(issue!.type).toBe('VULNERABILITY');
  });

  it('maps security rule ids to VULNERABILITY regardless of category', () => {
    const result: LintResult = {
      diagnostics: [
        diagnostic({
          rule: 'security/revoked-signing-key',
          category: 'network',
          severity: 'warning',
        }),
      ],
      ok: true,
      counts: { error: 0, warning: 1, info: 0 },
    };
    const [issue] = parseSonar(result);
    expect(issue).toBeDefined();
    expect(issue!.type).toBe('VULNERABILITY');
  });

  it('maps file and schema errors to BUG', () => {
    const result: LintResult = {
      diagnostics: [diagnostic({ rule: 'file/encoding', category: 'file', severity: 'error' })],
      ok: false,
      counts: { error: 1, warning: 0, info: 0 },
    };
    const [issue] = parseSonar(result);
    expect(issue).toBeDefined();
    expect(issue!.type).toBe('BUG');
  });

  it('maps everything else to CODE_SMELL', () => {
    const result: LintResult = {
      diagnostics: [diagnostic()],
      ok: true,
      counts: { error: 0, warning: 1, info: 0 },
    };
    const [issue] = parseSonar(result);
    expect(issue).toBeDefined();
    expect(issue!.type).toBe('CODE_SMELL');
  });

  it('maps error to BLOCKER, warning to MAJOR, and info to MINOR', () => {
    const bySeverity: Record<string, string> = {};
    for (const severity of ['error', 'warning', 'info'] as const) {
      const result: LintResult = {
        diagnostics: [diagnostic({ severity })],
        ok: severity === 'error',
        counts: { error: 0, warning: 0, info: 0 },
      };
      const [issue] = parseSonar(result);
      expect(issue).toBeDefined();
      bySeverity[severity] = issue!.severity;
    }
    expect(bySeverity.error).toBe('BLOCKER');
    expect(bySeverity.warning).toBe('MAJOR');
    expect(bySeverity.info).toBe('MINOR');
  });

  it('uses the given filename as filePath', () => {
    const result: LintResult = {
      diagnostics: [diagnostic()],
      ok: true,
      counts: { error: 0, warning: 1, info: 0 },
    };
    const [issue] = parseSonar(result, 'accounts/acme/stellar.toml');
    expect(issue).toBeDefined();
    expect(issue!.primaryLocation.filePath).toBe('accounts/acme/stellar.toml');
  });

  it('defaults filePath to stellar.toml', () => {
    const [issue] = parseSonar(lint(BROKEN));
    expect(issue).toBeDefined();
    expect(issue!.primaryLocation.filePath).toBe('stellar.toml');
  });

  it('reports the diagnostic position, and 1:1 when there is none', () => {
    const positioned: LintResult = {
      diagnostics: [diagnostic({ position: { line: 12, column: 3 } })],
      ok: false,
      counts: { error: 1, warning: 0, info: 0 },
    };
    const missing: LintResult = {
      diagnostics: [diagnostic()],
      ok: true,
      counts: { error: 0, warning: 1, info: 0 },
    };
    const [at] = parseSonar(positioned);
    expect(at).toBeDefined();
    expect(at!.primaryLocation.textRange).toEqual({
      startLine: 12,
      startColumn: 3,
      endLine: 12,
      endColumn: 3,
    });
    const [nowhere] = parseSonar(missing);
    expect(nowhere).toBeDefined();
    expect(nowhere!.primaryLocation.textRange).toEqual({
      startLine: 1,
      startColumn: 1,
      endLine: 1,
      endColumn: 1,
    });
  });

  it('produces an empty issues list for a clean file', () => {
    const issues = parseSonar(lint(CLEAN));
    expect(issues).toEqual([]);
  });

  it('round-trips through JSON.parse on real diagnostics', () => {
    const report = JSON.parse(formatSonar(lint(BROKEN), 'stellar.toml'));
    expect(report.issues).toHaveLength(lint(BROKEN).diagnostics.length);
    for (const issue of report.issues) {
      assertIssueShape(issue as SonarIssue);
      expect(lint(BROKEN).diagnostics.some((d) => d.rule === issue.ruleId)).toBe(true);
    }
  });
});
