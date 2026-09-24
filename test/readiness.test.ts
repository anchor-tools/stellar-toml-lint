import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../src/lint.js';
import {
  calculateReadiness,
  gradeFor,
  PROTOCOL_MAX_SCORE,
  PROTOCOL_ERROR_DEDUCTION,
  READINESS_MAX_SCORE,
  type ReadinessReport,
} from '../src/readiness.js';
import { formatReadiness, formatReadinessJson } from '../src/reporters.js';

const here = dirname(fileURLToPath(import.meta.url));
/** The reference anchor fixture: fully documented and SEP-1 clean. */
const REFERENCE = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');

/** Parses, but documents almost nothing — the wallet-listing gap. */
const MINIMAL = `VERSION="2.0.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"

[DOCUMENTATION]
ORG_NAME="Minimal Anchor"
ORG_URL="https://minimal.example.com"
`;

/** Syntactically impossible, so no semantic rule can run. */
const UNPARSEABLE = 'VERSION = \n';

const DISPOSABLE_CONTACT = `VERSION="2.0.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"

[DOCUMENTATION]
ORG_NAME="Throwaway Anchor"
ORG_URL="https://throwaway.example.com"
ORG_LOGO="https://throwaway.example.com/logo.png"
ORG_OFFICIAL_EMAIL="team@mailinator.com"
`;

function checkFor(report: ReadinessReport, id: string): ReadinessReport['checklist'][number] {
  const found = report.checklist.find((check) => check.id === id);
  if (found === undefined) throw new Error(`no check with id ${id}`);
  return found;
}

describe('calculateReadiness', () => {
  it('scores a fully documented reference anchor at Grade A or better', () => {
    const report = calculateReadiness(lint(REFERENCE));
    expect(report.parseFailure).toBe(false);
    expect(report.score).toBeGreaterThan(90);
    expect(['A+', 'A']).toContain(report.grade);
  });

  it('scores a minimally documented file in the C/B band', () => {
    const report = calculateReadiness(lint(MINIMAL));
    expect(report.score).toBeGreaterThanOrEqual(60);
    expect(report.score).toBeLessThan(90);
    expect(['B', 'C']).toContain(report.grade);
  });

  it('scores a file that will not parse as Grade F with zero points', () => {
    const report = calculateReadiness(lint(UNPARSEABLE));
    expect(report.parseFailure).toBe(true);
    expect(report.score).toBe(0);
    expect(report.grade).toBe('F');
    for (const check of report.checklist) expect(check.passed).toBe(false);
  });

  it('never lets the pillar scores exceed 100 in total', () => {
    const report = calculateReadiness(lint(REFERENCE));
    const total = report.pillars.reduce((sum, pillar) => sum + pillar.maxScore, 0);
    expect(total).toBe(READINESS_MAX_SCORE);
    expect(report.score).toBe(report.pillars.reduce((sum, p) => sum + p.score, 0));
    expect(report.score).toBeLessThanOrEqual(READINESS_MAX_SCORE);
  });

  it('deducts 15 points per error from the protocol pillar', () => {
    const result = lint(REFERENCE);
    const report = calculateReadiness(result);
    const expected = Math.max(
      0,
      PROTOCOL_MAX_SCORE - result.counts.error * PROTOCOL_ERROR_DEDUCTION,
    );
    const protocol = report.pillars.find((pillar) => pillar.id === 'protocol');
    expect(protocol?.score).toBe(expected);
    expect(protocol?.maxScore).toBe(PROTOCOL_MAX_SCORE);
  });

  it('flags the documentation a wallet listing review looks for', () => {
    const report = calculateReadiness(lint(MINIMAL));
    const logo = checkFor(report, 'identity/org-logo');
    expect(logo.passed).toBe(false);
    expect(logo.detail).toBeTruthy();
    expect(logo.suggestion).toBeTruthy();

    expect(checkFor(report, 'identity/org-name').passed).toBe(true);
    expect(checkFor(report, 'identity/org-url').passed).toBe(true);
    expect(checkFor(report, 'identity/official-email').passed).toBe(false);
  });

  it('recognises a disposable official email address', () => {
    const report = calculateReadiness(lint(DISPOSABLE_CONTACT));
    const disposable = checkFor(report, 'identity/email-not-disposable');
    expect(disposable.passed).toBe(false);
    expect(disposable.detail).toContain('mailinator.com');
  });

  it('passes every transparency check on the reference anchor', () => {
    const report = calculateReadiness(lint(REFERENCE));
    for (const check of report.checklist.filter((c) => c.pillar === 'transparency')) {
      expect(check.passed).toBe(true);
    }
  });

  it('is deterministic across runs', () => {
    expect(calculateReadiness(lint(REFERENCE))).toEqual(calculateReadiness(lint(REFERENCE)));
  });
});

describe('gradeFor', () => {
  it('maps the documented bands onto letters', () => {
    expect(gradeFor(100)).toBe('A+');
    expect(gradeFor(95)).toBe('A+');
    expect(gradeFor(94)).toBe('A');
    expect(gradeFor(90)).toBe('A');
    expect(gradeFor(89)).toBe('B');
    expect(gradeFor(80)).toBe('B');
    expect(gradeFor(79)).toBe('C');
    expect(gradeFor(70)).toBe('C');
    expect(gradeFor(69)).toBe('D');
    expect(gradeFor(60)).toBe('D');
    expect(gradeFor(59)).toBe('F');
    expect(gradeFor(0)).toBe('F');
  });
});

describe('formatReadiness', () => {
  it('prints the score, grade, and checklist marks', () => {
    const report = calculateReadiness(lint(REFERENCE));
    const output = formatReadiness(report, { color: false });
    expect(output).toContain('Listing Readiness Checklist');
    expect(output).toContain(`Grade ${report.grade}`);
    expect(output).toContain('[\u2713]');
    expect(output).toContain('[\u2717]');
    // eslint-disable-next-line no-control-regex
    expect(/\u001b\[/.test(output)).toBe(false);
  });

  it('adds ANSI colour only when asked', () => {
    const output = formatReadiness(calculateReadiness(lint(REFERENCE)), { color: true });
    // eslint-disable-next-line no-control-regex
    expect(/\u001b\[/.test(output)).toBe(true);
  });
});

describe('formatReadinessJson', () => {
  it('emits a parseable report with the documented shape', () => {
    const report = calculateReadiness(lint(REFERENCE));
    const parsed = JSON.parse(formatReadinessJson(report, 'stellar.toml'));
    expect(parsed.file).toBe('stellar.toml');
    expect(parsed.score).toBe(report.score);
    expect(parsed.grade).toBe(report.grade);
    expect(parsed.maxScore).toBe(READINESS_MAX_SCORE);
    expect(parsed.pillars).toHaveLength(3);
    expect(parsed.checklist).toHaveLength(report.checklist.length);
    for (const entry of parsed.checklist) {
      expect(typeof entry.id).toBe('string');
      expect(typeof entry.label).toBe('string');
      expect(typeof entry.passed).toBe('boolean');
      expect(typeof entry.points).toBe('number');
      expect(typeof entry.maxPoints).toBe('number');
    }
  });

  it('carries the parse-failure flag through', () => {
    const parsed = JSON.parse(formatReadinessJson(calculateReadiness(lint(UNPARSEABLE))));
    expect(parsed.parseFailure).toBe(true);
    expect(parsed.score).toBe(0);
  });
});
