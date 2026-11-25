import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { formatJson } from '../src/reporters.js';
import type { Diagnostic } from '../src/types.js';
import { checkNetworkIsolation, PUBLIC_NETWORK_PASSPHRASE } from '../src/gitops/ciEnvironments.js';
import {
  CI_REPORT_SCHEMA,
  buildCiReport,
  formatCiSarif,
  isCiEnvironmentReport,
  sarifCategory,
  validateSarif,
  type CiEnvironmentReport,
} from '../src/gitops/ciSarif.js';
import {
  GITHUB_COMMENT_LIMIT,
  formatCiScorecard,
  formatEnvironmentScorecard,
  gradeFor,
  scoreReport,
} from '../src/gitops/ciScorecard.js';
import { SCORECARD_MARKER } from '../src/gitops/ciWorkflowGenerator.js';

const FILE = 'environments/staging/stellar.toml';
const SOURCE = `VERSION="2.7.0"\nNETWORK_PASSPHRASE="${PUBLIC_NETWORK_PASSPHRASE}"\nORG_NAME=1\n`;

function lintJson(source = SOURCE, file = FILE): string {
  return formatJson(lint(source), file);
}

function stagingReport(
  overrides: Partial<Parameters<typeof buildCiReport>[0]> = {},
): CiEnvironmentReport {
  return buildCiReport({
    environment: 'staging',
    file: FILE,
    node: '20',
    checkNetwork: true,
    lintExitCode: 1,
    lintJson: lintJson(),
    isolation: checkNetworkIsolation(SOURCE, 'staging'),
    ...overrides,
  });
}

const warning: Diagnostic = {
  rule: 'documentation/org-url',
  severity: 'warning',
  category: 'documentation',
  message: 'ORG_URL should use https',
};

describe('buildCiReport', () => {
  it('merges linter findings with isolation findings', () => {
    const report = stagingReport();
    expect(report.schema).toBe(CI_REPORT_SCHEMA);
    expect(report.label).toBe('Staging');
    expect(report.node).toBe('20');
    expect(report.checkNetwork).toBe(true);
    expect(report.ok).toBe(false);
    expect(report.error).toBeUndefined();
    expect(report.isolation.map((d) => d.rule)).toEqual(['ci/network-passphrase-mismatch']);
    expect(report.diagnostics.length).toBeGreaterThan(0);
    expect(report.counts.error).toBe(
      [...report.diagnostics, ...report.isolation].filter((d) => d.severity === 'error').length,
    );
    expect(isCiEnvironmentReport(report)).toBe(true);
  });

  it('passes a clean run with no isolation errors', () => {
    const report = buildCiReport({
      environment: 'public',
      file: 'public.toml',
      lintExitCode: 0,
      lintJson: JSON.stringify({
        file: 'public.toml',
        diagnostics: [warning, { junk: true }, null],
      }),
      isolation: [],
    });
    expect(report.ok).toBe(true);
    expect(report.diagnostics).toEqual([warning]);
    expect(report.counts).toEqual({ error: 0, warning: 1, info: 0 });
    expect(report).not.toHaveProperty('node');
    expect(report.checkNetwork).toBe(false);
  });

  it('fails strict runs on warnings and trusts a non-zero linter exit code', () => {
    const json = JSON.stringify([{ diagnostics: [warning] }]);
    expect(
      buildCiReport({
        environment: 'public',
        file: 'f',
        lintExitCode: 0,
        lintJson: json,
        isolation: [],
        strict: true,
      }).ok,
    ).toBe(false);
    expect(
      buildCiReport({
        environment: 'public',
        file: 'f',
        lintExitCode: 1,
        lintJson: json,
        isolation: [],
      }).ok,
    ).toBe(false);
  });

  it('keeps isolation warnings from failing the run on their own', () => {
    const report = buildCiReport({
      environment: 'public',
      file: 'f',
      lintExitCode: 0,
      lintJson: '{"diagnostics":[]}',
      isolation: [{ ...warning, rule: 'ci/example' }],
    });
    expect(report.ok).toBe(true);
  });

  it.each([
    [undefined, 'linter produced no output (exit code 2)'],
    ['   ', 'linter produced no output (exit code 2)'],
    ['{not json', 'linter output is not valid JSON (exit code 2)'],
    ['{"file":"x"}', 'linter output has no diagnostics array (exit code 2)'],
    ['null', 'linter output has no diagnostics array (exit code 2)'],
  ])('records unusable linter output %#', (json, error) => {
    const report = buildCiReport({
      environment: 'testnet',
      file: 'f',
      lintExitCode: 2,
      ...(json === undefined ? {} : { lintJson: json }),
      isolation: [],
    });
    expect(report.error).toBe(error);
    expect(report.ok).toBe(false);
  });
});

describe('isCiEnvironmentReport', () => {
  it('rejects anything that is not a v1 report', () => {
    const report = stagingReport();
    expect(isCiEnvironmentReport(null)).toBe(false);
    expect(isCiEnvironmentReport('x')).toBe(false);
    expect(isCiEnvironmentReport({ ...report, schema: 'other' })).toBe(false);
    expect(isCiEnvironmentReport({ ...report, environment: 'moon' })).toBe(false);
    expect(isCiEnvironmentReport({ ...report, counts: null })).toBe(false);
    expect(isCiEnvironmentReport({ ...report, isolation: undefined })).toBe(false);
  });
});

describe('formatCiSarif', () => {
  it('emits valid SARIF 2.1.0 with one categorised run per environment', () => {
    const reports = [
      stagingReport(),
      buildCiReport({
        environment: 'public',
        file: './public/stellar.toml',
        lintExitCode: 0,
        lintJson: '{"diagnostics":[]}',
        isolation: [],
      }),
    ];
    const log = JSON.parse(formatCiSarif(reports, '9.9.9', { [FILE]: SOURCE }));
    expect(validateSarif(log)).toEqual([]);
    expect(log.version).toBe('2.1.0');
    expect(log.runs).toHaveLength(2);

    const [staging, production] = log.runs;
    expect(staging.tool.driver.version).toBe('9.9.9');
    expect(staging.automationDetails).toEqual({ id: 'stellar-toml-lint/staging/' });
    expect(staging.properties).toEqual({ environment: 'staging', node: '20', checkNetwork: true });
    expect(staging.invocations).toEqual([{ executionSuccessful: true, exitCode: 1 }]);
    const isolation = staging.results.find(
      (r: { ruleId: string }) => r.ruleId === 'ci/network-passphrase-mismatch',
    );
    expect(isolation.level).toBe('error');
    expect(isolation.locations[0].physicalLocation.artifactLocation.uri).toBe(FILE);
    expect(isolation.locations[0].physicalLocation.region).toMatchObject({
      startLine: 2,
      snippet: { text: `NETWORK_PASSPHRASE="${PUBLIC_NETWORK_PASSPHRASE}"` },
    });

    expect(production.automationDetails.id).toBe('stellar-toml-lint/public/');
    expect(production.properties).toEqual({ environment: 'public', checkNetwork: false });
    expect(production.results).toEqual([]);
    expect(production.tool.driver.rules).toEqual([]);
  });

  it('reports a failed linter execution as a tool notification', () => {
    const report = buildCiReport({
      environment: 'testnet',
      file: 'f.toml',
      lintExitCode: 2,
      isolation: [],
    });
    const log = JSON.parse(formatCiSarif([report]));
    expect(validateSarif(log)).toEqual([]);
    expect(log.runs[0].invocations[0]).toEqual({
      executionSuccessful: false,
      exitCode: 2,
      toolExecutionNotifications: [
        { level: 'error', message: { text: 'linter produced no output (exit code 2)' } },
      ],
    });
  });

  it('names code scanning categories per environment', () => {
    expect(sarifCategory('testnet')).toBe('stellar-toml-lint/testnet');
  });
});

describe('validateSarif', () => {
  const good = () => JSON.parse(formatCiSarif([stagingReport()]));

  it('rejects non-objects and missing runs', () => {
    expect(validateSarif(null)).toEqual(['SARIF log must be an object']);
    expect(validateSarif({ version: '2.0.0', runs: [] })).toEqual([
      'version must be "2.1.0"',
      '$schema should reference the SARIF 2.1.0 schema',
      'runs must be a non-empty array',
    ]);
  });

  it('requires a tool driver name and results array', () => {
    const log = good();
    log.runs.push({ tool: { driver: {} } });
    log.runs.push({ tool: { driver: { name: 'x' } }, automationDetails: { id: 'other/' } });
    expect(validateSarif(log)).toEqual([
      'runs[1]: tool.driver.name is required',
      'runs[2]: results must be an array',
    ]);
  });

  it('rejects duplicate categories and rule ids', () => {
    const log = good();
    log.runs.push(JSON.parse(JSON.stringify(log.runs[0])));
    log.runs[1].tool.driver.rules.push(log.runs[1].tool.driver.rules[0]);
    expect(validateSarif(log)).toContain('runs[1]: duplicate rule ids');
    expect(validateSarif(log)).toContain(
      'runs[1]: runs sharing tool and category "stellar-toml-lint/staging/" are rejected by code scanning',
    );
  });

  it('checks each result against code scanning requirements', () => {
    const log = good();
    const base = log.runs[0].results[0];
    const location = (uri: unknown, region: unknown = { startLine: 1 }) => [
      { physicalLocation: { artifactLocation: { uri }, region } },
    ];
    log.runs[0].results = [
      { ...base, message: {}, ruleId: undefined },
      { ...base, ruleId: 'nope' },
      { ...base, ruleIndex: 99 },
      { ...base, level: 'fatal' },
      { ...base, locations: [] },
      { ...base, locations: location('') },
      { ...base, locations: location('https://x/stellar.toml') },
      { ...base, locations: location('/abs/stellar.toml') },
      { ...base, locations: location('dir\\stellar.toml') },
      { ...base, locations: location('ok.toml', { startLine: 0, startColumn: 1.5 }) },
      { ...base, locations: [{}] },
    ];
    expect(validateSarif(log)).toEqual([
      'runs[0].results[0]: message.text is required',
      'runs[0].results[0]: ruleId is required',
      'runs[0].results[1]: ruleId has no rule',
      'runs[0].results[1]: ruleIndex does not point at ruleId',
      'runs[0].results[2]: ruleIndex does not point at ruleId',
      'runs[0].results[3]: invalid level "fatal"',
      'runs[0].results[4]: at least one location is required',
      'runs[0].results[5]: artifactLocation.uri is required',
      'runs[0].results[6]: artifactLocation.uri must be repository-relative',
      'runs[0].results[7]: artifactLocation.uri must be repository-relative',
      'runs[0].results[8]: artifactLocation.uri must be repository-relative',
      'runs[0].results[9]: region.startLine must be a positive integer',
      'runs[0].results[9]: region.startColumn must be a positive integer',
      'runs[0].results[10]: artifactLocation.uri is required',
    ]);
  });

  it('tolerates runs without rules or automation details', () => {
    expect(
      validateSarif({
        $schema: 's',
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'x' } }, results: [] }],
      }),
    ).toEqual([]);
  });
});

describe('scorecards', () => {
  it('scores and grades reports', () => {
    const base = stagingReport();
    expect(scoreReport({ ...base, counts: { error: 0, warning: 0, info: 0 } })).toBe(100);
    expect(scoreReport({ ...base, counts: { error: 1, warning: 2, info: 3 } })).toBe(67);
    expect(scoreReport({ ...base, counts: { error: 9, warning: 0, info: 0 } })).toBe(0);
    expect(scoreReport({ ...base, error: 'boom' })).toBe(0);
    expect([100, 95, 94, 85, 84, 70, 69, 50, 49].map(gradeFor).join('')).toBe('AABBCCDDF');
  });

  it('renders one environment with its findings and context', () => {
    const markdown = formatEnvironmentScorecard(stagingReport());
    expect(markdown).toContain(`### ❌ fail — Staging (\`${FILE}\`)`);
    expect(markdown).toContain('network isolation ❌ leaking');
    expect(markdown).toContain('Node 20 · live checks on');
    expect(markdown).toContain('| 🔴 error | `ci/network-passphrase-mismatch` | L2:1 |');
  });

  it('renders pass, warning-only isolation, errors and positionless findings', () => {
    const clean = buildCiReport({
      environment: 'public',
      file: 'p.toml',
      lintExitCode: 0,
      lintJson: JSON.stringify({
        diagnostics: [
          { ...warning, path: 'DOCUMENTATION.ORG_URL' },
          { ...warning, severity: 'info', rule: 'x|y' },
        ],
      }),
      isolation: [{ ...warning, rule: 'ci/review', message: 'a <b> c\nd' }],
    });
    const markdown = formatEnvironmentScorecard(clean);
    expect(markdown).toContain('### ✅ pass');
    expect(markdown).toContain('network isolation ⚠️ review');
    expect(markdown).toContain('offline checks');
    expect(markdown).not.toContain('Node ');
    expect(markdown).toContain('| DOCUMENTATION.ORG_URL |');
    expect(markdown).toContain('| — | a &lt;b> c d |');
    expect(markdown).toContain('`x\\|y`');
    expect(markdown).toContain('🔵 info');

    const errored = formatEnvironmentScorecard(
      buildCiReport({ environment: 'testnet', file: 't.toml', lintExitCode: 2, isolation: [] }),
    );
    expect(errored).toContain('💥 errored');
    expect(errored).toContain('> ⚠️ linter produced no output (exit code 2)');
    expect(errored).toContain('**Score 0/100 (F)**');
    expect(errored).not.toContain('| Severity |');
  });

  it('truncates long finding lists', () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ ...warning, rule: `r/${i}` }));
    const report = buildCiReport({
      environment: 'public',
      file: 'p.toml',
      lintExitCode: 0,
      lintJson: JSON.stringify({ diagnostics: many }),
      isolation: [],
    });
    expect(formatEnvironmentScorecard(report)).toContain(
      '_…and 5 more; see the code scanning alerts._',
    );
  });

  it('builds the PR comment with marker, summary table, ordered sections and footer', () => {
    const production = buildCiReport({
      environment: 'public',
      file: 'p.toml',
      lintExitCode: 0,
      lintJson: '{"diagnostics":[]}',
      isolation: [],
    });
    const comment = formatCiScorecard([production, stagingReport()], {
      runUrl: 'https://github.com/o/r/actions/runs/1',
      commit: '0123456789abcdef0123',
    });
    expect(comment.startsWith(`${SCORECARD_MARKER}\n## stellar.toml environment scorecard`)).toBe(
      true,
    );
    expect(comment).toContain('**❌ 1 of 2 environments failed**');
    expect(comment.indexOf('| Staging |')).toBeLessThan(
      comment.indexOf('| Production (public network) |'),
    );
    expect(comment).toContain('<details open>\n<summary>Staging</summary>');
    expect(comment).toContain('<details>\n<summary>Production (public network)</summary>');
    expect(comment).toContain(
      'commit `0123456789ab` · [workflow run](https://github.com/o/r/actions/runs/1)',
    );
  });

  it('summarises all-pass and empty runs', () => {
    const production = buildCiReport({
      environment: 'public',
      file: 'p.toml',
      lintExitCode: 0,
      lintJson: '{"diagnostics":[]}',
      isolation: [],
    });
    expect(formatCiScorecard([production])).toContain('**✅ All 1 environments passed**');
    const empty = formatCiScorecard([]);
    expect(empty).toContain('⚪ No environment reports were produced');
    expect(empty).toContain('<sub>Generated by stellar-toml-lint</sub>');
  });

  it('stays within the comment size limit', () => {
    const report = stagingReport();
    const comment = formatCiScorecard(
      [report, { ...report, environment: 'testnet', label: 'Testnet' }],
      {
        limit: 1200,
      },
    );
    expect(comment.length).toBeLessThanOrEqual(1200);
    expect(comment).toContain('_Details truncated to fit GitHub’s comment size limit._');
    expect(GITHUB_COMMENT_LIMIT).toBe(65_536);
  });
});
