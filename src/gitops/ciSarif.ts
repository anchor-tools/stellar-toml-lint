/**
 * Per-environment CI reports and their SARIF 2.1.0 export.
 *
 * Each matrix cell produces one {@link CiEnvironmentReport}: the linter's own
 * findings plus the network-isolation assertions for that tenant. The report is
 * the single source for both the SARIF uploaded to code scanning and the
 * markdown scorecard posted on the pull request, so the two never disagree.
 */

import { finalize } from '../lint.js';
import { formatSarif } from '../reporters.js';
import type { Diagnostic, LintResult, Severity } from '../types.js';
import { CI_ENVIRONMENTS, type CiEnvironmentName } from './ciEnvironments.js';

export const CI_REPORT_SCHEMA = 'stellar-toml-lint/ci-report@1';

export interface CiEnvironmentReport {
  schema: typeof CI_REPORT_SCHEMA;
  environment: CiEnvironmentName;
  label: string;
  file: string;
  node?: string;
  checkNetwork: boolean;
  /** Linter exit code: 0 clean, 1 findings, 2 usage or I/O failure. */
  lintExitCode: number;
  /** Set when the linter produced no usable output. */
  error?: string;
  ok: boolean;
  counts: Record<Severity, number>;
  /** SEP-1 findings from the linter. */
  diagnostics: Diagnostic[];
  /** `ci/*` network-isolation findings. */
  isolation: Diagnostic[];
}

export interface BuildCiReportInput {
  environment: CiEnvironmentName;
  file: string;
  node?: string;
  checkNetwork?: boolean;
  lintExitCode: number;
  /** The linter's `--format json` output, or `undefined` if there was none. */
  lintJson?: string;
  isolation: Diagnostic[];
  strict?: boolean;
}

function isDiagnostic(value: unknown): value is Diagnostic {
  if (typeof value !== 'object' || value === null) return false;
  const d = value as Record<string, unknown>;
  return (
    typeof d.rule === 'string' &&
    typeof d.message === 'string' &&
    (d.severity === 'error' || d.severity === 'warning' || d.severity === 'info')
  );
}

/** Parses the linter's JSON output; throws with a readable reason. */
function parseLintJson(text: string): Diagnostic[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('linter output is not valid JSON');
  }
  // Multiple files arrive as an array; a CI cell always lints exactly one.
  const entries = Array.isArray(parsed) ? parsed : [parsed];
  const diagnostics: Diagnostic[] = [];
  for (const entry of entries) {
    const list = (entry as { diagnostics?: unknown } | null)?.diagnostics;
    if (!Array.isArray(list)) throw new Error('linter output has no diagnostics array');
    diagnostics.push(...list.filter(isDiagnostic));
  }
  return diagnostics;
}

/** Combines a linter run and isolation findings into one environment report. */
export function buildCiReport(input: BuildCiReportInput): CiEnvironmentReport {
  const profile = CI_ENVIRONMENTS[input.environment];
  let diagnostics: Diagnostic[] = [];
  let error: string | undefined;

  if (input.lintJson === undefined || input.lintJson.trim() === '') {
    error = `linter produced no output (exit code ${input.lintExitCode})`;
  } else {
    try {
      diagnostics = parseLintJson(input.lintJson);
    } catch (reason) {
      error = `${(reason as Error).message} (exit code ${input.lintExitCode})`;
    }
  }

  const combined = finalize(
    [...diagnostics, ...input.isolation],
    { strict: input.strict ?? false },
    undefined,
  );
  const isolationFailed = input.isolation.some((d) => d.severity === 'error');
  // Trust the linter's exit code over a recount: it also reflects
  // `--max-warnings` and project config that the JSON does not carry.
  const lintOk = error === undefined && input.lintExitCode === 0;

  return {
    schema: CI_REPORT_SCHEMA,
    environment: input.environment,
    label: profile.label,
    file: input.file,
    ...(input.node === undefined ? {} : { node: input.node }),
    checkNetwork: input.checkNetwork ?? false,
    lintExitCode: input.lintExitCode,
    ...(error === undefined ? {} : { error }),
    ok: lintOk && !isolationFailed && combined.ok,
    counts: combined.counts,
    diagnostics: finalize(diagnostics, {}, undefined).diagnostics,
    isolation: finalize(input.isolation, {}, undefined).diagnostics,
  };
}

/** Type guard for reports read back from disk. */
export function isCiEnvironmentReport(value: unknown): value is CiEnvironmentReport {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    r.schema === CI_REPORT_SCHEMA &&
    typeof r.environment === 'string' &&
    r.environment in CI_ENVIRONMENTS &&
    typeof r.file === 'string' &&
    typeof r.ok === 'boolean' &&
    Array.isArray(r.diagnostics) &&
    Array.isArray(r.isolation) &&
    typeof r.counts === 'object' &&
    r.counts !== null
  );
}

/** The code-scanning category for an environment's results. */
export function sarifCategory(environment: CiEnvironmentName): string {
  return `stellar-toml-lint/${environment}`;
}

type SarifLog = {
  $schema: string;
  version: string;
  runs: Record<string, unknown>[];
};

function reportRun(
  report: CiEnvironmentReport,
  version: string,
  source?: string,
): Record<string, unknown> {
  const result: LintResult = finalize([...report.diagnostics, ...report.isolation], {}, undefined);
  const log = JSON.parse(formatSarif(result, report.file, version, source)) as SarifLog;
  const run = log.runs[0] as Record<string, unknown>;
  return {
    ...run,
    // Distinct ids keep each tenant's alerts separate in code scanning.
    automationDetails: { id: `${sarifCategory(report.environment)}/` },
    invocations: [
      {
        executionSuccessful: report.error === undefined,
        exitCode: report.lintExitCode,
        ...(report.error === undefined
          ? {}
          : {
              toolExecutionNotifications: [{ level: 'error', message: { text: report.error } }],
            }),
      },
    ],
    properties: {
      environment: report.environment,
      ...(report.node === undefined ? {} : { node: report.node }),
      checkNetwork: report.checkNetwork,
    },
  };
}

/**
 * SARIF for one or more environment reports, one run per environment.
 *
 * `source` maps a report's file path to its contents so results carry snippets.
 */
export function formatCiSarif(
  reports: readonly CiEnvironmentReport[],
  version = '0.1.0',
  sources: Readonly<Record<string, string>> = {},
): string {
  const log: SarifLog = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: reports.map((report) => reportRun(report, version, sources[report.file])),
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}

const SARIF_LEVELS = new Set(['none', 'note', 'warning', 'error']);

/**
 * Checks a SARIF log against the SARIF 2.1.0 requirements GitHub code scanning
 * enforces on upload. Returns one message per problem.
 */
export function validateSarif(log: unknown): string[] {
  const problems: string[] = [];
  if (typeof log !== 'object' || log === null) return ['SARIF log must be an object'];
  const root = log as Record<string, unknown>;
  if (root.version !== '2.1.0') problems.push('version must be "2.1.0"');
  if (typeof root.$schema !== 'string')
    problems.push('$schema should reference the SARIF 2.1.0 schema');
  if (!Array.isArray(root.runs) || root.runs.length === 0) {
    problems.push('runs must be a non-empty array');
    return problems;
  }

  const categories = new Set<string>();
  root.runs.forEach((value: unknown, r) => {
    const run = value as Record<string, unknown>;
    const at = `runs[${r}]`;
    const driver = (run.tool as { driver?: Record<string, unknown> } | undefined)?.driver;
    if (typeof driver?.name !== 'string' || driver.name === '') {
      problems.push(`${at}: tool.driver.name is required`);
      return;
    }
    const rules = Array.isArray(driver.rules) ? (driver.rules as { id?: unknown }[]) : [];
    const ruleIds = rules.map((rule) => rule.id);
    if (new Set(ruleIds).size !== ruleIds.length) problems.push(`${at}: duplicate rule ids`);

    const id = (run.automationDetails as { id?: unknown } | undefined)?.id;
    const category = typeof id === 'string' ? id : '';
    if (categories.has(category)) {
      problems.push(
        `${at}: runs sharing tool and category "${category}" are rejected by code scanning`,
      );
    }
    categories.add(category);

    if (!Array.isArray(run.results)) {
      problems.push(`${at}: results must be an array`);
      return;
    }
    run.results.forEach((value: unknown, i) => {
      const result = value as Record<string, unknown>;
      const where = `${at}.results[${i}]`;
      const text = (result.message as { text?: unknown } | undefined)?.text;
      if (typeof text !== 'string' || text === '')
        problems.push(`${where}: message.text is required`);
      if (typeof result.ruleId !== 'string') problems.push(`${where}: ruleId is required`);
      else {
        if (!ruleIds.includes(result.ruleId)) problems.push(`${where}: ruleId has no rule`);
        if (typeof result.ruleIndex === 'number' && ruleIds[result.ruleIndex] !== result.ruleId) {
          problems.push(`${where}: ruleIndex does not point at ruleId`);
        }
      }
      if (result.level !== undefined && !SARIF_LEVELS.has(result.level as string)) {
        problems.push(`${where}: invalid level "${String(result.level)}"`);
      }
      const locations = result.locations;
      if (!Array.isArray(locations) || locations.length === 0) {
        problems.push(`${where}: at least one location is required`);
        return;
      }
      for (const location of locations as Record<string, unknown>[]) {
        const physical = location.physicalLocation as Record<string, unknown> | undefined;
        const uri = (physical?.artifactLocation as { uri?: unknown } | undefined)?.uri;
        if (typeof uri !== 'string' || uri === '') {
          problems.push(`${where}: artifactLocation.uri is required`);
        } else if (/^[a-z][a-z0-9+.-]*:/i.test(uri) || uri.startsWith('/') || uri.includes('\\')) {
          problems.push(`${where}: artifactLocation.uri must be repository-relative`);
        }
        const region = physical?.region as Record<string, unknown> | undefined;
        for (const key of ['startLine', 'startColumn'] as const) {
          const n = region?.[key];
          if (n !== undefined && (!Number.isInteger(n) || (n as number) < 1)) {
            problems.push(`${where}: region.${key} must be a positive integer`);
          }
        }
      }
    });
  });
  return problems;
}
