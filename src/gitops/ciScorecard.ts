/**
 * Markdown scorecards for the CI matrix: one fragment per environment for the
 * job summary, and one combined comment for the pull request bot.
 */

import type { Diagnostic } from '../types.js';
import { CI_ENVIRONMENT_NAMES } from './ciEnvironments.js';
import type { CiEnvironmentReport } from './ciSarif.js';
import { SCORECARD_MARKER } from './ciWorkflowGenerator.js';

/** GitHub rejects issue comments longer than this. */
export const GITHUB_COMMENT_LIMIT = 65_536;
/** Findings listed per environment before the table is truncated. */
const MAX_ROWS = 25;

export interface CiScorecardOptions {
  /** Link to the workflow run, shown in the footer. */
  runUrl?: string;
  /** Commit the scorecard describes. */
  commit?: string;
  /** Character budget; defaults to GitHub's comment limit. */
  limit?: number;
}

/**
 * A 0–100 score: errors cost 20 points, warnings 5, info 1. Coarse on purpose —
 * it is there to make regressions visible at a glance, not to rank anchors.
 */
export function scoreReport(report: CiEnvironmentReport): number {
  if (report.error !== undefined) return 0;
  const { error, warning, info } = report.counts;
  return Math.max(0, 100 - error * 20 - warning * 5 - info);
}

export function gradeFor(score: number): string {
  if (score >= 95) return 'A';
  if (score >= 85) return 'B';
  if (score >= 70) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

function cell(text: string): string {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .replace(/</g, '&lt;');
}

function location(d: Diagnostic): string {
  if (d.position) return `L${d.position.line}:${d.position.column}`;
  return d.path ?? '—';
}

const ICON: Record<Diagnostic['severity'], string> = {
  error: '🔴 error',
  warning: '🟡 warning',
  info: '🔵 info',
};

function isolationStatus(report: CiEnvironmentReport): string {
  if (report.isolation.some((d) => d.severity === 'error')) return '❌ leaking';
  if (report.isolation.length > 0) return '⚠️ review';
  return '✅ isolated';
}

function status(report: CiEnvironmentReport): string {
  if (report.error !== undefined) return '💥 errored';
  return report.ok ? '✅ pass' : '❌ fail';
}

function findingsTable(findings: Diagnostic[]): string[] {
  const rows = findings.slice(0, MAX_ROWS);
  const lines = [
    '| Severity | Rule | Location | Message |',
    '| --- | --- | --- | --- |',
    ...rows.map(
      (d) =>
        `| ${ICON[d.severity]} | \`${cell(d.rule)}\` | ${cell(location(d))} | ${cell(d.message)} |`,
    ),
  ];
  if (findings.length > rows.length) {
    lines.push('', `_…and ${findings.length - rows.length} more; see the code scanning alerts._`);
  }
  return lines;
}

/** The section for one environment: summary line plus its findings. */
export function formatEnvironmentScorecard(report: CiEnvironmentReport): string {
  const score = scoreReport(report);
  const { error, warning, info } = report.counts;
  const lines = [
    `### ${status(report)} — ${cell(report.label)} (\`${cell(report.file)}\`)`,
    '',
    `**Score ${score}/100 (${gradeFor(score)})** · ${error} errors · ${warning} warnings · ${info} info · network isolation ${isolationStatus(report)}` +
      (report.node === undefined ? '' : ` · Node ${cell(report.node)}`) +
      (report.checkNetwork ? ' · live checks on' : ' · offline checks'),
  ];
  if (report.error !== undefined) {
    lines.push('', `> ⚠️ ${cell(report.error)}`);
  }
  const findings = [...report.isolation, ...report.diagnostics];
  if (findings.length > 0) {
    lines.push('', ...findingsTable(findings));
  }
  return `${lines.join('\n')}\n`;
}

function order(a: CiEnvironmentReport, b: CiEnvironmentReport): number {
  return CI_ENVIRONMENT_NAMES.indexOf(a.environment) - CI_ENVIRONMENT_NAMES.indexOf(b.environment);
}

/**
 * The pull request comment. It starts with {@link SCORECARD_MARKER} so the bot
 * can find and update it, and stays within GitHub's comment size limit by
 * collapsing per-environment detail before it would overflow.
 */
export function formatCiScorecard(
  reports: readonly CiEnvironmentReport[],
  options: CiScorecardOptions = {},
): string {
  const limit = options.limit ?? GITHUB_COMMENT_LIMIT;
  const sorted = [...reports].sort(order);
  const passed = sorted.filter((r) => r.ok).length;
  const overall =
    sorted.length === 0
      ? '⚪ No environment reports were produced'
      : passed === sorted.length
        ? `✅ All ${sorted.length} environments passed`
        : `❌ ${sorted.length - passed} of ${sorted.length} environments failed`;

  const head = [
    SCORECARD_MARKER,
    '## stellar.toml environment scorecard',
    '',
    `**${overall}**`,
    '',
    '| Environment | File | Status | Score | Errors | Warnings | Info | Network isolation |',
    '| --- | --- | --- | --- | --- | --- | --- | --- |',
    ...sorted.map((r) => {
      const score = scoreReport(r);
      return `| ${cell(r.label)} | \`${cell(r.file)}\` | ${status(r)} | ${score} (${gradeFor(score)}) | ${r.counts.error} | ${r.counts.warning} | ${r.counts.info} | ${isolationStatus(r)} |`;
    }),
    '',
  ].join('\n');

  const footerParts = [
    options.commit ? `commit \`${cell(options.commit.slice(0, 12))}\`` : undefined,
    options.runUrl ? `[workflow run](${encodeURI(options.runUrl)})` : undefined,
  ].filter((part): part is string => part !== undefined);
  const footer = `\n---\n<sub>Generated by stellar-toml-lint${footerParts.length > 0 ? ` · ${footerParts.join(' · ')}` : ''}</sub>\n`;

  const truncated = '\n_Details truncated to fit GitHub’s comment size limit._\n';
  let body = head;
  for (const report of sorted) {
    const section = `\n<details${report.ok ? '' : ' open'}>\n<summary>${cell(report.label)}</summary>\n\n${formatEnvironmentScorecard(report)}\n</details>\n`;
    // Reserve room for the notice so the comment never exceeds the limit.
    if (body.length + section.length + truncated.length + footer.length > limit) {
      body += truncated;
      break;
    }
    body += section;
  }
  return body + footer;
}
