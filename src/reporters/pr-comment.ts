import { computeScore } from '../generators/badge.js';
import type { Diagnostic, LintResult } from '../types.js';

/**
 * Aggregated pull-request comment for the GitHub Action (`--format pr-comment`).
 *
 * Where `--format github` scatters inline annotations across the diff (capped
 * at ten per run) and `--format markdown` targets `$GITHUB_STEP_SUMMARY`, this
 * reporter renders the whole audit as one GitHub-flavored Markdown dashboard
 * that the action posts **on the pull request itself**: the overall verdict
 * with the exit code, the Wallet Readiness score with its letter-grade badge,
 * any breaking (deprecated-field) changes, and a collapsible section with the
 * detailed suggestions and spec links.
 *
 * The output is a pure function of the run — no timestamp — so repeated runs
 * over an unchanged file produce a byte-identical comment body, which is what
 * lets the action update its previous comment in place instead of piling up
 * one comment per commit.
 *
 * The first line is an HTML marker comment; the action's posting script
 * (`action.yml`) searches the PR for a comment carrying it so it can update
 * in place. Everything sourced from the linted file — messages, paths,
 * suggestions, rule ids, the file name — is Markdown-escaped, because a
 * hostile `stellar.toml` must not be able to inject markup into a PR comment.
 */

/** Marker embedded at the top of every comment; the posting script keys on it. */
export const PR_COMMENT_MARKER = '<!-- stellar-toml-lint-report -->';

/** Repo the footer links back to. */
const REPO_URL = 'https://github.com/anchor-tools/stellar-toml-lint';

/** Rule id that flags deprecated fields — the closest thing to a breaking change SEP-1 has. */
export const BREAKING_CHANGE_RULE = 'general/deprecated-field';

export interface PrCommentOptions {
  /** File the report is about. Default `stellar.toml`. */
  filename?: string;
  /**
   * The linter's exit code, shown alongside the verdict so a reviewer can see
   * what CI decided without opening the run. Defaults to `0`/`1` from
   * {@link LintResult.ok}.
   */
  exitCode?: number;
  /** Maximum findings rendered in the collapsible details section. Default 20. */
  maxDetails?: number;
}

/** Letter grade for the Wallet Readiness score — same thresholds as the HTML report. */
function gradeOf(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/** Shields.io colour matching the grade's hue in the HTML report. */
function gradeColor(grade: string): string {
  if (grade === 'A') return 'brightgreen';
  if (grade === 'B') return 'green';
  if (grade === 'C') return 'yellow';
  if (grade === 'D') return 'orange';
  return 'red';
}

/** Static shields.io badge URL; parts are URI-encoded for the badge path. */
function badgeUrl(label: string, message: string, color: string): string {
  return `https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(message)}-${color}`;
}

/**
 * Diagnostics that indicate a breaking change: deprecated fields and legacy
 * configuration forms. Heuristic by design — SEP-1 has no stable
 * "breaking change" flag yet, so it keys on the deprecation rule id (plus any
 * message that self-describes as a deprecation) and narrows when a stable
 * signal lands.
 */
export function breakingChanges(diagnostics: Diagnostic[]): Diagnostic[] {
  return diagnostics.filter((d) => d.rule === BREAKING_CHANGE_RULE || /deprecat/i.test(d.message));
}

/** The field a deprecation diagnostic is about, for a one-line summary. */
function breakingChangeField(d: Diagnostic): string {
  const match = /^([A-Z][A-Z0-9_]+)\b/.exec(d.message);
  return match?.[1] ?? d.path ?? d.rule;
}

/** Escapes text for prose contexts: bold, list items, headings. */
function escapeMarkdown(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/([|`<>*_[\]])/g, '\\$1')
    .replace(/\r?\n/g, ' ');
}

/**
 * Escapes a value destined for a backtick code span, where GitHub interprets
 * none of the usual markup but does end the span at an unescaped backtick.
 * Full {@link escapeMarkdown} would be wrong here: a literal `\_` inside a
 * code span renders verbatim, so `AUTH_SERVER` would display as `AUTH\_SERVER`.
 */
function escapeCodeSpan(s: string): string {
  return s.replace(/`/g, '\\`').replace(/\r?\n/g, ' ');
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

/** `line:column` when known, else the dotted path, else an em dash. */
function locationOf(d: Diagnostic): string {
  if (d.position) return `${d.position.line}:${d.position.column}`;
  return d.path ?? '—';
}

/**
 * One bullet in the collapsible details section: rule, location, message, and
 * — when the rule provides them — the concrete suggestion and the spec link.
 */
function detailLine(d: Diagnostic): string[] {
  const location = escapeMarkdown(locationOf(d));
  const lines = [`- **\`${escapeCodeSpan(d.rule)}\`** (${location}): ${escapeMarkdown(d.message)}`];
  if (d.suggestion !== undefined && d.suggestion !== '') {
    lines.push(`  - Suggestion: ${escapeMarkdown(d.suggestion)}`);
  }
  if (d.helpUri !== undefined && d.helpUri !== '') {
    lines.push(`  - Spec: <${d.helpUri}>`);
  }
  return lines;
}

/**
 * Formats the aggregated PR comment.
 *
 * Layout: a status table (verdict badge, exit code, per-severity counts, and
 * the Wallet Readiness grade badge), a breaking-changes section when the run
 * found deprecated fields, and a collapsible `<details>` block carrying the
 * per-diagnostic suggestions so the comment opens scannable and expands on
 * demand.
 */
export function formatPrComment(result: LintResult, options: PrCommentOptions = {}): string {
  const filename = options.filename ?? 'stellar.toml';
  const exitCode = options.exitCode ?? (result.ok ? 0 : 1);
  const maxDetails = options.maxDetails ?? 20;

  const { error, warning, info } = result.counts;
  const verdict = result.ok ? 'Pass' : 'Fail';
  const statusColor = result.ok ? 'brightgreen' : 'red';
  const statusBadge = `![${verdict}](${badgeUrl('SEP-1', verdict, statusColor)})`;

  const score = computeScore(result);
  const grade = gradeOf(score);
  const readinessBadge = `![Wallet Readiness ${score}/100 (${grade})](${badgeUrl(
    'Wallet Readiness',
    `${score} / 100 (${grade})`,
    gradeColor(grade),
  )})`;

  const lines: string[] = [
    PR_COMMENT_MARKER,
    `## 🛰️ \`stellar.toml\` lint report`,
    '',
    `**${escapeMarkdown(filename)}** — ${plural(error + warning + info, 'finding')}`,
    '',
    '| Status | Exit code | Errors | Warnings | Info | Wallet Readiness |',
    '| --- | :-: | :-: | :-: | :-: | :-: |',
    `| ${statusBadge} | \`${exitCode}\` | ${error} | ${warning} | ${info} | ${readinessBadge} |`,
  ];

  const breaking = breakingChanges(result.diagnostics);
  if (breaking.length > 0) {
    lines.push('', `### ⚠️ Breaking changes (${breaking.length})`);
    lines.push('', 'Deprecated fields in this change may break existing clients:');
    for (const d of breaking) {
      lines.push(
        `- **\`${escapeCodeSpan(breakingChangeField(d))}\`** — ${escapeMarkdown(d.message)}`,
      );
      if (d.suggestion !== undefined && d.suggestion !== '') {
        lines.push(`  - Fix: ${escapeMarkdown(d.suggestion)}`);
      }
    }
  }

  if (result.diagnostics.length > 0) {
    const details = result.diagnostics.slice(0, maxDetails);
    const overflow = result.diagnostics.length - details.length;
    lines.push(
      '',
      '<details>',
      `<summary>🔍 Diagnostics &amp; suggestions (${result.diagnostics.length})</summary>`,
      '',
    );
    for (const d of details) lines.push(...detailLine(d));
    if (overflow > 0) {
      lines.push('', `…and ${overflow} more — see the full run log for the rest.`);
    }
    lines.push('', '</details>');
  } else {
    lines.push('', '✅ No SEP-1 findings — the file matches the spec.');
  }

  lines.push(
    '',
    '---',
    '',
    `<sub>🤖 Updated automatically by <a href="${REPO_URL}">stellar-toml-lint</a> — SEP-1 compliance for <code>${escapeMarkdown(filename)}</code></sub>`,
    '',
  );

  return lines.join('\n');
}
