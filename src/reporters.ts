import type { Diagnostic, LintResult, Severity } from './types.js';

export { formatHtml } from './reporters/html.js';

/** Minimal ANSI helpers. Avoids a dependency for what is a dozen escape codes. */
export function makeColors(enabled: boolean) {
  const wrap = (open: number, close: number) => (s: string) =>
    enabled ? `[${open}m${s}[${close}m` : s;
  return {
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    grey: wrap(90, 39),
    bold: wrap(1, 22),
    underline: wrap(4, 24),
  };
}

const SEVERITY_LABEL: Record<Severity, string> = {
  error: 'error',
  warning: 'warning',
  info: 'info',
};

export interface TextReporterOptions {
  /** Path shown in the header and in each location line. */
  filename?: string;
  color?: boolean;
  /** Print the `suggestion` line under each diagnostic. */
  showSuggestions?: boolean;
  /** Print the spec `helpUri` under each diagnostic. */
  showHelp?: boolean;
  /**
   * Set when non-error diagnostics were filtered out upstream, so the
   * "nothing found" message can say "no errors" rather than overstating a
   * clean bill of health.
   */
  errorsOnly?: boolean;
}

/**
 * Human-readable output, one diagnostic per line, grouped in severity order.
 *
 * The format deliberately mirrors ESLint and tsc — `file:line:col severity
 * message rule` — because editors and terminal emulators already know how to
 * turn that shape into a clickable link.
 */
export function formatText(result: LintResult, options: TextReporterOptions = {}): string {
  const {
    filename = 'stellar.toml',
    color = false,
    showSuggestions = true,
    showHelp = false,
    errorsOnly = false,
  } = options;
  const c = makeColors(color);
  const lines: string[] = [];

  if (result.diagnostics.length === 0) {
    const verdict = errorsOnly ? 'No SEP-1 errors found.' : 'No SEP-1 issues found.';
    return `${c.bold(filename)}\n  ${verdict}\n`;
  }

  lines.push(c.bold(c.underline(filename)));

  // Width the location column to its widest entry. A rule about an absent key
  // has no line number and falls back to the dotted path, which is longer than
  // "12:1" — a fixed width would knock every following column out of line.
  const locations = result.diagnostics.map(locationOf);
  const width = Math.max(...locations.map((l) => l.length), 9);

  result.diagnostics.forEach((d, i) => {
    const location = locations[i] ?? '-';
    lines.push(
      `  ${c.grey(location.padEnd(width))} ${colorize(c, d.severity)}  ${d.message}  ${c.grey(d.rule)}`,
    );

    if (showSuggestions && d.suggestion) {
      lines.push(`  ${' '.repeat(width)} ${c.grey('↳')} ${c.grey(d.suggestion)}`);
    }
    if (showHelp && d.helpUri) {
      lines.push(`  ${' '.repeat(width)} ${c.grey(d.helpUri)}`);
    }
  });

  lines.push('');
  lines.push(summaryLine(result, c));
  lines.push('');
  return lines.join('\n');
}

/** `line:column` when known, else the dotted path, else a placeholder. */
function locationOf(d: Diagnostic): string {
  if (d.position) return `${d.position.line}:${d.position.column}`;
  return d.path ?? '-';
}

function colorize(c: ReturnType<typeof makeColors>, severity: Severity): string {
  const label = (SEVERITY_LABEL[severity] ?? severity).padEnd(7);
  if (severity === 'error') return c.red(label);
  if (severity === 'warning') return c.yellow(label);
  return c.blue(label);
}

function summaryLine(result: LintResult, c: ReturnType<typeof makeColors>): string {
  const { error, warning, info } = result.counts;
  const total = error + warning + info;
  const parts = [
    `${error} ${plural(error, 'error')}`,
    `${warning} ${plural(warning, 'warning')}`,
    `${info} ${plural(info, 'info')}`,
  ];
  const text = `  ${total} ${plural(total, 'problem')} (${parts.join(', ')})`;
  return error > 0 ? c.red(c.bold(text)) : warning > 0 ? c.yellow(text) : c.grey(text);
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

/**
 * The closing line of a multi-file run: `Checked 4 files: 3 passed, 1 failed
 * (2 errors, 3 warnings)`.
 *
 * Pass/fail is counted per file from each result's own verdict, so `--strict`
 * is reflected exactly as it is in that file's report; the totals behind the
 * parentheses are summed across every file, which is what a CI log needs to
 * judge the whole set at a glance.
 */
export function formatSummary(
  entries: { name: string; result: LintResult }[],
  options: { color?: boolean } = {},
): string {
  const c = makeColors(options.color ?? false);

  const checked = entries.length;
  const passed = entries.filter((entry) => entry.result.ok).length;
  const failed = checked - passed;

  const totals = entries.reduce(
    (acc, { result }) => {
      acc.error += result.counts.error;
      acc.warning += result.counts.warning;
      acc.info += result.counts.info;
      return acc;
    },
    { error: 0, warning: 0, info: 0 },
  );

  // Errors and warnings are always named, because they are what the exit code
  // reacts to; info only earns a mention when there is some to mention.
  const parts = [
    `${totals.error} ${plural(totals.error, 'error')}`,
    `${totals.warning} ${plural(totals.warning, 'warning')}`,
  ];
  if (totals.info > 0) parts.push(`${totals.info} ${plural(totals.info, 'info')}`);

  const line = `Checked ${checked} ${plural(checked, 'file')}: ${passed} passed, ${failed} failed (${parts.join(', ')})`;

  // The leading newline separates it from the last file's own summary, which
  // every text block already ends with.
  const text = `\n${line}\n`;
  return failed > 0 ? c.red(c.bold(text)) : totals.warning > 0 ? c.yellow(text) : c.grey(text);
}

/** Machine-readable output for scripts and dashboards. */
export function formatJson(result: LintResult, filename = 'stellar.toml'): string {
  return `${JSON.stringify(
    {
      file: filename,
      ok: result.ok,
      counts: result.counts,
      diagnostics: result.diagnostics,
    },
    null,
    2,
  )}\n`;
}

/** GitHub Actions workflow commands, which render as inline PR annotations. */
export function formatGithub(result: LintResult, filename = 'stellar.toml'): string {
  const lines = result.diagnostics.map((d) => {
    const level = d.severity === 'info' ? 'notice' : d.severity;
    const params = [`file=${filename}`];
    if (d.position) {
      params.push(`line=${d.position.line}`, `col=${d.position.column}`);
    }
    params.push(`title=${escapeProperty(`SEP-1: ${d.rule}`)}`);
    return `::${level} ${params.join(',')}::${escapeData(d.message)}`;
  });
  return lines.length > 0 ? `${lines.join('\n')}\n` : '';
}

// GitHub's workflow command format reserves these characters.
function escapeData(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(s: string): string {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/**
 * SARIF 2.1.0, the format GitHub code scanning ingests.
 *
 * Uploading this via `github/codeql-action/upload-sarif` puts SEP-1 findings in
 * the Security tab alongside everything else, with history and dismissal.
 */
export function formatSarif(
  result: LintResult,
  filename = 'stellar.toml',
  version = '0.1.0',
): string {
  const rules = new Map<string, Diagnostic>();
  for (const d of result.diagnostics) {
    if (!rules.has(d.rule)) rules.set(d.rule, d);
  }
  const ruleIndex = new Map([...rules.keys()].map((id, i) => [id, i]));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'stellar-toml-lint',
            informationUri: 'https://github.com/anchor-tools/stellar-toml-lint',
            version,
            rules: [...rules.entries()].map(([id, d]) => ({
              id,
              name: id,
              shortDescription: { text: `SEP-1: ${id}` },
              ...(d.helpUri ? { helpUri: d.helpUri } : {}),
              properties: { category: d.category },
            })),
          },
        },
        results: result.diagnostics.map((d) => ({
          ruleId: d.rule,
          ruleIndex: ruleIndex.get(d.rule) ?? 0,
          level: d.severity === 'info' ? 'note' : d.severity,
          message: { text: d.suggestion ? `${d.message}. ${d.suggestion}` : d.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: toUri(filename) },
                region: {
                  // SARIF requires 1-based positive integers.
                  startLine: Math.max(d.position?.line ?? 1, 1),
                  startColumn: Math.max(d.position?.column ?? 1, 1),
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/** SARIF artifact URIs must be relative and forward-slashed. */
function toUri(filename: string): string {
  return filename.replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * JUnit XML, which Jenkins, Bamboo, CircleCI and Azure DevOps parse to draw
 * pass/fail charts and test suite summaries.
 *
 * A lint run maps onto the schema the way a test suite does: the file is the
 * `<testsuite>`, and every diagnostic is a `<testcase>` named after its rule.
 *
 * JUnit has no notion of a non-fatal problem, so the two outcome elements are
 * split by what actually fails the run: `<failure>` is reserved for the
 * error-severity findings that drive the exit code, so a dashboard that counts
 * failures agrees with CI. Warnings and info land in `<error>` entries — still
 * visible, without claiming the file failed — and carry their severity in the
 * `type` attribute so the difference is machine-readable.
 */
export function formatJunit(result: LintResult, filename = 'stellar.toml'): string {
  const cases = result.diagnostics.map((d) => {
    const outcome = d.severity === 'error' ? 'failure' : 'error';
    const attributes = [
      `name="${escapeXmlAttribute(d.rule)}"`,
      `classname="${escapeXmlAttribute(d.category)}"`,
      `file="${escapeXmlAttribute(filename)}"`,
      ...(d.position ? [`line="${d.position.line}"`] : []),
      'time="0"',
    ].join(' ');

    // The element body carries what the terminal reporter shows under the
    // message: the concrete next step, and the spec link when one is known.
    const body = [d.message, d.suggestion, d.helpUri].filter(hasText).join('\n');

    return [
      `    <testcase ${attributes}>`,
      `      <${outcome} type="${d.severity}" message="${escapeXmlAttribute(d.message)}">${escapeXml(body)}</${outcome}>`,
      '    </testcase>',
    ].join('\n');
  });

  const counts = [
    `tests="${result.diagnostics.length}"`,
    `failures="${result.counts.error}"`,
    `errors="${result.counts.warning + result.counts.info}"`,
  ].join(' ');

  const suite = [
    `  <testsuite name="${escapeXmlAttribute(filename)}" ${counts} skipped="0" time="0">`,
    ...cases,
    '  </testsuite>',
  ];

  // No XML declaration is emitted. A run over several files concatenates one
  // document per file onto stdout, and a declaration anywhere but the very
  // first byte is a parse error, so omitting it is the honest option.
  return [
    `<testsuites name="${escapeXmlAttribute('stellar-toml-lint')}" ${counts}>`,
    ...suite,
    '</testsuites>',
    '',
  ].join('\n');
}

function hasText(value: string | undefined): value is string {
  return value !== undefined && value !== '';
}

/**
 * Escapes XML text, replacing the characters XML 1.0 forbids with U+FFFD.
 *
 * Diagnostic messages quote values read out of the linted file, so neither the
 * markup characters nor stray control bytes can be assumed away. A control
 * character that survives into the document makes a parser reject all of it,
 * which in CI looks like the linter failed to run at all.
 */
function escapeXml(s: string): string {
  return sanitizeXmlChars(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * XML 1.0 permits tab, newline, carriage return, and everything from #x20
 * upward that is not a lone surrogate or a noncharacter. Written as Unicode
 * property escapes because the literal form is a control-character regex.
 */
function sanitizeXmlChars(s: string): string {
  return s.replace(/[\p{Cc}\p{Cs}\uFFFE\uFFFF]/gu, (char) =>
    char === '\t' || char === '\n' || char === '\r' ? char : '\uFFFD',
  );
}

/** Attributes additionally have to escape both quote characters. */
function escapeXmlAttribute(s: string): string {
  return escapeXml(s).replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/**
 * Checkstyle XML, the shape Jenkins (Warnings NG), SonarQube-adjacent
 * dashboards, and Java-adjacent CI pipelines read for static-analysis results.
 *
 * The document mirrors what Checkstyle itself emits: one `<file>` per linted
 * file, one `<error>` per diagnostic carrying `line`, `column`, `severity`,
 * `message`, and `source`. `source` holds the rule id so a consumer can group,
 * baseline, or suppress findings the way it would a Checkstyle check.
 * Severity maps straight across (`error`, `warning`, `info`).
 *
 * `line` and `column` are always present, defaulting to 1: the format treats
 * them as required attributes even for a finding about an absent key that has
 * no position of its own — the same compromise SARIF makes for the same
 * diagnostics.
 *
 * Like `formatJunit`, no XML declaration is emitted. A run over several files
 * concatenates one document per file onto stdout, and a declaration anywhere
 * but the very first byte is a parse error, so omitting it is the honest
 * option.
 */
export function formatCheckstyle(
  result: LintResult,
  filename = 'stellar.toml',
  version = '0.1.0',
): string {
  const errors = result.diagnostics.map((d) => {
    const attributes = [
      `line="${Math.max(d.position?.line ?? 1, 1)}"`,
      `column="${Math.max(d.position?.column ?? 1, 1)}"`,
      `severity="${d.severity}"`,
      `message="${escapeXmlAttribute(d.message)}"`,
      `source="${escapeXmlAttribute(d.rule)}"`,
    ].join(' ');
    return `    <error ${attributes} />`;
  });

  return [
    `<checkstyle version="${escapeXmlAttribute(version)}">`,
    `  <file name="${escapeXmlAttribute(filename)}">`,
    ...errors,
    '  </file>',
    '</checkstyle>',
    '',
  ].join('\n');
}

/**
 * GitHub-flavored Markdown for a workflow's `$GITHUB_STEP_SUMMARY`.
 *
 * GitHub Actions caps the inline annotations `--format github` emits at ten
 * per run, and scatters the rest across commits and files. Piping this report
 * into the step summary instead renders the whole run — a pass/fail badge, the
 * error and warning counts, and one table row per finding — on the Action
 * overview page. Each diagnostic with a suggestion or spec link also gets a
 * collapsible `<details>` block so the table stays scannable.
 *
 * ```bash
 * stellar-toml-lint --format markdown >> "$GITHUB_STEP_SUMMARY"
 * ```
 */
export function formatMarkdown(result: LintResult, filename = 'stellar.toml'): string {
  const { error, warning, info } = result.counts;
  const name = escapeMarkdown(filename);

  if (result.diagnostics.length === 0) {
    return `### ✅ ${name}: No SEP-1 issues found\n`;
  }

  const status = result.ok ? '✅ Passed' : '❌ Failed';
  const lines: string[] = [
    `### ${status}: ${name}`,
    '',
    `**${error} ${plural(error, 'error')}**, **${warning} ${plural(warning, 'warning')}**, **${info} ${plural(info, 'info')}**`,
    '',
    '| Location | Severity | Rule | Message |',
    '| --- | --- | --- | --- |',
  ];

  for (const d of result.diagnostics) {
    lines.push(
      `| ${escapeMarkdownCell(locationOf(d))} | ${d.severity} | ${escapeMarkdownCell(d.rule)} | ${escapeMarkdownCell(d.message)} |`,
    );
  }

  const details = result.diagnostics.filter((d) => hasText(d.suggestion) || hasText(d.helpUri));
  if (details.length > 0) {
    lines.push('');
    lines.push('<details>');
    lines.push(`<summary>Details &amp; suggestions (${details.length})</summary>`);
    lines.push('');
    for (const d of details) {
      lines.push(`- **${escapeMarkdownCell(d.rule)}** (${escapeMarkdownCell(locationOf(d))})`);
      if (hasText(d.suggestion)) lines.push(`  - ${escapeMarkdownCell(d.suggestion)}`);
      if (hasText(d.helpUri)) lines.push(`  - Spec: <${d.helpUri}>`);
    }
    lines.push('');
    lines.push('</details>');
  }

  return `${lines.join('\n')}\n`;
}

/**
 * Escapes the characters GitHub's Markdown renderer would otherwise read as
 * markup. Diagnostic messages quote values straight out of the linted file, so
 * a `|` in a currency code or a `<script>` in a description must not be able to
 * break the table or inject markup into the run summary.
 */
function escapeMarkdown(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/([|`<>*_[\]])/g, '\\$1')
    .replace(/\r?\n/g, ' ');
}

/**
 * Table cells additionally have to escape their column separator, and the
 * angle brackets a raw `<` would open a tag with inside the summary document.
 */
function escapeMarkdownCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r?\n/g, ' ');
}

/** Newline-delimited JSON for streaming analysis. */
export function formatNdjson(result: LintResult, filename = 'stellar.toml'): string {
  const lines: string[] = [];

  for (const d of result.diagnostics) {
    lines.push(
      JSON.stringify({
        type: 'diagnostic',
        file: filename,
        rule: d.rule,
        severity: d.severity,
        message: d.message,
        ...(d.position ? { position: d.position } : {}),
      }),
    );
  }

  lines.push(
    JSON.stringify({
      type: 'summary',
      file: filename,
      ok: result.ok,
      counts: result.counts,
    }),
  );

  return `${lines.join('\n')}\n`;
}
