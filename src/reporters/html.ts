import { computeScore } from '../generators/badge.js';
import type { Diagnostic, LintResult } from '../types.js';

/**
 * Standalone HTML audit report for `--format html`.
 *
 * The document is deliberately self-contained: styles live in a single inline
 * `<style>` block, the severity filter is a tiny inline script, and nothing is
 * fetched from the network. A compliance reviewer can archive the file, attach
 * it to audit documentation, or open it on an air-gapped machine and see
 * exactly what the linter saw.
 *
 * Every string that originates from the linted file — messages, paths,
 * suggestions, rule ids, even the file name itself — passes through
 * {@link escapeHtml}, because those strings are attacker-controlled in the
 * threat model of "open this report in a browser".
 */
export function formatHtml(result: LintResult, filename = 'stellar.toml'): string {
  const safeName = escapeHtml(filename);
  const generated = new Date();
  const stamp = generated.toISOString();
  const { error, warning, info } = result.counts;
  const total = error + warning + info;

  const score = computeScore(result);
  const grade = gradeOf(score);
  const passed = result.ok;
  const verdict = passed ? 'Pass' : 'Fail';

  const rows =
    result.diagnostics.length > 0
      ? result.diagnostics.map((d) => diagnosticRow(d, filename)).join('\n')
      : `<tr><td colspan="5" class="empty">No SEP-1 issues found.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="stellar-toml-lint">
<meta name="robots" content="noindex">
<title>SEP-1 audit: ${safeName} — ${verdict}</title>
<style>
:root {
  --bg: #f4f6fa;
  --card: #ffffff;
  --ink: #17202e;
  --muted: #5b6676;
  --line: #e2e7ef;
  --error: #b42318;
  --error-bg: #fef3f2;
  --warning: #b54708;
  --warning-bg: #fffaeb;
  --info: #175cd3;
  --info-bg: #eff8ff;
  --pass: #067647;
  --pass-bg: #ecfdf3;
  --accent: #1f3a5f;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #10151d;
    --card: #1a212c;
    --ink: #e8ecf3;
    --muted: #9aa5b5;
    --line: #2a3341;
    --error: #fda29b;
    --error-bg: #3b1d1a;
    --warning: #fdb022;
    --warning-bg: #3b2f14;
    --info: #84adff;
    --info-bg: #16233c;
    --pass: #6ce9a6;
    --pass-bg: #12301f;
    --accent: #9ec3ff;
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
.wrap { max-width: 64rem; margin: 0 auto; padding: 0 1.25rem; }
.visually-hidden {
  position: absolute; width: 1px; height: 1px; margin: -1px;
  padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.top {
  background: var(--accent);
  color: #f5f8ff;
  padding: 2rem 0 1.75rem;
}
@media (prefers-color-scheme: dark) { .top { background: #131b28; } }
.top .brand {
  margin: 0 0 0.5rem;
  font-size: 0.78rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  opacity: 0.75;
}
.title-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; }
.top h1 {
  margin: 0;
  font-size: clamp(1.35rem, 3vw, 1.9rem);
  font-weight: 700;
  word-break: break-all;
}
.verdict {
  display: inline-block;
  padding: 0.2rem 0.7rem;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 700;
  letter-spacing: 0.05em;
}
.verdict-pass { background: var(--pass-bg); color: var(--pass); }
.verdict-fail { background: var(--error-bg); color: var(--error); }
.top .meta { margin: 0.65rem 0 0; font-size: 0.9rem; opacity: 0.85; }
main { padding: 1.75rem 0 3rem; }
.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.5rem;
}
.card h2 { margin: 0 0 1rem; font-size: 1.05rem; letter-spacing: 0.02em; }
.readiness { display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap; }
.grade {
  flex: none;
  width: 4.5rem;
  height: 4.5rem;
  border-radius: 12px;
  display: grid;
  place-items: center;
  font-size: 2rem;
  font-weight: 800;
}
.grade-a, .grade-b { background: var(--pass-bg); color: var(--pass); }
.grade-c, .grade-d { background: var(--warning-bg); color: var(--warning); }
.grade-f { background: var(--error-bg); color: var(--error); }
.readiness-body { flex: 1 1 16rem; min-width: 12rem; }
.score-row {
  display: flex;
  justify-content: space-between;
  font-size: 0.88rem;
  color: var(--muted);
  margin-bottom: 0.35rem;
}
.score-row .score-value { font-weight: 700; color: var(--ink); }
.meter {
  height: 0.7rem;
  background: var(--line);
  border-radius: 999px;
  overflow: hidden;
}
.meter-fill { height: 100%; border-radius: 999px; }
.meter-fill.grade-a, .meter-fill.grade-b { background: var(--pass); }
.meter-fill.grade-c, .meter-fill.grade-d { background: var(--warning); }
.meter-fill.grade-f { background: var(--error); }
.chips { display: flex; flex-wrap: wrap; gap: 0.5rem; list-style: none; margin: 1rem 0 0; padding: 0; }
.chip {
  padding: 0.2rem 0.7rem;
  border-radius: 999px;
  font-size: 0.82rem;
  font-weight: 600;
}
.chip-error { background: var(--error-bg); color: var(--error); }
.chip-warning { background: var(--warning-bg); color: var(--warning); }
.chip-info { background: var(--info-bg); color: var(--info); }
.filters { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
.filter {
  font: inherit;
  font-size: 0.88rem;
  padding: 0.35rem 0.9rem;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--card);
  color: var(--ink);
  cursor: pointer;
}
.filter:hover { border-color: var(--accent); }
.filter:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.filter.is-active { background: var(--accent); border-color: var(--accent); color: #f5f8ff; }
@media (prefers-color-scheme: dark) { .filter.is-active { color: #10151d; } }
.filter .count { font-weight: 700; }
.table-scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.93rem; }
th, td { text-align: left; padding: 0.7rem 0.75rem; vertical-align: top; border-top: 1px solid var(--line); }
thead th {
  border-top: 0;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}
tbody tr:hover { background: var(--bg); }
.pill {
  display: inline-block;
  padding: 0.1rem 0.6rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 700;
  white-space: nowrap;
}
.pill-error { background: var(--error-bg); color: var(--error); }
.pill-warning { background: var(--warning-bg); color: var(--warning); }
.pill-info { background: var(--info-bg); color: var(--info); }
code, .loc {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 0.85em;
}
.loc { word-break: break-all; }
.rule { color: var(--muted); word-break: break-all; }
.msg { margin: 0; }
td:has(.msg) { min-width: 22rem; }
details.more { margin-top: 0.5rem; }
details.more summary {
  cursor: pointer;
  font-size: 0.85rem;
  color: var(--accent);
  font-weight: 600;
}
details.more summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.frame, .snippet {
  margin: 0.6rem 0;
  padding: 0.7rem 0.85rem;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow-x: auto;
  white-space: pre;
}
.fix { margin: 0.4rem 0 0; color: var(--muted); font-size: 0.9rem; }
.spec-link { color: var(--accent); font-weight: 600; }
.empty { color: var(--muted); font-style: italic; text-align: center; padding: 1.5rem; }
.verdict-banner {
  border-left: 4px solid var(--pass);
  background: var(--pass-bg);
  color: var(--ink);
  padding: 0.8rem 1rem;
  border-radius: 0 8px 8px 0;
  margin-bottom: 1.5rem;
}
.verdict-banner.is-fail { border-left-color: var(--error); background: var(--error-bg); }
footer {
  border-top: 1px solid var(--line);
  padding: 1.25rem 0 2rem;
  color: var(--muted);
  font-size: 0.82rem;
}
footer p { margin: 0.25rem 0; }
@media print {
  body { background: #ffffff; color: #000000; }
  .filters { display: none; }
  .card { border-color: #999999; break-inside: avoid; }
  details.more[open] { break-inside: avoid; }
}
</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <p class="brand">stellar-toml-lint · SEP-1 audit report</p>
    <div class="title-row">
      <h1>${safeName}</h1>
      <span class="verdict ${passed ? 'verdict-pass' : 'verdict-fail'}">${verdict}</span>
    </div>
    <p class="meta">Generated <time datetime="${stamp}">${stamp}</time> · ${total} ${plural(total, 'problem')} (${error} ${plural(error, 'error')}, ${warning} ${plural(warning, 'warning')}, ${info} ${plural(info, 'info')})</p>
  </div>
</header>
<main class="wrap">
  <section class="card" aria-labelledby="readiness-title">
    <h2 id="readiness-title">Wallet Readiness</h2>
    <div class="readiness">
      <div class="grade grade-${grade.toLowerCase()}" role="img" aria-label="Readiness grade ${grade}">${grade}</div>
      <div class="readiness-body">
        <div class="score-row"><span class="score-label">Score</span><span class="score-value">${score} / 100</span></div>
        <div class="meter" role="img" aria-label="Readiness score ${score} out of 100">
          <div class="meter-fill grade-${grade.toLowerCase()}" style="width: ${score}%;"></div>
        </div>
        <ul class="chips">
          <li class="chip chip-error">${error} ${plural(error, 'error')}</li>
          <li class="chip chip-warning">${warning} ${plural(warning, 'warning')}</li>
          <li class="chip chip-info">${info} ${plural(info, 'info')}</li>
        </ul>
      </div>
    </div>
  </section>
  <p class="verdict-banner ${passed ? '' : 'is-fail'}">${
    passed
      ? `${safeName} passed: no SEP-1 errors were found.`
      : `${safeName} failed: ${error} ${plural(error, 'error')} must be fixed before this file is deployment-ready.`
  }</p>
  <section aria-labelledby="diagnostics-title">
    <h2 id="diagnostics-title">Diagnostics</h2>
    <div class="filters" role="group" aria-label="Filter diagnostics by severity">
      <button type="button" class="filter is-active" data-severity="all" aria-pressed="true">All <span class="count">${total}</span></button>
      <button type="button" class="filter" data-severity="error" aria-pressed="false">Errors <span class="count">${error}</span></button>
      <button type="button" class="filter" data-severity="warning" aria-pressed="false">Warnings <span class="count">${warning}</span></button>
      <button type="button" class="filter" data-severity="info" aria-pressed="false">Info <span class="count">${info}</span></button>
    </div>
    <div class="table-scroll">
      <table>
        <caption class="visually-hidden">Diagnostics for ${safeName}</caption>
        <thead>
          <tr><th scope="col">Severity</th><th scope="col">Location</th><th scope="col">Message</th><th scope="col">Rule</th><th scope="col">Spec</th></tr>
        </thead>
        <tbody>
${rows}
        </tbody>
      </table>
    </div>
  </section>
</main>
<footer>
  <div class="wrap">
    <p>Generated by stellar-toml-lint against <strong>${safeName}</strong> on ${stamp}.</p>
    <p>This report is self-contained: styles are inlined and nothing is loaded from the network.</p>
  </div>
</footer>
<script>
(function () {
  var buttons = document.querySelectorAll('.filter');
  var rows = document.querySelectorAll('tbody tr[data-severity]');
  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      var severity = button.getAttribute('data-severity');
      buttons.forEach(function (other) {
        var active = other === button;
        other.setAttribute('aria-pressed', String(active));
        other.classList.toggle('is-active', active);
      });
      rows.forEach(function (row) {
        row.hidden = !(severity === 'all' || row.getAttribute('data-severity') === severity);
      });
    });
  });
})();
</script>
</body>
</html>
`;
}

/** One table row: severity pill, location, message, expandable fix, rule, spec link. */
function diagnosticRow(d: Diagnostic, filename: string): string {
  const location = d.position ? `${d.position.line}:${d.position.column}` : (d.path ?? '—');

  const expandable = d.suggestion !== undefined || d.position !== undefined || d.path !== undefined;
  const details = expandable
    ? `<details class="more">
<summary>Show suggestion and code frame</summary>
<pre class="frame"><code>${escapeHtml(codeFrame(d, filename))}</code></pre>${
        d.suggestion !== undefined ? `\n<p class="fix">${escapeHtml(d.suggestion)}</p>` : ''
      }
</details>`
    : '';

  const spec = specLink(d.helpUri);

  return `          <tr data-severity="${d.severity}">
            <td><span class="pill pill-${d.severity}">${d.severity}</span></td>
            <td><code class="loc">${escapeHtml(location)}</code></td>
            <td><p class="msg">${escapeHtml(d.message)}</p>${details}</td>
            <td><code class="rule">${escapeHtml(d.rule)}</code></td>
            <td>${spec}</td>
          </tr>`;
}

/**
 * The line/column code frame: coordinates, rule, and dotted path.
 *
 * The reporter receives no raw source, so the frame renders the coordinates
 * the rule reported rather than inventing a caret position it cannot verify.
 */
function codeFrame(d: Diagnostic, filename: string): string {
  const where = d.position ? `${filename}:${d.position.line}:${d.position.column}` : filename;
  const lines = [`${where}  ${d.severity}  ${d.rule}`];
  if (d.path) lines.push(d.path);
  return lines.join('\n');
}

/** A spec link, but only for http(s) or in-page targets — never `javascript:`. */
function specLink(helpUri: string | undefined): string {
  if (helpUri === undefined || helpUri === '') return '<span aria-hidden="true">—</span>';
  if (!/^(https?:\/\/|#|\/(?!\/))/i.test(helpUri)) return '<span aria-hidden="true">—</span>';
  return `<a class="spec-link" href="${escapeHtml(helpUri)}" rel="noreferrer noopener" target="_blank">SEP-1</a>`;
}

/** Letter grade for the Wallet Readiness score, the same scale schools use. */
function gradeOf(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

/**
 * Escapes text for both element content and attribute values.
 *
 * Quotes are included so the same helper is safe in `href="…"` and
 * `datetime="…"` attributes, not just in text nodes.
 */
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
