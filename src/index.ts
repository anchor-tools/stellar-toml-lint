/**
 * Public API for stellar-toml-lint.
 *
 * @example
 * ```ts
 * import { lint, formatText } from 'stellar-toml-lint';
 *
 * const result = lint(await readFile('stellar.toml', 'utf8'));
 * if (!result.ok) console.error(formatText(result));
 * ```
 */
export { lint, lintDomain } from './lint.js';
export { lspMain } from './lsp.js';
export { allRules, ruleIds } from './rules/index.js';
export {
  formatText,
  formatJson,
  formatSarif,
  formatGithub,
  formatJunit,
  formatHtml,
  formatCheckstyle,
  formatMarkdown,
} from './reporters.js';
export type { TextReporterOptions } from './reporters.js';
export { probeTls } from './tls.js';
export type { TlsProbe } from './tls.js';
export { createFixtureFetch, fixtureCandidates, MissingFixtureError } from './mock-fixtures.js';
export type { FixtureFile } from './mock-fixtures.js';
export type {
  Diagnostic,
  Fix,
  LintOptions,
  LintResult,
  Position,
  Rule,
  RuleCategory,
  RuleContext,
  RuleOverrides,
  Severity,
  TlsSession,
} from './types.js';
export { SPEC_URL } from './spec.js';
export { applyFixes, computeFixEdits } from './fix.js';
export type { OffsetTextEdit } from './fix.js';
export { codeActionsFor } from './lsp/code-actions.js';
export type { LspCodeAction, LspRange, LspTextEdit, LspWorkspaceEdit } from './lsp/code-actions.js';
