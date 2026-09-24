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
export { allRules, ruleIds } from './rules/index.js';
export {
  formatText,
  formatJson,
  formatSarif,
  formatGithub,
  formatJunit,
  formatReadiness,
  formatReadinessJson,
} from './reporters.js';
export type { TextReporterOptions, ReadinessReporterOptions } from './reporters.js';
export { calculateReadiness, gradeFor } from './readiness.js';
export type {
  ReadinessCheck,
  ReadinessGrade,
  ReadinessPillar,
  ReadinessPillarId,
  ReadinessReport,
} from './readiness.js';
export { probeTls } from './tls.js';
export type { TlsProbe } from './tls.js';
export type {
  Diagnostic,
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
