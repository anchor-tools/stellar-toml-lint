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
  K8sIngressCertManagerAuditor,
  auditK8sManifests,
  gitopsRules,
} from './gitops/k8sIngressAuditor.js';
export { parseYamlDocuments } from './gitops/yaml.js';
export type { YamlDocument, YamlParseError, YamlParseResult } from './gitops/yaml.js';
export { formatText, formatJson, formatSarif, formatGithub, formatJunit } from './reporters.js';
export type { TextReporterOptions } from './reporters.js';
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
