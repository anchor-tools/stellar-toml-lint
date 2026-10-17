import { readFile } from 'node:fs/promises';
import type { CustomRegexMatcher, StellarToml } from '../types.js';
import { analyzeRegex, auditRegexSources } from '../rules/redos-detector.js';

export interface PolicyRule {
  id: string;
  description: string;
  severity: 'error' | 'warning' | 'info';
  match: PolicyMatch;
  message: string;
  suggestion?: string;
}

export interface PolicyMatch {
  jsonPath?: string;
  objectMatch?: Record<string, unknown>;
  allOf?: PolicyMatch[];
  anyOf?: PolicyMatch[];
  not?: PolicyMatch;
  /**
   * A regular expression the selected node's string value must match.
   *
   * The pattern is written by whoever wrote the policy, so it is screened for
   * catastrophic backtracking before it is ever compiled — see
   * {@link collectRegexMatchers} and `src/rules/redos-detector.ts`. A pattern
   * that can hang is refused rather than evaluated: a policy engine that
   * freezes the pipeline it was meant to guard is worse than one rule fewer.
   */
  regex?: string;
  /** Flags for {@link PolicyMatch.regex}. `g` is ignored, as `test` is stateful with it. */
  regexFlags?: string;
}

export interface Policy {
  version: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
}

export interface PolicyDiagnostic {
  rule: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  path?: string;
  position?: { line: number; column: number };
  suggestion?: string;
  policyId: string;
}

function evaluateJsonPath(obj: unknown, path: string): unknown[] {
  const parts = path.split('.').filter((p) => p !== '$');
  let current: unknown[] = [obj];

  for (const part of parts) {
    const next: unknown[] = [];
    for (const item of current) {
      if (part === '*') {
        if (Array.isArray(item)) {
          next.push(...item);
        } else if (item && typeof item === 'object') {
          next.push(...Object.values(item));
        }
      } else if (part.endsWith(']') && part.includes('[')) {
        const key = part.slice(0, part.indexOf('['));
        const indexStr = part.slice(part.indexOf('[') + 1, part.indexOf(']'));
        const index = parseInt(indexStr, 10);
        if (key) {
          const obj = item as Record<string, unknown>;
          if (obj[key] && Array.isArray(obj[key]) && obj[key][index] !== undefined) {
            next.push(obj[key][index]);
          }
        } else if (Array.isArray(item) && item[index] !== undefined) {
          next.push(item[index]);
        }
      } else {
        if (item && typeof item === 'object' && part in item) {
          next.push((item as Record<string, unknown>)[part]);
        }
      }
    }
    current = next;
  }

  return current;
}

function matchObject(obj: unknown, pattern: Record<string, unknown>): boolean {
  if (!obj || typeof obj !== 'object') return false;
  const objRecord = obj as Record<string, unknown>;

  for (const [key, expectedValue] of Object.entries(pattern)) {
    if (!(key in objRecord)) return false;
    const actualValue = objRecord[key];

    if (expectedValue === null) {
      if (actualValue !== null) return false;
    } else if (typeof expectedValue === 'object' && expectedValue !== null) {
      if (!matchObject(actualValue, expectedValue as Record<string, unknown>)) return false;
    } else if (actualValue !== expectedValue) {
      return false;
    }
  }
  return true;
}

function findPositions(source: string, path: string): { line: number; column: number }[] {
  const lines = source.split('\n');
  const positions: { line: number; column: number }[] = [];
  const pathParts = path.split('.').filter((p) => p !== '$');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    for (const part of pathParts) {
      if (line.includes(part)) {
        const col = line.indexOf(part);
        if (col >= 0) {
          positions.push({ line: i + 1, column: col + 1 });
        }
      }
    }
  }

  return positions.length > 0 ? positions : [{ line: 1, column: 1 }];
}

export async function loadPolicy(policyPath: string): Promise<Policy> {
  const content = await readFile(policyPath, 'utf8');

  if (policyPath.endsWith('.yaml') || policyPath.endsWith('.yml')) {
    try {
      const yamlModule = await import('yaml');
      return yamlModule.parse(content) as Policy;
    } catch {
      throw new Error('YAML support requires "yaml" package. Install with: npm install yaml');
    }
  }

  return JSON.parse(content) as Policy;
}

/**
 * Every regex matcher a policy declares, with the path that reaches it.
 *
 * The CLI hands these to `lint()` as {@link LintOptions.customRegexes} so the
 * `security/redos-*` rules report them through the ordinary diagnostic
 * pipeline, and {@link validatePolicy} screens the same list so a dangerous
 * matcher fails policy loading outright.
 */
export function collectRegexMatchers(policy: Policy): CustomRegexMatcher[] {
  const matchers: CustomRegexMatcher[] = [];
  const origin = `policy "${policy.name}"`;

  const walk = (match: PolicyMatch | undefined, path: string): void => {
    if (match === undefined) return;
    if (typeof match.regex === 'string') {
      matchers.push({
        pattern: match.regex,
        ...(match.regexFlags === undefined ? {} : { flags: match.regexFlags }),
        path: `${path}.regex`,
        origin,
      });
    }
    match.allOf?.forEach((child, i) => walk(child, `${path}.allOf[${i}]`));
    match.anyOf?.forEach((child, i) => walk(child, `${path}.anyOf[${i}]`));
    walk(match.not, `${path}.not`);
  };

  (policy.rules ?? []).forEach((rule, index) => {
    walk(rule.match, `rules[${index}].match`);
  });

  return matchers;
}

/**
 * Diagnostics for every unsafe regex matcher in a policy.
 *
 * Separate from {@link evaluatePolicy} so a caller can refuse to load a policy
 * before it runs, which is what the CLI does.
 */
export function auditPolicyRegexes(policy: Policy): PolicyDiagnostic[] {
  return auditRegexSources(collectRegexMatchers(policy)).map((diagnostic) => ({
    rule: diagnostic.rule,
    severity: diagnostic.severity,
    message: diagnostic.message,
    ...(diagnostic.path === undefined ? {} : { path: diagnostic.path }),
    ...(diagnostic.suggestion === undefined ? {} : { suggestion: diagnostic.suggestion }),
    policyId: policy.name,
  }));
}

export function validatePolicy(policy: Policy): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!policy.version) {
    errors.push('Policy must have a version');
  }

  if (!policy.name) {
    errors.push('Policy must have a name');
  }

  if (!policy.rules || !Array.isArray(policy.rules) || policy.rules.length === 0) {
    errors.push('Policy must have a non-empty rules array');
  } else {
    for (const rule of policy.rules) {
      if (!rule.id) errors.push('Rule must have an id');
      if (!rule.description) errors.push(`Rule ${rule.id}: must have a description`);
      if (!rule.severity || !['error', 'warning', 'info'].includes(rule.severity)) {
        errors.push(`Rule ${rule.id}: severity must be error, warning, or info`);
      }
      if (!rule.match) errors.push(`Rule ${rule.id}: must have a match condition`);
      if (!rule.message) errors.push(`Rule ${rule.id}: must have a message`);
    }
  }

  // A matcher that can hang the linter is a validation failure, not a finding
  // about the document: the policy must be fixed before it is used at all.
  for (const matcher of collectRegexMatchers(policy)) {
    const report = analyzeRegex(matcher.pattern, matcher.flags ?? '');
    if (report.parseError !== undefined) {
      errors.push(`${matcher.path}: /${matcher.pattern}/ is not valid: ${report.parseError}`);
      continue;
    }
    for (const finding of report.findings) {
      errors.push(
        `${matcher.path}: /${matcher.pattern}/ is vulnerable to ${finding.complexity} ` +
          `backtracking (\`${finding.fragment}\`) — ${finding.detail}`,
      );
    }
  }

  return { valid: errors.length === 0, errors };
}

export function evaluatePolicy(
  policy: Policy,
  toml: StellarToml,
  source: string,
): PolicyDiagnostic[] {
  const diagnostics: PolicyDiagnostic[] = [];

  // Screen every matcher once, up front. A rule whose pattern can hang is
  // skipped and reported in its place, so one bad policy entry costs that one
  // rule rather than the whole run.
  const regexFindings = auditPolicyRegexes(policy);
  const unsafe = new Set(
    regexFindings
      .map((diagnostic) => diagnostic.path)
      .filter((path): path is string => path !== undefined),
  );
  diagnostics.push(...regexFindings);

  for (const [index, rule] of policy.rules.entries()) {
    if (hasUnsafeRegex(rule.match, `rules[${index}].match`, unsafe)) continue;

    const jsonPath = rule.match.jsonPath ?? '$';
    const matches = evaluateJsonPath(toml, jsonPath);

    for (const match of matches) {
      // Evaluate the match conditions against the matched node
      let shouldReport = true;

      if (rule.match.regex !== undefined) {
        shouldReport = shouldReport && matchRegex(match, rule.match);
      }

      if (rule.match.objectMatch) {
        shouldReport = shouldReport && matchObject(match, rule.match.objectMatch);
      }

      if (rule.match.allOf) {
        shouldReport = shouldReport && rule.match.allOf.every((m) => evaluateMatchOnNode(match, m));
      }

      if (rule.match.anyOf) {
        shouldReport = shouldReport && rule.match.anyOf.some((m) => evaluateMatchOnNode(match, m));
      }

      if (rule.match.not) {
        shouldReport = shouldReport && !evaluateMatchOnNode(match, rule.match.not);
      }

      if (shouldReport) {
        const positions = findPositions(source, jsonPath);
        diagnostics.push({
          rule: rule.id,
          severity: rule.severity,
          message: rule.message,
          path: jsonPath,
          position: positions[0],
          suggestion: rule.suggestion,
          policyId: policy.name,
        });
      }
    }
  }

  return diagnostics;
}

/** `true` when any regex under `match` was screened out as unsafe. */
function hasUnsafeRegex(
  match: PolicyMatch | undefined,
  path: string,
  unsafe: ReadonlySet<string>,
): boolean {
  if (match === undefined) return false;
  if (match.regex !== undefined && unsafe.has(`${path}.regex`)) return true;
  if (match.allOf?.some((child, i) => hasUnsafeRegex(child, `${path}.allOf[${i}]`, unsafe))) {
    return true;
  }
  if (match.anyOf?.some((child, i) => hasUnsafeRegex(child, `${path}.anyOf[${i}]`, unsafe))) {
    return true;
  }
  return hasUnsafeRegex(match.not, `${path}.not`, unsafe);
}

/**
 * Tests a node's string value against a screened matcher.
 *
 * `g` is stripped: `RegExp.prototype.test` advances `lastIndex` with that flag
 * set, which would make the same matcher answer differently on its second
 * node. A pattern that will not compile (despite having parsed) matches
 * nothing rather than throwing mid-evaluation.
 */
function matchRegex(node: unknown, match: PolicyMatch): boolean {
  if (match.regex === undefined) return false;
  const value =
    typeof node === 'string' ? node : typeof node === 'number' ? String(node) : undefined;
  if (value === undefined) return false;

  try {
    const flags = (match.regexFlags ?? '').replace(/[gy]/g, '');
    return new RegExp(match.regex, flags).test(value);
  } catch {
    return false;
  }
}

function evaluateMatchOnNode(node: unknown, match: PolicyMatch): boolean {
  if (match.regex !== undefined) return matchRegex(node, match);

  if (match.jsonPath) {
    // For nested jsonPath, evaluate relative to the current node
    const results = evaluateJsonPath(node, match.jsonPath);
    return results.length > 0;
  }

  if (match.objectMatch) {
    return matchObject(node, match.objectMatch);
  }

  if (match.allOf) {
    return match.allOf.every((m) => evaluateMatchOnNode(node, m));
  }

  if (match.anyOf) {
    return match.anyOf.some((m) => evaluateMatchOnNode(node, m));
  }

  if (match.not) {
    return !evaluateMatchOnNode(node, match.not);
  }

  return true;
}

export function createSamplePolicy(): Policy {
  return {
    version: '1.0',
    name: 'enterprise-compliance',
    description: 'Enterprise compliance policy for Stellar anchors',
    rules: [
      {
        id: 'kyc-required',
        description: 'All regulated assets must have KYC enabled',
        severity: 'error',
        match: {
          jsonPath: '$.CURRENCIES[*]',
          objectMatch: {
            regulated: true,
          },
        },
        message: 'Regulated asset must have KYC server configured',
        suggestion: 'Add KYC_SERVER to SERVERS section',
      },
      {
        id: 'no-self-signed-certs',
        description: 'Disallow self-signed certificates',
        severity: 'error',
        match: {
          jsonPath: '$.SERVERS[*].TLS_CERT',
          objectMatch: {},
        },
        message: 'Self-signed certificates are not allowed',
        suggestion: 'Use a certificate from a trusted CA',
      },
      {
        id: 'multi-sig-issuers',
        description: 'Require multi-sig for all issuers',
        severity: 'warning',
        match: {
          jsonPath: '$.CURRENCIES[*].issuer',
          objectMatch: {},
        },
        message: 'Issuer should use multi-sig configuration',
        suggestion: 'Configure multi-sig for the issuing account',
      },
      {
        id: 'asset-display-decimals',
        description: 'display_decimals must be between 0 and 7',
        severity: 'error',
        match: {
          jsonPath: '$.CURRENCIES[*].display_decimals',
          objectMatch: {},
        },
        message: 'display_decimals must be in range 0-7',
        suggestion: 'Set display_decimals to a value between 0 and 7',
      },
      {
        id: 'signing-key-exists',
        description: 'SIGNING_KEY must be present',
        severity: 'error',
        match: {
          not: { jsonPath: '$.SIGNING_KEY' },
        },
        message: 'SIGNING_KEY is required',
        suggestion: 'Add SIGNING_KEY to the stellar.toml',
      },
      {
        id: 'org-documentation-exists',
        description: 'Organization documentation must exist',
        severity: 'warning',
        match: {
          not: { jsonPath: '$.DOCUMENTATION' },
        },
        message: 'Organization documentation is missing',
        suggestion: 'Add DOCUMENTATION section to the stellar.toml',
      },
    ],
  };
}
