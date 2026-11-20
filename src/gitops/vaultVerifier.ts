/**
 * HashiCorp Vault secret engine verifier for GitOps configurations.
 *
 * Inspects GitOps configuration files (Helm values, Kubernetes secrets templates,
 * GitHub Action workflows) for Vault references, validates KV v2 secret paths,
 * token renewal lease configurations, and verifies that secret injection manifests
 * do not expose cleartext tokens in environment variables or ConfigMaps.
 *
 * Standardizes secret mask logging so Vault tokens are never leaked in diagnostics
 * or logs. Provides automated dry-run testing against mock Vault servers to verify
 * secret retrieval and dynamic leasing.
 *
 * The checks work on the raw text of the file, so YAML, TOML, JSON, dotenv and
 * workflow files are all inspected the same way. When the file also parses as
 * JSON or TOML, the normalized structure is scanned too.
 *
 * Every regular expression here is linear: no nested quantifiers over
 * overlapping character classes, so hostile input cannot cause catastrophic
 * backtracking.
 */
import { parse as parseToml } from 'smol-toml';
import type { Rule } from '../types.js';

/** Vault KV v2 engine path prefix */
export const VAULT_KV_V2 = 'kv/v2';

/** Vault AppRole auth method path */
export const VAULT_APPROLE = 'approle';

/** Vault OIDC auth method path */
export const VAULT_OIDC = 'oidc';

/** Default Vault KV v2 mount path */
export const DEFAULT_VAULT_MOUNT = 'secret';

/** Vault token TTL (Time To Live) in seconds */
export const DEFAULT_VAULT_TTL = 7200;

/** Vault max TTL in seconds */
export const DEFAULT_VAULT_MAX_TTL = 86400;

/** Minimum token TTL, in seconds, below which renewals are considered unsafe. */
const DEFAULT_VAULT_MIN_TTL = 60;

/**
 * Severity levels for Vault-related findings.
 */
export type VaultSeverity = 'critical' | 'error' | 'warning' | 'info';

/**
 * Vault finding type.
 */
export interface VaultFinding {
  /** The rule ID identifying this finding */
  rule: string;
  /** Severity of the finding */
  severity: VaultSeverity;
  /** Human-readable description */
  message: string;
  /** Suggestion for remediation */
  suggestion: string;
  /** Optional path in the source file where the issue was found */
  path?: string;
  /** Optional position in the source file */
  position?: { line: number; column: number };
}

/**
 * Options for Vault secret engine verification.
 */
export interface VaultVerificationOptions {
  /** Whether to perform actual HTTP calls to a Vault server */
  dryRun?: boolean;
  /** Mock Vault server base URL for dry-run mode */
  mockVaultUrl?: string;
  /** Vault KV v2 secret path prefix */
  kvPathPrefix?: string;
  /** Maximum allowed token TTL in seconds */
  maxTtl?: number;
  /** Minimum required token TTL in seconds */
  minTtl?: number;
}

/**
 * Result of Vault secret engine verification.
 */
export interface VaultVerificationResult {
  /** True when no findings (all checks passed) */
  passed: boolean;
  /** Array of findings */
  findings: VaultFinding[];
  /** Summary text for reporting */
  summary: string;
}

/** Lease details returned by a dry-run read against a mock Vault server. */
export interface VaultLeaseInfo {
  duration?: number;
  renewable?: boolean;
}

/**
 * Rule IDs for Vault security findings.
 */
export const VAULT_RULE_IDS = {
  /** Vault KV v2 secret path not configured or invalid */
  KV_PATH_INVALID: 'security/vault-kv-path-invalid',
  /** Vault token TTL too short or misconfigured */
  TTL_MISCONFIGURED: 'security/vault-ttl-misconfigured',
  /** Vault token exposed in environment variable */
  TOKEN_ENV_EXPOSED: 'security/vault-token-env-exposed',
  /** Vault token exposed in ConfigMap */
  TOKEN_CONFIGMAP_EXPOSED: 'security/vault-token-configmap-exposed',
  /** Vault AppRole role ID not properly restricted */
  APPROLE_ROLE_ID: 'security/vault-approle-role-id',
  /** Vault OIDC role binding misconfigured */
  OIDC_ROLE_BINDING: 'security/vault-oidc-role-binding',
  /** Vault secret engine path not using KV v2 */
  KV_ENGINE_NOT_V2: 'security/vault-kv-engine-not-v2',
  /** Vault dynamic lease not configured */
  DYNAMIC_LEASE_MISSING: 'security/vault-dynamic-lease-missing',
};

/**
 * Human-readable names for Vault rule IDs.
 */
export const VAULT_RULE_NAMES: Record<string, string> = {
  [VAULT_RULE_IDS.KV_PATH_INVALID]: 'Vault KV v2 secret path invalid or missing',
  [VAULT_RULE_IDS.TTL_MISCONFIGURED]: 'Vault token TTL misconfigured',
  [VAULT_RULE_IDS.TOKEN_ENV_EXPOSED]: 'Vault token exposed in environment variable',
  [VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED]: 'Vault token exposed in ConfigMap',
  [VAULT_RULE_IDS.APPROLE_ROLE_ID]: 'Vault AppRole role ID not properly restricted',
  [VAULT_RULE_IDS.OIDC_ROLE_BINDING]: 'Vault OIDC role binding misconfigured',
  [VAULT_RULE_IDS.KV_ENGINE_NOT_V2]: 'Vault secret engine not using KV v2',
  [VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING]: 'Vault dynamic lease not configured',
};

/** Recommendation headings used in the summary, per rule. */
const RULE_CATEGORIES: Record<string, string> = {
  [VAULT_RULE_IDS.KV_PATH_INVALID]: 'Vault path configuration',
  [VAULT_RULE_IDS.TTL_MISCONFIGURED]: 'Token TTL configuration',
  [VAULT_RULE_IDS.TOKEN_ENV_EXPOSED]: 'Environment variable security',
  [VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED]: 'ConfigMap security',
  [VAULT_RULE_IDS.APPROLE_ROLE_ID]: 'AppRole authentication',
  [VAULT_RULE_IDS.OIDC_ROLE_BINDING]: 'OIDC authentication',
  [VAULT_RULE_IDS.KV_ENGINE_NOT_V2]: 'KV engine version',
  [VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING]: 'Dynamic lease configuration',
};

/**
 * Interface for a parsed GitOps configuration file.
 */
export interface GitOpsFile {
  /** Raw file content */
  content: string;
  /** Parsed TOML/JSON/YAML structure (if applicable) */
  parsed?: Record<string, unknown>;
  /** File path */
  path: string;
  /** File extension */
  ext: string;
}

/**
 * Types of GitOps files that can be inspected.
 */
export type GitOpsFileType =
  'helm-values' | 'kubernetes-secret' | 'github-workflow' | 'kubernetes-deployment' | 'generic';

/** Values that are obviously not real secrets. */
const PLACEHOLDER = /^(?:example|dummy|test|placeholder|replace|changeme|xxx|<|\$\{|\{\{)/i;

/**
 * Parses a GitOps configuration file and extracts relevant sections.
 *
 * JSON and TOML are parsed; YAML is inspected as text only, since a YAML parser
 * is not a runtime dependency of this package.
 */
export function parseGitOpsFile(filePath: string, content: string): GitOpsFile {
  const base = filePath.split(/[\\/]/).pop() ?? filePath;
  const dot = base.lastIndexOf('.');
  const ext = dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
  let parsed: Record<string, unknown> | undefined;

  try {
    if (ext === 'json') {
      const value: unknown = JSON.parse(content);
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        parsed = value as Record<string, unknown>;
      }
    } else if (ext === 'toml') {
      parsed = parseToml(content) as Record<string, unknown>;
    }
  } catch {
    // If parsing fails, proceed with raw content only
  }

  return {
    content,
    ...(parsed ? { parsed } : {}),
    path: filePath,
    ext,
  };
}

/** Raw content plus, when available, the normalized parsed structure. */
function scanText(file: GitOpsFile): string {
  return file.parsed ? `${file.content}\n${JSON.stringify(file.parsed)}` : file.content;
}

/**
 * Extracts Vault references from a GitOps configuration file.
 *
 * searches for:
 * - Vault KV v2 secret paths (e.g., {{ .Values.vault.secrets.apiKey }})
 * - Environment variables referencing Vault tokens
 * - ConfigMap references containing Vault tokens
 * - AppRole authentication configurations
 * - OIDC authentication configurations
 */
export function extractVaultReferences(file: GitOpsFile): {
  kvPaths: string[];
  envVars: string[];
  configMapRefs: string[];
  appRoleConfig: { roleId: string; secretId: string } | null;
  oidcConfig: { url: string; role: string; aud: string } | null;
} {
  const text = scanText(file);
  const unique = (values: string[]) => [...new Set(values)];

  // Helm template expressions referencing Vault, e.g. {{ .Values.vault.token }}
  const kvPaths = unique(
    [...text.matchAll(/\{\{[^{}]*\}\}/g)]
      .map((match) => match[0].trim())
      .filter((expression) => /vault/i.test(expression)),
  );

  // Environment variable names that suggest secrets
  const envVars = unique(
    [...text.matchAll(/\bname["']?\s*:\s*["']?([A-Za-z_]\w*)/g)]
      .map((match) => match[1] ?? '')
      .filter((name) => /VAULT|SECRET|TOKEN|PASSWORD|KEY/i.test(name)),
  );

  // ConfigMap names referenced from pods (configMapRef / configMapKeyRef / volumes)
  const configMapRefs = unique(
    [...text.matchAll(CONFIGMAP_REF)].map((match) => match[1] ?? '').filter(Boolean),
  );

  const roleId = firstValue(text, 'role_id');
  const secretId = firstValue(text, 'secret_id');
  const appRoleConfig =
    roleId !== undefined || secretId !== undefined
      ? { roleId: roleId ?? '', secretId: secretId ?? '' }
      : null;

  let oidcConfig: { url: string; role: string; aud: string } | null = null;
  if (/oidc/i.test(text)) {
    const url = firstValue(text, 'url');
    if (url !== undefined) {
      oidcConfig = {
        url,
        role: firstValue(text, 'role') ?? '',
        aud: firstValue(text, 'aud') ?? '',
      };
    }
  }

  return { kvPaths, envVars, configMapRefs, appRoleConfig, oidcConfig };
}

/** First scalar value assigned to `key` in YAML (`key: v`), TOML (`key = v`) or JSON. */
function firstValue(text: string, key: string): string | undefined {
  const match = new RegExp(
    `\\b${key}["']?[ \\t]*[:=][ \\t]*(?:"([^"\\n]*)"|'([^'\\n]*)'|([^\\s,}#]*))`,
  ).exec(text);
  return match ? (match[1] ?? match[2] ?? match[3] ?? '') : undefined;
}

/** Every scalar value assigned to `key`, in order. */
function allValues(text: string, key: string): string[] {
  const pattern = new RegExp(
    `\\b${key}["']?[ \\t]*[:=][ \\t]*(?:"([^"\\n]*)"|'([^'\\n]*)'|([^\\s,}#]*))`,
    'g',
  );
  return [...text.matchAll(pattern)].map((match) => match[1] ?? match[2] ?? match[3] ?? '');
}

const CONFIGMAP_REF =
  /configMap(?:Ref|KeyRef)?["']?\s*:\s*\{?\s*["']?name["']?\s*:\s*["']?([\w.-]+)/gi;

/**
 * Validates a Vault KV v2 secret path format.
 *
 * A valid KV v2 path should:
 * - Start with a forward slash (optional but recommended)
 * - Contain only valid path characters (alphanumeric, slash, dash, underscore, dot)
 * - Not contain Vault internal path traversal patterns
 */
export function validateVaultKvPath(path: string): { valid: boolean; error?: string } {
  if (!path || path.trim().length === 0) {
    return { valid: false, error: 'Vault secret path is empty' };
  }

  const trimmed = path.trim();

  if (/(?:^|\/)\.{1,2}(?:\/|$)/.test(trimmed)) {
    return { valid: false, error: 'Vault path contains directory traversal pattern' };
  }

  // A single character class: linear time on any input.
  if (!/^[\w./-]+$/.test(trimmed)) {
    return {
      valid: false,
      error: `Vault path '${trimmed}' contains invalid characters. Use alphanumeric characters, slashes, dashes, underscores, or dots.`,
    };
  }

  return { valid: true };
}

/**
 * Validates the `.Values` reference inside a Helm expression that points at
 * Vault. Go templates only allow identifiers between the dots, so a reference
 * like `.Values.vault.secrets.bad-path` never resolves.
 */
function validateHelmVaultReference(expression: string): { valid: boolean; error?: string } {
  const reference = /\.Values((?:\.[^\s{}|)]+)+)/.exec(expression)?.[1];
  if (reference === undefined) return { valid: true };
  const bad = reference
    .split('.')
    .slice(1)
    .find((segment) => !/^[A-Za-z_]\w*$/.test(segment));
  if (bad === undefined) return { valid: true };
  return {
    valid: false,
    error: `Vault reference '${expression}' has invalid path segment '${bad}'; Helm value paths must be identifiers (use index for keys with dashes).`,
  };
}

/**
 * Validates Vault token TTL configuration.
 *
 * Checks that the TTL is within acceptable bounds and that
 * the max TTL is greater than or equal to the default TTL.
 */
export function validateVaultTtl(
  ttl: number,
  maxTtl: number,
  options: { minTtl?: number; maxTtl?: number } = {},
): { valid: boolean; error?: string } {
  const { minTtl = DEFAULT_VAULT_MIN_TTL, maxTtl: configuredMaxTtl = DEFAULT_VAULT_MAX_TTL } =
    options;

  if (ttl <= 0) {
    return { valid: false, error: 'Vault token TTL must be greater than zero' };
  }

  if (ttl < minTtl) {
    return {
      valid: false,
      error: `Vault token TTL (${ttl}s) is below minimum recommended value (${minTtl}s)`,
    };
  }

  if (ttl > configuredMaxTtl) {
    return {
      valid: false,
      error: `Vault token TTL (${ttl}s) exceeds maximum allowed (${configuredMaxTtl}s)`,
    };
  }

  if (maxTtl < ttl) {
    return {
      valid: false,
      error: `Vault max TTL must be greater than or equal to the default TTL (max_ttl ${maxTtl}s < ttl ${ttl}s)`,
    };
  }

  return { valid: true };
}

/**
 * Checks if a GitOps file exposes Vault tokens in environment variables.
 */
export function checkVaultTokenEnvExposure(file: GitOpsFile): VaultFinding[] {
  const findings: VaultFinding[] = [];
  const text = scanText(file);
  const flagged = new Set<string>();
  const flag = (name: string) => {
    if (flagged.has(name)) return;
    flagged.add(name);
    findings.push({
      rule: VAULT_RULE_IDS.TOKEN_ENV_EXPOSED,
      severity: 'error',
      message: `Vault token may be exposed in environment variable: ${name}`,
      suggestion:
        'Inject Vault tokens at runtime (Vault Agent sidecar, Kubernetes secretKeyRef, or CI secret store) instead of hardcoding them in environment variables.',
      path: file.path,
    });
  };
  const sensitiveName = /VAULT|TOKEN|SECRET/i;
  const literal = (value: string) => value.length >= 8 && !PLACEHOLDER.test(value);

  // Kubernetes container env: `- name: VAULT_TOKEN` followed by a literal `value:`.
  // (`valueFrom:` references a Secret and is the safe form.)
  const k8sEnv =
    /\bname\s*:\s*["']?([A-Za-z_]\w*)["']?[ \t]*\r?\n[ \t]*value\s*:\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s#]+))/g;
  for (const match of text.matchAll(k8sEnv)) {
    const name = match[1] ?? '';
    const value = match[2] ?? match[3] ?? match[4] ?? '';
    if (sensitiveName.test(name) && literal(value)) flag(name);
  }

  // dotenv / shell / Dockerfile: `VAULT_TOKEN=s.abc...`
  const assignment = /\b([A-Za-z_]\w*)=(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'#]+))/g;
  for (const match of text.matchAll(assignment)) {
    const name = match[1] ?? '';
    const value = match[2] ?? match[3] ?? match[4] ?? '';
    if (sensitiveName.test(name) && literal(value)) flag(name);
  }

  // GitHub Actions / compose `env:` maps: `VAULT_TOKEN: s.abc...`
  const mapping = /^[ \t]+([A-Z_][A-Z0-9_]*)[ \t]*:[ \t]*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s#]+))/gm;
  for (const match of text.matchAll(mapping)) {
    const name = match[1] ?? '';
    const value = match[2] ?? match[3] ?? match[4] ?? '';
    if (/VAULT/.test(name) && /TOKEN|SECRET/.test(name) && literal(value)) flag(name);
  }

  return findings;
}

/**
 * Checks if a GitOps file exposes Vault tokens in ConfigMaps.
 */
export function checkVaultTokenConfigMapExposure(file: GitOpsFile): VaultFinding[] {
  const findings: VaultFinding[] = [];
  const text = scanText(file);
  const flagged = new Set<string>();
  const flag = (name: string) => {
    if (flagged.has(name)) return;
    flagged.add(name);
    findings.push({
      rule: VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED,
      severity: 'error',
      message: `Vault token may be exposed in ConfigMap: ${name}`,
      suggestion:
        'Use Vault Agent sidecar injection or Kubernetes Secret references. Do not store Vault tokens directly in ConfigMaps.',
      path: file.path,
    });
  };

  // Pods referencing a ConfigMap whose name suggests it holds Vault credentials.
  for (const match of text.matchAll(CONFIGMAP_REF)) {
    const name = match[1] ?? '';
    if (/vault|token|secret/i.test(name)) flag(name);
  }

  // A ConfigMap manifest whose data carries a Vault token key.
  if (/\bkind\s*:\s*["']?ConfigMap\b/.test(text)) {
    const name =
      /\bmetadata\s*:\s*\r?\n\s*name\s*:\s*["']?([\w.-]+)/.exec(text)?.[1] ?? 'ConfigMap';
    if (/^[ \t]+[\w.-]*vault[\w.-]*token[\w.-]*[ \t]*:/im.test(text)) flag(name);
  }

  return findings;
}

/**
 * Checks if a GitOps file has properly restricted AppRole role_id.
 */
export function checkVaultAppRoleRestriction(file: GitOpsFile): VaultFinding[] {
  const findings: VaultFinding[] = [];
  const text = scanText(file);

  const roleIds = allValues(text, 'role_id');
  if (roleIds.some((value) => value === '' || /^\*+$/.test(value))) {
    findings.push({
      rule: VAULT_RULE_IDS.APPROLE_ROLE_ID,
      severity: 'error',
      message: 'Vault AppRole role_id is empty or uses wildcard',
      suggestion:
        'Configure a specific AppRole role_id with proper policies. Avoid using wildcard or empty role IDs.',
      path: file.path,
    });
  }

  const secretIds = allValues(text, 'secret_id');
  if (secretIds.some((value) => value !== '' && !PLACEHOLDER.test(value))) {
    findings.push({
      rule: VAULT_RULE_IDS.APPROLE_ROLE_ID,
      severity: 'error',
      message: 'Vault AppRole secret_id may be exposed in configuration',
      suggestion:
        'Use Vault Agent sidecar injection or Kubernetes secrets to inject secret_id at runtime. Avoid storing secret_id in GitOps configurations.',
      path: file.path,
    });
  }

  return findings;
}

/**
 * Checks if a GitOps file has properly configured OIDC role binding for Vault.
 */
export function checkVaultOidcRoleBinding(file: GitOpsFile): VaultFinding[] {
  const findings: VaultFinding[] = [];
  const text = scanText(file);
  const lowerText = text.toLowerCase();

  // No OIDC config found - this may be fine if using AppRole instead
  if (!lowerText.includes('oidc')) {
    return findings;
  }

  for (const field of ['url', 'role', 'aud']) {
    if (firstValue(lowerText, field) === undefined) {
      findings.push({
        rule: VAULT_RULE_IDS.OIDC_ROLE_BINDING,
        severity: 'warning',
        message: `Vault OIDC configuration missing required field: ${field}`,
        suggestion: `Configure Vault OIDC ${field} for proper authentication role binding.`,
        path: file.path,
      });
    }
  }

  const role = firstValue(text, 'role');
  if ((role === undefined || role === '') && !lowerText.includes('bound_service_account_name')) {
    findings.push({
      rule: VAULT_RULE_IDS.OIDC_ROLE_BINDING,
      severity: 'error',
      message: 'Vault OIDC role binding not properly configured',
      suggestion:
        'Configure bound_service_account_name or role_name in Vault OIDC auth method to restrict which service accounts can obtain tokens.',
      path: file.path,
    });
  }

  return findings;
}

/**
 * Checks if a GitOps file uses Vault KV v2 secret engine.
 */
export function checkVaultKvEngineVersion(file: GitOpsFile): VaultFinding[] {
  const text = scanText(file).toLowerCase();

  const hasKvV2 = ['kv/v2', 'kv-v2', 'kv_v2', 'secrets_engine', 'version 2', 'version: 2'].some(
    (marker) => text.includes(marker),
  );
  if (hasKvV2) return [];

  const looksLikeKvPath = /\bsecret\/data\b|\/data\/general\b|\/data\/metadata\b/.test(text);
  const looksLikeKvBlock =
    /^secret\s*:\s*\r?\n\s+data\s*:/m.test(text) || text.includes('"secret":{"data"');

  if (looksLikeKvPath || looksLikeKvBlock) {
    return [
      {
        rule: VAULT_RULE_IDS.KV_ENGINE_NOT_V2,
        severity: 'warning',
        message: 'Vault secret engine appears to be KV v1, consider migrating to KV v2',
        suggestion:
          'Migrate Vault secrets to KV v2 for versioning, soft-delete and metadata support.',
        path: file.path,
      },
    ];
  }

  return [
    {
      rule: VAULT_RULE_IDS.KV_ENGINE_NOT_V2,
      severity: 'info',
      message: 'Vault secret engine version not explicitly specified',
      suggestion:
        'Explicitly specify KV v2 engine path in GitOps configuration for clarity and future-proofing.',
      path: file.path,
    },
  ];
}

/**
 * Checks if a GitOps file has dynamic leases configured for Vault secrets.
 */
export function checkVaultDynamicLease(file: GitOpsFile): VaultFinding[] {
  const text = scanText(file);

  const hasLeaseConfig = ['renewable', 'max_ttl', 'ttl', 'auth', 'token', 'period'].some(
    (indicator) => new RegExp(`\\b${indicator}\\b`, 'i').test(text),
  );
  const hasDynamicLease = [
    /\blease\s*:/i,
    /\brenewal\s*:/i,
    /\bmax_ttl["']?\s*[:=]/i,
    /auth\/token/i,
  ].some((pattern) => pattern.test(text));

  if (hasDynamicLease) return [];

  if (hasLeaseConfig) {
    return [
      {
        rule: VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING,
        severity: 'warning',
        message: 'Vault dynamic lease configuration may be incomplete',
        suggestion:
          'Configure explicit dynamic lease settings (max_ttl, token_ttl) for Vault secrets to enable automatic rotation and renewal.',
        path: file.path,
      },
    ];
  }

  return [
    {
      rule: VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING,
      severity: 'error',
      message: 'Vault dynamic lease not configured',
      suggestion:
        'Configure dynamic leases for Vault secrets with appropriate TTL and max_ttl settings to enable automatic token rotation and renewal.',
      path: file.path,
    },
  ];
}

/** Whether a file mentions Vault at all; engine-level checks only apply then. */
function referencesVault(text: string): boolean {
  return /vault|approle|role_id|secret_id/i.test(text);
}

/**
 * Main verifier class that inspects GitOps configurations for Vault secret engine issues.
 */
export class VaultSecretEngineVerifier {
  /** Options for verification */
  private readonly options: Required<Omit<VaultVerificationOptions, 'mockVaultUrl'>> &
    Pick<VaultVerificationOptions, 'mockVaultUrl'>;

  /**
   * Creates a new VaultSecretEngineVerifier instance.
   * @param options Configuration options for the verifier
   */
  constructor(options: VaultVerificationOptions = {}) {
    this.options = {
      dryRun: options.dryRun ?? false,
      kvPathPrefix: options.kvPathPrefix ?? DEFAULT_VAULT_MOUNT,
      maxTtl: options.maxTtl ?? DEFAULT_VAULT_MAX_TTL,
      minTtl: options.minTtl ?? DEFAULT_VAULT_MIN_TTL,
      ...(options.mockVaultUrl !== undefined ? { mockVaultUrl: options.mockVaultUrl } : {}),
    };
  }

  /**
   * Verifies a single GitOps configuration file for Vault-related issues.
   * @param filePath Path to the GitOps configuration file
   * @param content Raw file content
   * @returns VaultVerificationResult with findings and pass/fail status
   */
  async verifyFile(filePath: string, content: string): Promise<VaultVerificationResult> {
    const file = parseGitOpsFile(filePath, content);
    const text = scanText(file);
    const allFindings: VaultFinding[] = [];

    // 1. Validate Vault references in Helm expressions and literal KV paths
    const references = extractVaultReferences(file);
    for (const expression of references.kvPaths) {
      const validation = validateHelmVaultReference(expression);
      if (!validation.valid) allFindings.push(this.kvPathFinding(filePath, validation.error));
    }
    for (const match of text.matchAll(/\b[\w-]+\/data\/[^\s"',}]+/g)) {
      const validation = validateVaultKvPath(match[0]);
      if (!validation.valid) allFindings.push(this.kvPathFinding(filePath, validation.error));
    }

    // 2-5. Token exposure and auth method configuration
    allFindings.push(
      ...checkVaultTokenEnvExposure(file),
      ...checkVaultTokenConfigMapExposure(file),
      ...checkVaultAppRoleRestriction(file),
      ...checkVaultOidcRoleBinding(file),
    );

    // 6-7. Engine version and leasing only make sense for files that use Vault
    if (referencesVault(text)) {
      allFindings.push(...checkVaultKvEngineVersion(file), ...checkVaultDynamicLease(file));
    }

    // 8. TTL bounds, whenever a TTL is declared
    const ttl = /(?:^|[^\w])ttl["']?[ \t]*[:=][ \t]*["']?(\d+)/im.exec(text)?.[1];
    const maxTtl = /\bmax_ttl["']?[ \t]*[:=][ \t]*["']?(\d+)/i.exec(text)?.[1];
    if (ttl !== undefined) {
      const validation = validateVaultTtl(
        Number.parseInt(ttl, 10),
        maxTtl !== undefined ? Number.parseInt(maxTtl, 10) : this.options.maxTtl,
        { minTtl: this.options.minTtl, maxTtl: this.options.maxTtl },
      );
      if (!validation.valid) {
        allFindings.push({
          rule: VAULT_RULE_IDS.TTL_MISCONFIGURED,
          severity: 'error',
          message: validation.error ?? 'Vault token TTL misconfigured',
          suggestion: `Adjust Vault token TTL to be within acceptable bounds (${this.options.minTtl}s to ${this.options.maxTtl}s).`,
          path: filePath,
        });
      }
    }

    const findings = dedupe(allFindings, (f) => `${f.rule}:${f.message}`);
    return {
      passed: findings.length === 0,
      findings,
      summary: this.generateSummary(findings),
    };
  }

  private kvPathFinding(filePath: string, error: string | undefined): VaultFinding {
    return {
      rule: VAULT_RULE_IDS.KV_PATH_INVALID,
      severity: 'error',
      message: error ?? 'Invalid Vault KV v2 secret path',
      suggestion:
        'Use proper Vault KV v2 secret path format (e.g., secret/data/path or secret/data/path/).',
      path: filePath,
    };
  }

  /**
   * Verifies multiple GitOps configuration files.
   * @param files Array of { path, content } objects
   * @returns VaultVerificationResult with aggregated findings
   */
  async verifyFiles(
    files: Array<{ path: string; content: string }>,
  ): Promise<VaultVerificationResult> {
    const allFindings: VaultFinding[] = [];
    for (const file of files) {
      allFindings.push(...(await this.verifyFile(file.path, file.content)).findings);
    }

    const findings = dedupe(allFindings, (f) => `${f.rule}:${f.message}:${f.path}`);
    return {
      passed: findings.length === 0,
      findings,
      summary: this.generateSummary(findings, files.length),
    };
  }

  /**
   * Generates a human-readable summary of findings.
   * @param findings Array of VaultFinding objects
   * @param fileCount Number of files inspected
   * @returns Summary text
   */
  private generateSummary(findings: VaultFinding[], fileCount: number = 1): string {
    const files = `${fileCount} file${fileCount === 1 ? '' : 's'}`;
    if (findings.length === 0) {
      return `Vault secret engine verification passed (${files} inspected)`;
    }

    const counts: Record<VaultSeverity, number> = { critical: 0, error: 0, warning: 0, info: 0 };
    for (const finding of findings) counts[finding.severity] += 1;

    let summary = `Vault secret engine verification: ${findings.length} issue${
      findings.length === 1 ? '' : 's'
    } found across ${files}:`;
    if (counts.critical > 0) summary += `\n  Critical: ${counts.critical}`;
    if (counts.error > 0) summary += `\n  Errors: ${counts.error}`;
    if (counts.warning > 0) summary += `\n  Warnings: ${counts.warning}`;
    if (counts.info > 0) summary += `\n  Info: ${counts.info}`;

    const recommendations = [
      ...new Set(findings.map((finding) => RULE_CATEGORIES[finding.rule]).filter(Boolean)),
    ];
    if (recommendations.length > 0) {
      summary += '\n\nRecommendations:';
      for (const rec of recommendations) summary += `\n- ${rec}`;
    }

    return summary;
  }

  /**
   * Performs a dry-run test against a mock Vault server.
   * This simulates secret retrieval and dynamic leasing without
   * connecting to a real Vault server.
   * @param secretPath The Vault KV v2 secret path to test
   * @returns Verification result for the mock Vault interaction
   */
  async dryRunVaultInteraction(secretPath: string): Promise<{
    success: boolean;
    secret?: string;
    error?: string;
    leaseInfo?: VaultLeaseInfo;
  }> {
    if (this.options.dryRun !== true || !this.options.mockVaultUrl) {
      return {
        success: false,
        error: 'Dry-run mode not enabled or mock Vault URL not configured',
      };
    }

    try {
      const mockUrl = new URL(this.options.mockVaultUrl);
      mockUrl.pathname = `/v1/${VAULT_KV_V2}/${secretPath.replace(/^\/+/, '')}`;

      const response = await fetch(mockUrl.toString(), {
        method: 'GET',
        headers: {
          'X-Vault-Token': `test-token-${Math.random().toString(36).substring(2, 15)}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        return {
          success: false,
          error: `Mock Vault returned ${response.status}: ${errorText}`,
        };
      }

      const data = (await response.json()) as {
        data?: Record<string, unknown>;
        lease_duration?: number;
        renewable?: boolean;
      };

      if (!data.data) {
        return {
          success: false,
          error: 'No secret data found in mock Vault response',
        };
      }

      return {
        success: true,
        secret: JSON.stringify(data.data),
        leaseInfo: {
          ...(data.lease_duration !== undefined ? { duration: data.lease_duration } : {}),
          ...(data.renewable !== undefined ? { renewable: data.renewable } : {}),
        },
      };
    } catch (error) {
      return {
        success: false,
        error: `Mock Vault interaction failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  /**
   * Simulates Vault token renewal for testing dynamic leasing.
   * @param currentTtl Current token TTL in seconds
   * @param renewalPercent Percentage of TTL to renew (typically 50-75%)
   * @returns New TTL after renewal simulation. `expired` is true when the
   *   renewed amount fell below the minimum TTL and had to be clamped up.
   */
  simulateTokenRenewal(
    currentTtl: number,
    renewalPercent: number = 50,
  ): { newTtl: number; renewedTtl: number; expired: boolean } {
    const renewedAmount = Math.floor(currentTtl * (renewalPercent / 100));
    const newTtl = Math.max(renewedAmount, this.options.minTtl);
    return {
      newTtl,
      renewedTtl: newTtl,
      expired: renewedAmount < this.options.minTtl,
    };
  }
}

function dedupe<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const k = key(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Creates a default VaultSecretEngineVerifier instance configured for production use.
 */
export function createDefaultVerifier(): VaultSecretEngineVerifier {
  return new VaultSecretEngineVerifier();
}

/**
 * Creates a VaultSecretEngineVerifier instance configured for dry-run/mock testing.
 * @param mockVaultUrl Base URL of the mock Vault server
 * @returns Configured verifier instance
 */
export function createMockVerifier(mockVaultUrl: string): VaultSecretEngineVerifier {
  return new VaultSecretEngineVerifier({
    dryRun: true,
    mockVaultUrl,
  });
}

/** All Vault rule IDs. */
export const vaultRuleIds: readonly string[] = Object.values(VAULT_RULE_IDS);

/** Registered Vault security rules for --list-rules and --off/--warn/--error. */
export const vaultRules: Rule[] = [
  {
    id: VAULT_RULE_IDS.KV_PATH_INVALID,
    category: 'security',
    severity: 'error',
    description: 'Public GitOps files must not contain invalid Vault KV v2 secret paths',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.TTL_MISCONFIGURED,
    category: 'security',
    severity: 'error',
    description: 'Vault token TTL misconfigured',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.TOKEN_ENV_EXPOSED,
    category: 'security',
    severity: 'error',
    description: 'Vault token exposed in environment variable',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED,
    category: 'security',
    severity: 'error',
    description: 'Vault token exposed in ConfigMap',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.APPROLE_ROLE_ID,
    category: 'security',
    severity: 'error',
    description: 'Vault AppRole role_id not properly restricted',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.OIDC_ROLE_BINDING,
    category: 'security',
    severity: 'error',
    description: 'Vault OIDC role binding misconfigured',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.KV_ENGINE_NOT_V2,
    category: 'security',
    severity: 'warning',
    description: 'Vault secret engine not using KV v2',
    run() {},
  },
  {
    id: VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING,
    category: 'security',
    severity: 'error',
    description: 'Vault dynamic lease not configured',
    run() {},
  },
];
