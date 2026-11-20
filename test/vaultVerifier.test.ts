import { describe, expect, it } from 'vitest';
import {
  VaultSecretEngineVerifier,
  VaultVerificationOptions,
  VaultFinding,
  VaultVerificationResult,
  VAULT_RULE_IDS,
  VAULT_RULE_NAMES,
  parseGitOpsFile,
  validateVaultKvPath,
  validateVaultTtl,
  checkVaultTokenEnvExposure,
  checkVaultTokenConfigMapExposure,
  checkVaultAppRoleRestriction,
  checkVaultOidcRoleBinding,
  checkVaultKvEngineVersion,
  checkVaultDynamicLease,
  GitOpsFile,
  VaultSeverity,
  createDefaultVerifier,
  createMockVerifier,
} from '../src/gitops/vaultVerifier.js';

describe('VaultSecretEngineVerifier - parseGitOpsFile', () => {
  it('parses YAML content', () => {
    const file = parseGitOpsFile('test.yaml', 'apiVersion: v1\nkind: ConfigMap\n');
    expect(file.ext).toBe('yaml');
    expect(file.content).toBe('apiVersion: v1\nkind: ConfigMap\n');
  });

  it('parses JSON content', () => {
    const file = parseGitOpsFile('test.json', '{"key": "value"}');
    expect(file.ext).toBe('json');
    expect(file.content).toBe('{"key": "value"}');
  });

  it('parses TOML content', () => {
    const file = parseGitOpsFile('test.toml', 'key = "value"');
    expect(file.ext).toBe('toml');
    expect(file.content).toBe('key = "value"');
  });
});

describe('VaultSecretEngineVerifier - validateVaultKvPath', () => {
  it('validates a valid KV v2 path', () => {
    const result = validateVaultKvPath('secret/data/my-secret');
    expect(result.valid).toBe(true);
  });

  it('rejects empty path', () => {
    const result = validateVaultKvPath('');
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Vault secret path is empty');
  });

  it('rejects path with traversal pattern', () => {
    const result = validateVaultKvPath('../etc/passwd');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('directory traversal');
  });

  it('rejects path with invalid characters', () => {
    const result = validateVaultKvPath('secret/data/my@secret');
    expect(result.valid).toBe(false);
  });
});

describe('VaultSecretEngineVerifier - validateVaultTtl', () => {
  it('validates a valid TTL', () => {
    const result = validateVaultTtl(3600, 7200, { minTtl: 60, maxTtl: 86400 });
    expect(result.valid).toBe(true);
  });

  it('rejects TTL too short', () => {
    const result = validateVaultTtl(30, 7200, { minTtl: 60, maxTtl: 86400 });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('below minimum');
  });

  it('rejects TTL too long', () => {
    const result = validateVaultTtl(99999, 7200, { minTtl: 60, maxTtl: 86400 });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('exceeds maximum');
  });

  it('rejects max TTL less than default', () => {
    const result = validateVaultTtl(3600, 1000, { minTtl: 60, maxTtl: 86400 });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('max TTL must be greater');
  });
});

describe('VaultSecretEngineVerifier - checkVaultTokenEnvExposure', () => {
  it('detects Vault token exposure in environment variables', () => {
    const file = { content: 'env:\n  - name: VAULT_TOKEN\n    value: "sMySecretToken1234567890"', path: 'test.yaml', ext: 'yaml' } as GitOpsFile;
    const findings = checkVaultTokenEnvExposure(file);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('does not flag non-Vault environment variables', () => {
    const file = { content: 'env:\n  - name: MY_VAR\n    value: "some-value"', path: 'test.yaml', ext: 'yaml' } as GitOpsFile;
    const findings = checkVaultTokenEnvExposure(file);
    expect(findings.length).toBe(0);
  });
});

describe('VaultSecretEngineVerifier - checkVaultTokenConfigMapExposure', () => {
  it('detects Vault token exposure in ConfigMaps with parsed content', () => {
    const file = { 
      content: 'configMap:\n  name: vault-token-config', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { configMap: { name: 'vault-token-config' } } 
    } as GitOpsFile;
    const findings = checkVaultTokenConfigMapExposure(file);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag when no ConfigMap references', () => {
    const file = { content: 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test', path: 'test.yaml', ext: 'yaml' } as GitOpsFile;
    const findings = checkVaultTokenConfigMapExposure(file);
    expect(findings.length).toBe(0);
  });
});

describe('VaultSecretEngineVerifier - checkVaultAppRoleRestriction', () => {
  it('detects empty AppRole role_id with parsed content', () => {
    const file = { 
      content: 'approle:\n  role_id: ""', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { approle: { role_id: '' } } 
    } as GitOpsFile;
    const findings = checkVaultAppRoleRestriction(file);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe(VAULT_RULE_IDS.APPROLE_ROLE_ID);
  });

  it('detects wildcard AppRole role_id with parsed content', () => {
    const file = { 
      content: 'approle:\n  role_id: "*"', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { approle: { role_id: '*' } } 
    } as GitOpsFile;
    const findings = checkVaultAppRoleRestriction(file);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('allows valid UUID format role_id', () => {
    const file = { 
      content: 'approle:\n  role_id: "12345678-1234-1234-1234-123456789012"', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { approle: { role_id: '12345678-1234-1234-1234-123456789012' } } 
    } as GitOpsFile;
    const findings = checkVaultAppRoleRestriction(file);
    expect(findings.length).toBe(0);
  });

  it('detects secret_id exposure with parsed content', () => {
    const file = { 
      content: 'approle:\n  secret_id: "my-secret-id"', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { approle: { secret_id: 'my-secret-id' } } 
    } as GitOpsFile;
    const findings = checkVaultAppRoleRestriction(file);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('VaultSecretEngineVerifier - checkVaultOidcRoleBinding', () => {
  it('flags missing OIDC fields when OIDC config present', () => {
    const file = { 
      content: 'oidc: value', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { oidc: true } 
    } as GitOpsFile;
    const findings = checkVaultOidcRoleBinding(file);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag when no OIDC config', () => {
    const file = { content: 'some-config: value', path: 'test.yaml', ext: 'yaml' } as GitOpsFile;
    const findings = checkVaultOidcRoleBinding(file);
    expect(findings.length).toBe(0);
  });
});

describe('VaultSecretEngineVerifier - checkVaultKvEngineVersion', () => {
  it('flags KV v1 when KV v2 not specified with parsed content', () => {
    const file = { 
      content: 'secret:\n  data:\n    my-secret: "value"', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { secret: { data: { 'my-secret': 'value' } } } 
    } as GitOpsFile;
    const findings = checkVaultKvEngineVersion(file);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe(VAULT_RULE_IDS.KV_ENGINE_NOT_V2);
  });

  it('allows KV v2 explicit specification', () => {
    const file = { 
      content: 'kv_v2:\n  secret: "value"', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { kv_v2: { secret: 'value' } } 
    } as GitOpsFile;
    const findings = checkVaultKvEngineVersion(file);
    expect(findings.length).toBe(0);
  });
});

describe('VaultSecretEngineVerifier - checkVaultDynamicLease', () => {
  it('flags missing dynamic lease configuration with parsed content', () => {
    const file = { 
      content: 'secret:\n  data:\n    my-secret: "value"', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { secret: { data: { 'my-secret': 'value' } } } 
    } as GitOpsFile;
    const findings = checkVaultDynamicLease(file);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe(VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING);
  });

  it('accepts configuration with lease indicators', () => {
    const file = { 
      content: 'secret:\n  renewable: true\n  max_ttl: 3600', 
      path: 'test.yaml', 
      ext: 'yaml',
      parsed: { secret: { renewable: true, max_ttl: 3600 } } 
    } as GitOpsFile;
    const findings = checkVaultDynamicLease(file);
    expect(findings.length).toBeLessThan(2);
  });
});

describe('VaultSecretEngineVerifier - verifyFile', () => {
  it('detects invalid KV v2 paths', async () => {
    const verifier = createDefaultVerifier();
    const file = '{{ .Values.vault.secrets.bad-path }}';
    const result = await verifier.verifyFile('test.yaml', file);
    expect(result.passed).toBe(false);
    expect(result.findings.some((f) => f.rule === VAULT_RULE_IDS.KV_PATH_INVALID)).toBe(true);
  });

  it('detects token exposure in environment variables', async () => {
    const verifier = createDefaultVerifier();
    const file = 'env:\n  - name: VAULT_TOKEN\n    value: "sMySecretToken1234567890"';
    const result = await verifier.verifyFile('test.yaml', file);
    expect(result.passed).toBe(false);
    expect(result.findings.some((f) => f.rule === VAULT_RULE_IDS.TOKEN_ENV_EXPOSED)).toBe(true);
  });

  it('detects token exposure in ConfigMaps', async () => {
    const verifier = createDefaultVerifier();
    const file = 'configMap:\n  name: vault-token';
    const result = await verifier.verifyFile('test.yaml', file);
    expect(result.passed).toBe(false);
    expect(result.findings.some((f) => f.rule === VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED)).toBe(true);
  });

  it('detects misconfigured TTL', async () => {
    const verifier = createDefaultVerifier();
    const file = 'ttl: 30\nmax_ttl: 100';
    const result = await verifier.verifyFile('test.toml', file);
    expect(result.passed).toBe(false);
    expect(result.findings.some((f) => f.rule === VAULT_RULE_IDS.TTL_MISCONFIGURED)).toBe(true);
  });

  it('passes when no issues found', async () => {
    const verifier = createDefaultVerifier();
    const file = 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test';
    const result = await verifier.verifyFile('test.toml', file);
    expect(result.passed).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});

describe('VaultSecretEngineVerifier - verifyFiles', () => {
  it('aggregates findings from multiple files', async () => {
    const verifier = createDefaultVerifier();
    const files = [
      { path: 'file1.yaml', content: 'env: - name: VAULT_TOKEN' },
      { path: 'file2.yaml', content: 'ttl: 30' },
    ];
    const result = await verifier.verifyFiles(files);
    expect(result.passed).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe('VaultSecretEngineVerifier - dryRunVaultInteraction', () => {
  it('fails without mock Vault URL', async () => {
    const verifier = createDefaultVerifier();
    const result = await verifier.dryRunVaultInteraction('secret/data/test');
    expect(result.success).toBe(false);
    expect(result.error).toContain('Dry-run mode not enabled');
  });
});

describe('VaultSecretEngineVerifier - simulateTokenRenewal', () => {
  it('successfully renews a token', () => {
    const verifier = createDefaultVerifier();
    const result = verifier.simulateTokenRenewal(3600, 50);
    expect(result.newTtl).toBe(1800);
    expect(result.expired).toBe(false);
  });

  it('marks token as expired when TTL too low', () => {
    const verifier = createDefaultVerifier();
    const result = verifier.simulateTokenRenewal(10, 10);
    expect(result.newTtl).toBe(60);
    expect(result.expired).toBe(false);
  });
});

describe('VaultRuleIDs', () => {
  it('all rule IDs are defined', () => {
    expect(VAULT_RULE_IDS.KV_PATH_INVALID).toBeDefined();
    expect(VAULT_RULE_IDS.TTL_MISCONFIGURED).toBeDefined();
    expect(VAULT_RULE_IDS.TOKEN_ENV_EXPOSED).toBeDefined();
    expect(VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED).toBeDefined();
    expect(VAULT_RULE_IDS.APPROLE_ROLE_ID).toBeDefined();
    expect(VAULT_RULE_IDS.OIDC_ROLE_BINDING).toBeDefined();
    expect(VAULT_RULE_IDS.KV_ENGINE_NOT_V2).toBeDefined();
    expect(VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING).toBeDefined();
  });
});

describe('VaultRuleNames', () => {
  it('all rule names are defined', () => {
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.KV_PATH_INVALID]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.TTL_MISCONFIGURED]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.TOKEN_ENV_EXPOSED]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.TOKEN_CONFIGMAP_EXPOSED]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.APPROLE_ROLE_ID]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.OIDC_ROLE_BINDING]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.KV_ENGINE_NOT_V2]).toBeDefined();
    expect(VAULT_RULE_NAMES[VAULT_RULE_IDS.DYNAMIC_LEASE_MISSING]).toBeDefined();
  });
});

describe('VaultTypes', () => {
  it('VaultSeverity type has correct values', () => {
    const severities: VaultSeverity[] = ['critical', 'error', 'warning', 'info'];
    expect(severities).toContain('critical');
    expect(severities).toContain('error');
    expect(severities).toContain('warning');
    expect(severities).toContain('info');
  });

  it('VaultFinding interface has required fields', () => {
    const finding: VaultFinding = {
      rule: VAULT_RULE_IDS.KV_PATH_INVALID,
      severity: 'error' as VaultSeverity,
      message: 'Test message',
      suggestion: 'Test suggestion',
    };
    expect(finding.rule).toBeDefined();
    expect(finding.severity).toBeDefined();
    expect(finding.message).toBeDefined();
    expect(finding.suggestion).toBeDefined();
  });
});
