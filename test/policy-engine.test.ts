import { describe, it, expect } from 'vitest';
import {
  loadPolicy,
  validatePolicy,
  evaluatePolicy,
  createSamplePolicy,
  type Policy,
} from '../src/policy/engine.js';

describe('Policy Engine', () => {
  const sampleToml = {
    VERSION: '2.0.0',
    NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
    DOCUMENTATION: {
      ORG_NAME: 'Test Anchor',
      ORG_URL: 'https://example.com',
      ORG_OFFICIAL_EMAIL: 'contact@example.com',
      ORG_GITHUB: 'testanchor',
    },
    SIGNING_KEY: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    SERVERS: [
      {
        WEB_AUTH_ENDPOINT: 'https://auth.example.com',
        TRANSFER_SERVER: 'https://transfer.example.com',
        KYC_SERVER: 'https://kyc.example.com',
      },
    ],
    CURRENCIES: [
      {
        code: 'USDC',
        issuer: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        status: 'test',
        display_decimals: 2,
        regulated: true,
      },
      {
        code: 'EURC',
        issuer: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        status: 'live',
        display_decimals: 2,
      },
    ],
    VALIDATORS: [
      {
        ALIAS: 'validator1',
        PUBLIC_KEY: 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
        HOST: 'validator1.example.com:11625',
      },
      {
        ALIAS: 'validator2',
        PUBLIC_KEY: 'GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
        HOST: 'validator2.example.com:11625',
      },
    ],
  };

  const sampleSource = `VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
DOCUMENTATION = { ORG_NAME = "Test Anchor", ORG_URL = "https://example.com", ORG_OFFICIAL_EMAIL = "contact@example.com", ORG_GITHUB = "testanchor" }
SIGNING_KEY = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
SERVERS = [{ WEB_AUTH_ENDPOINT = "https://auth.example.com", TRANSFER_SERVER = "https://transfer.example.com", KYC_SERVER = "https://kyc.example.com" }]
CURRENCIES = [{ code = "USDC", issuer = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", status = "test", display_decimals = 2, regulated = true }, { code = "EURC", issuer = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", status = "live", display_decimals = 2 }]
VALIDATORS = [{ ALIAS = "validator1", PUBLIC_KEY = "GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", HOST = "validator1.example.com:11625" }, { ALIAS = "validator2", PUBLIC_KEY = "GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", HOST = "validator2.example.com:11625" }]`;

  it('creates a valid sample policy', () => {
    const policy = createSamplePolicy();
    expect(policy.version).toBe('1.0');
    expect(policy.name).toBe('enterprise-compliance');
    expect(policy.rules.length).toBeGreaterThan(0);
  });

  it('validates a correct policy', () => {
    const policy = createSamplePolicy();
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects policy without version', () => {
    const policy = createSamplePolicy();
    delete (policy as Partial<Policy>).version;
    const result = validatePolicy(policy as Policy);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Policy must have a version');
  });

  it('rejects policy without name', () => {
    const policy = createSamplePolicy();
    delete (policy as Partial<Policy>).name;
    const result = validatePolicy(policy as Policy);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Policy must have a name');
  });

  it('rejects policy without rules', () => {
    const policy = createSamplePolicy();
    (policy as Policy).rules = [];
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
  });

  it('evaluates kyc-required rule (should pass with KYC_SERVER)', () => {
    const policy = createSamplePolicy();
    const diagnostics = evaluatePolicy(policy, sampleToml, sampleSource);
    const kycRule = diagnostics.find((d) => d.rule === 'kyc-required');
    expect(kycRule).toBeUndefined();
  });

  it('evaluates signing-key-exists rule (should pass with key)', () => {
    const policy = createSamplePolicy();
    const diagnostics = evaluatePolicy(policy, sampleToml, sampleSource);
    const keyRule = diagnostics.find((d) => d.rule === 'signing-key-exists');
    expect(keyRule).toBeUndefined();
  });

  it('evaluates org-documentation-exists rule (should pass)', () => {
    const policy = createSamplePolicy();
    const diagnostics = evaluatePolicy(policy, sampleToml, sampleSource);
    const docRule = diagnostics.find((d) => d.rule === 'org-documentation-exists');
    expect(docRule).toBeUndefined();
  });

  it('fails org-documentation-exists when missing', () => {
    const policy = createSamplePolicy();
    const { DOCUMENTATION, ...incompleteToml } = sampleToml;
    void DOCUMENTATION;
    const diagnostics = evaluatePolicy(policy, incompleteToml, sampleSource);
    const docRule = diagnostics.find((d) => d.rule === 'org-documentation-exists');
    expect(docRule).toBeDefined();
    expect(docRule?.severity).toBe('warning');
  });

  it('fails signing-key-exists when SIGNING_KEY missing', () => {
    const policy = createSamplePolicy();
    const { SIGNING_KEY, ...noKeyToml } = sampleToml;
    void SIGNING_KEY;
    const diagnostics = evaluatePolicy(policy, noKeyToml, sampleSource);
    const keyRule = diagnostics.find((d) => d.rule === 'signing-key-exists');
    expect(keyRule).toBeDefined();
    expect(keyRule?.severity).toBe('error');
  });

  it('loads JSON policy from file', async () => {
    const policy = createSamplePolicy();
    const json = JSON.stringify(policy, null, 2);
    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const tmpPath = path.join(os.tmpdir(), 'test-policy.json');
    await fs.writeFile(tmpPath, json);

    const loaded = await loadPolicy(tmpPath);
    expect(loaded.name).toBe('enterprise-compliance');
    expect(loaded.rules.length).toBe(policy.rules.length);
  });
});
