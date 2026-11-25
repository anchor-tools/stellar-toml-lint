import { describe, expect, it } from 'vitest';
import { StrKey } from '@stellar/stellar-base';
import {
  checkSecrets,
  maskSecret,
  renderSecretReport,
  scanSecrets,
  secretDetectorRuleIds,
  SECURITY_SECRET_HIGH_ENTROPY,
  SECURITY_SECRET_STELLAR_SEED,
  shannonEntropy,
} from '../src/security/secretDetector.js';

// Deterministic, checksum-valid fixtures generated with @stellar/stellar-base.
const SEED = StrKey.encodeEd25519SecretSeed(Buffer.alloc(32, 7));
const PUBLIC_G = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1));
const PUBLIC_C = StrKey.encodeContract(Buffer.alloc(32, 2));
const AWS_KEY = 'AKIA3ZQ7XMP2K9WTL4HD';
const GH_TOKEN = 'ghp_aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4';
const BEARER = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ1234567890';
const HIGH_ENTROPY = 'h8Kp2Qv9Zx4Lm7Nb3Rf6Tg1Yw5Uj8Cs0';

describe('secret detector', () => {
  it('computes Shannon entropy', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
  });

  it('masks values without echoing them', () => {
    expect(maskSecret(SEED)).toBe('SADQ...54X');
    expect(maskSecret('short')).toBe('[REDACTED]');
  });

  it('registers rule ids', () => {
    expect(secretDetectorRuleIds).toContain(SECURITY_SECRET_STELLAR_SEED);
    expect(secretDetectorRuleIds).toContain(SECURITY_SECRET_HIGH_ENTROPY);
  });

  it('finds a Stellar seed in a value and in a comment, redacted', () => {
    const source = `SIGNING_KEY = "${SEED}" # backup seed: ${SEED}\n`;
    const result = scanSecrets(source, { SIGNING_KEY: SEED });
    expect(result.halt).toBe(true);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0]?.masked).toBe(maskSecret(SEED));
    expect(result.findings[0]?.position).toEqual({ line: 1, column: 16 });
    expect(result.redactedSource).not.toContain(SEED);
    expect(result.redactedSource).toContain(maskSecret(SEED));
  });

  it('passes public keys, contract ids and dummy seeds', () => {
    const source = [
      `ACCOUNTS = ["${PUBLIC_G}"]`,
      `WEB_AUTH_CONTRACT_ID = "${PUBLIC_C}"`,
      `SIGNING_KEY = "S${'A'.repeat(54)}Z"`,
      'api_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
      'DUMMY_KEY = "AKIAIOSFODNN7EXAMPLE"',
    ].join('\n');
    const result = scanSecrets(source);
    expect(result.findings).toEqual([]);
    expect(result.halt).toBe(false);
  });

  it('detects AWS, GitHub, bearer and PEM credentials', () => {
    const source = [
      `AWS_ACCESS_KEY_ID = "${AWS_KEY}"`,
      `github_token = "${GH_TOKEN}"`,
      `Authorization = "Bearer ${BEARER}"`,
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIBOgIBAAJBALk9Zx2Qv8Tn4Ms7Yb1Rf6Hg3Wj0Cp5Dn2Sa7Fq9Lm4Kt8Xz',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');
    const kinds = scanSecrets(source).findings.map((finding) => finding.kind);
    expect(kinds).toContain('aws-access-key');
    expect(kinds).toContain('github-token');
    expect(kinds).toContain('bearer-token');
    expect(kinds).toContain('private-key');
  });

  it('scans repeated PEM BEGIN markers in linear time', () => {
    // The old PEM regex backtracked across every BEGIN marker when no END
    // followed (CodeQL js/polynomial-redos). Unclosed markers are not secrets.
    const source = '-----BEGIN DSA PRIVATE KEY-----\n'.repeat(1000);
    const result = scanSecrets(source);
    expect(result.findings).toEqual([]);
    expect(result.halt).toBe(false);
  });

  it('finds high-entropy values only in sensitive contexts', () => {
    const withSecret = scanSecrets(`api_token = "${HIGH_ENTROPY}"`).findings;
    expect(withSecret.some((finding) => finding.kind === 'high-entropy')).toBe(true);

    const photoHash = 'a'.repeat(8) + 'b'.repeat(8) + 'c'.repeat(8) + '1'.repeat(8);
    const clean = scanSecrets(`id_photo_hash = "${photoHash}"`).findings;
    expect(clean).toEqual([]);
  });

  it('scans parsed values that are not visible in the raw source', () => {
    const doc = { api_token: HIGH_ENTROPY, DOCUMENTATION: { ORG_DESCRIPTION: 'hello' } };
    const result = scanSecrets('VERSION = "2"', doc);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.path).toBe('api_token');
  });

  it('emits masked diagnostics and honours --off overrides', () => {
    const source = `SIGNING_KEY = "${SEED}"`;
    const diagnostics = checkSecrets(source);
    expect(diagnostics[0]).toMatchObject({ severity: 'error', category: 'security' });
    expect(JSON.stringify(diagnostics)).not.toContain(SEED);
    expect(
      checkSecrets(source, undefined, { rules: { [SECURITY_SECRET_STELLAR_SEED]: 'off' } }),
    ).toEqual([]);
  });

  it('renders a masked report', () => {
    const result = scanSecrets(`api_token = "${HIGH_ENTROPY}"`);
    const report = renderSecretReport(result);
    expect(report).toContain('CREDENTIALS DETECTED');
    expect(report).not.toContain(HIGH_ENTROPY);
    expect(renderSecretReport(scanSecrets('VERSION = "2"'))).toContain('no credentials');
  });
});
