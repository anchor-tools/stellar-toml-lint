import { describe, expect, it } from 'vitest';
import { HashAgilityAuditor } from '../../src/crypto/hashAgilityAuditor.js';

describe('HashAgilityAuditor', () => {
  it('classifies hashes accurately by bit length and encoding', () => {
    // MD5 128-bit
    const md5Hex = 'd41d8cd98f00b204e9800998ecf8427e';
    expect(HashAgilityAuditor.classifyHash(md5Hex)).toEqual({
      algorithm: 'MD5',
      bitLength: 128,
      encoding: 'hex',
    });

    // SHA-1 160-bit
    const sha1Hex = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
    expect(HashAgilityAuditor.classifyHash(sha1Hex)).toEqual({
      algorithm: 'SHA-1',
      bitLength: 160,
      encoding: 'hex',
    });

    // SHA-256 256-bit
    const sha256Hex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(HashAgilityAuditor.classifyHash(sha256Hex)).toEqual({
      algorithm: 'SHA-256',
      bitLength: 256,
      encoding: 'hex',
    });
  });

  it('computes sha256 and sha512 upgrades', () => {
    const text = 'test-input-string';
    const sha256Hash = HashAgilityAuditor.computeSha256(text);
    const sha512Hash = HashAgilityAuditor.computeSha512(text);

    expect(sha256Hash.length).toBe(64);
    expect(sha512Hash.length).toBe(128);
  });

  it('detects deprecated hashes and flags insecure rating', () => {
    const tomlWithMd5 = {
      DOCUMENTATION: {
        ORG_NAME: 'Anchor Corp',
        DOCUMENTATION_HASH: 'd41d8cd98f00b204e9800998ecf8427e', // MD5
      },
    };

    const report = HashAgilityAuditor.audit(tomlWithMd5);
    expect(report.deprecatedCount).toBe(1);
    expect(report.securityRating).toBe('INSECURE');
    expect(report.inspections[0]?.isDeprecated).toBe(true);
    expect(report.inspections[0]?.detectedAlgorithm).toBe('MD5');
  });

  it('passes compliant modern SHA-256 digests', () => {
    const tomlWithSha256 = {
      DOCUMENTATION: {
        CODE_HASH: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ORG_LOGO_HASH: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      },
    };

    const report = HashAgilityAuditor.audit(tomlWithSha256);
    expect(report.compliantCount).toBe(2);
    expect(report.deprecatedCount).toBe(0);
    expect(report.securityRating).toBe('SECURE');
    expect(report.score).toBe(100);
  });
});
