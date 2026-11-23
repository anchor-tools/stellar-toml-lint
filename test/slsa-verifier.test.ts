import { createHash, generateKeyPairSync, sign as signBytes, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import {
  SlsaProvenanceError,
  SlsaProvenanceVerifier,
  certificateChainTrusted,
  dssePae,
  normalizeProvenance,
  parseProvenanceDocuments,
  renderProvenanceReport,
  verifyEnvelopeSignature,
  verifySlsaProvenance,
  type DsseEnvelope,
} from '../src/gitops/slsaVerifier.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string =>
  readFileSync(join(here, 'fixtures', 'gitops', 'slsa', name), 'utf8');

const artifact = new Uint8Array(
  readFileSync(join(here, 'fixtures', 'gitops', 'slsa', 'artifact.txt')),
);
const otherArtifact = new Uint8Array(
  readFileSync(join(here, 'fixtures', 'gitops', 'slsa', 'artifact-other.txt')),
);

const valid = fixture('attestation.intoto.jsonl');
const chainAttestation = fixture('attestation-chain.intoto.jsonl');
const caPem = fixture('ca.pem');
const leafPem = fixture('leaf.pem');
const tampered = fixture('attestation-tampered.intoto.jsonl');
const unsigned = fixture('attestation-unsigned.intoto.jsonl');
const publicKeyBundle = fixture('attestation-public-key.json');
const certPem = fixture('cert.pem');
const publicKeyPem = fixture('public.pem');
const certificateFingerprint = createHash('sha256')
  .update(new X509Certificate(certPem).raw)
  .digest('hex');

const EXPECTED_COMMIT = '9f2c4fd3a1b7e5d80c6a2b4e7f9012345678abcd';
const EXPECTED_REPOSITORY = 'https://github.com/anchor-tools/stellar-toml-lint';

const codes = (report: ReturnType<typeof verifySlsaProvenance>): string[] =>
  report.findings.map((finding) => finding.code);

describe('DSSE and provenance parsing', () => {
  it('encodes the DSSE pre-authentication encoding', () => {
    expect(dssePae('t', Buffer.from('x')).toString('utf8')).toBe('DSSEv1 1 t 1 x');
  });

  it('parses a Sigstore bundle and an unsigned in-toto statement', () => {
    expect(parseProvenanceDocuments(valid)[0]?.format).toBe('sigstore-bundle');
    expect(parseProvenanceDocuments(unsigned)[0]?.format).toBe('in-toto-statement');
    expect(parseProvenanceDocuments(`[${unsigned.trim()}]`)).toHaveLength(1);
  });

  it('selects the attestation whose subject matches the artifact in a JSONL file', () => {
    const statement = JSON.parse(unsigned) as Record<string, unknown>;
    const other = {
      ...statement,
      subject: [{ name: 'other.tgz', digest: { sha256: '1'.repeat(64) } }],
    };
    const documents = parseProvenanceDocuments(
      `${JSON.stringify(other)}\n${JSON.stringify(statement)}`,
    );
    const report = verifySlsaProvenance(
      artifact,
      `${JSON.stringify(other)}\n${JSON.stringify(statement)}`,
    );
    expect(documents).toHaveLength(2);
    expect(report.attestation.subjectDigests.sha256).toBe(
      createHash('sha256').update(artifact).digest('hex'),
    );
  });

  it('rejects malformed and non-provenance documents', () => {
    expect(() => parseProvenanceDocuments('')).toThrow(SlsaProvenanceError);
    expect(() => parseProvenanceDocuments('{not json}')).toThrow(/not valid JSON/);
    expect(() => parseProvenanceDocuments('{"hello":"world"}')).toThrow(/No in-toto statement/);
  });

  it('normalizes a legacy SLSA v0.2 predicate', () => {
    const normalized = normalizeProvenance({
      predicateType: 'https://slsa.dev/provenance/v0.2',
      predicate: {
        buildType: 'https://github.com/slsa-framework/slsa-github-generator@v1',
        builder: { id: 'https://github.com/slsa-framework/slsa-github-generator' },
        invocation: {
          configSource: {
            uri: 'git+https://github.com/org/repo@refs/tags/v1',
            entryPoint: '.github/workflows/release.yml',
          },
          parameters: { event_name: 'release' },
        },
        materials: [
          {
            uri: 'git+https://github.com/org/repo@refs/tags/v1',
            digest: { sha1: EXPECTED_COMMIT },
          },
        ],
      },
    });
    expect(normalized?.sourceRepository).toBe('github.com/org/repo');
    expect(normalized?.sourceCommit).toBe(EXPECTED_COMMIT);
    expect(normalized?.workflowTrigger).toBe('release');
    expect(normalized?.workflowPath).toBe('.github/workflows/release.yml');
  });
});

describe('SlsaProvenanceVerifier', () => {
  it('verifies a signed bundle against a pinned certificate and awards SLSA level 3', () => {
    const report = verifySlsaProvenance(artifact, valid, {
      artifactName: 'artifact.txt',
      trustedCertificateSha256: [certificateFingerprint],
      expectedBuilderId: 'https://github.com/actions/runner/github-hosted',
      expectedSourceRepository: EXPECTED_REPOSITORY,
      expectedCommitSha: EXPECTED_COMMIT,
      expectedWorkflowTrigger: 'push',
      requiredLevel: 3,
    });

    expect(report.ok).toBe(true);
    expect(report.level).toBe(3);
    expect(report.requiredLevel).toBe(3);
    expect(report.format).toBe('sigstore-bundle');
    expect(report.signature.verified).toBe(true);
    expect(report.signature.trusted).toBe(true);
    expect(report.signature.certificateValid).toBe(true);
    expect(report.signature.certificateSubject).toContain('fixture-builder');
    expect(report.attestation.digestMatches).toBe(true);
    expect(report.attestation.builderId).toBe('https://github.com/actions/runner/github-hosted');
    expect(report.attestation.sourceRepository).toBe('github.com/anchor-tools/stellar-toml-lint');
    expect(report.attestation.controls).toContain('SLSA_L3_TRUSTED_BUILDER');
    expect(report.findings).toEqual([]);
  });

  it('verifies a bundle whose signer is pinned by public key', () => {
    const report = verifySlsaProvenance(artifact, publicKeyBundle, {
      trustedPublicKeys: [publicKeyPem],
      requiredLevel: 3,
    });
    expect(report.signature.verified).toBe(true);
    expect(report.signature.trusted).toBe(true);
    expect(report.level).toBe(3);
    expect(report.ok).toBe(true);
  });

  it('trusts a bundle whose chain terminates in a pinned root CA', () => {
    const report = verifySlsaProvenance(artifact, chainAttestation, {
      trustedRootCertificates: [caPem],
      requiredLevel: 3,
    });
    expect(report.signature.verified).toBe(true);
    expect(report.signature.trusted).toBe(true);
    expect(report.level).toBe(3);
    expect(report.ok).toBe(true);
  });

  it('does not trust a chain that terminates elsewhere', () => {
    expect(
      certificateChainTrusted([new X509Certificate(leafPem)], [new X509Certificate(caPem)]),
    ).toBe(true);
    expect(
      certificateChainTrusted([new X509Certificate(certPem)], [new X509Certificate(caPem)]),
    ).toBe(false);

    const report = verifySlsaProvenance(artifact, valid, {
      trustedRootCertificates: [caPem],
      requiredLevel: 3,
    });
    expect(report.signature.verified).toBe(true);
    expect(report.signature.trusted).toBe(false);
    expect(report.level).toBe(2);
    expect(
      report.findings.find((finding) => finding.code === 'provenance/untrusted-signer')?.severity,
    ).toBe('error');
  });

  it('caps an untrusted signer at level 2 instead of claiming level 3', () => {
    const report = verifySlsaProvenance(artifact, valid, { requiredLevel: 3 });
    expect(report.signature.verified).toBe(true);
    expect(report.signature.trusted).toBe(false);
    expect(report.level).toBe(2);
    expect(codes(report)).toContain('provenance/trust-root-unconfigured');
    expect(codes(report)).toContain('provenance/level-below-required');
    expect(report.ok).toBe(false);
  });

  it('rejects a tampered attestation whose signature no longer matches', () => {
    const report = verifySlsaProvenance(artifact, tampered);
    expect(report.signature.verified).toBe(false);
    expect(report.signature.trusted).toBe(false);
    expect(report.level).toBe(0);
    expect(report.ok).toBe(false);
    expect(codes(report)).toContain('provenance/signature-invalid');
    expect(codes(report)).toContain('provenance/digest-mismatch');
    expect(report.attestation.digestMatches).toBe(false);
    expect(report.attestation.controls).toEqual(['SLSA_L0_NONE']);
  });

  it('rejects a valid attestation presented for a different artifact', () => {
    const report = verifySlsaProvenance(otherArtifact, valid, {
      trustedCertificateSha256: [certificateFingerprint],
    });
    expect(report.signature.verified).toBe(true);
    expect(report.attestation.digestMatches).toBe(false);
    expect(report.level).toBe(0);
    expect(report.ok).toBe(false);
    expect(codes(report)).toContain('provenance/digest-mismatch');
  });

  it('accepts an unsigned statement only at level 1', () => {
    const report = verifySlsaProvenance(artifact, unsigned);
    expect(report.format).toBe('in-toto-statement');
    expect(report.signature.method).toBe('none');
    expect(report.level).toBe(1);
    expect(report.ok).toBe(true);
    expect(codes(report)).toContain('provenance/signature-missing');
  });

  it('enforces expected builder, repository, commit, and trigger', () => {
    const report = verifySlsaProvenance(artifact, valid, {
      trustedCertificateSha256: [certificateFingerprint],
      expectedBuilderId: 'https://evil.example/builder',
      expectedSourceRepository: 'https://github.com/attacker/fork',
      expectedCommitSha: 'f'.repeat(40),
      expectedWorkflowTrigger: 'pull_request',
    });
    expect(report.ok).toBe(false);
    expect(codes(report)).toEqual(
      expect.arrayContaining([
        'provenance/builder-mismatch',
        'provenance/source-mismatch',
        'provenance/commit-mismatch',
        'provenance/trigger-mismatch',
      ]),
    );
  });

  it('warns when the attestation binds no subject', () => {
    const report = verifySlsaProvenance(
      artifact,
      JSON.stringify({
        _type: 'https://in-toto.io/Statement/v1',
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: { buildType: 'x', builder: { id: 'y' } },
      }),
    );
    expect(codes(report)).toContain('provenance/subject-missing');
    expect(codes(report)).toContain('provenance/digest-mismatch');
  });

  it('reports a missing SLSA predicate rather than throwing', () => {
    const report = verifySlsaProvenance(
      artifact,
      JSON.stringify({
        _type: 'https://in-toto.io/Statement/v1',
        predicateType: 'https://example.com/custom/v1',
        predicate: {},
      }),
    );
    expect(report.level).toBe(0);
    expect(report.ok).toBe(false);
    expect(codes(report)).toContain('provenance/predicate-unrecognised');
    expect(codes(report)).toContain('provenance/missing');
  });

  it('rejects a bundle with no verification material', () => {
    const bundle = JSON.parse(valid) as Record<string, unknown>;
    delete bundle['verificationMaterial'];
    const report = verifySlsaProvenance(artifact, JSON.stringify(bundle));
    expect(report.signature.verified).toBe(false);
    expect(report.signature.error).toContain('No verification material');
    expect(report.level).toBe(0);
    expect(codes(report)).toContain('provenance/signature-invalid');
  });

  it('is usable through the class API with an injected artifact name', () => {
    const report = new SlsaProvenanceVerifier().verify(artifact, valid, {
      artifactName: 'artifact.txt',
      trustedCertificateSha256: [certificateFingerprint.toUpperCase().replace(/(..)/g, '$1:')],
    });
    expect(report.artifact.name).toBe('artifact.txt');
    expect(report.signature.trusted).toBe(true);
  });
});

describe('cryptographic signature assertions', () => {
  const payloadBytes = Buffer.from(
    JSON.stringify({ predicateType: 'https://slsa.dev/provenance/v1' }),
  );
  const pae = dssePae('application/vnd.in-toto+json', payloadBytes);

  function envelope(signature: string, keyid = ''): DsseEnvelope {
    return {
      payloadType: 'application/vnd.in-toto+json',
      payload: payloadBytes.toString('base64'),
      signatures: [{ keyid, sig: signature }],
    };
  }

  it('verifies an RSA/SHA-256 signature against a pinned key', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const signature = signBytes('sha256', pae, privateKey).toString('base64');
    const result = verifyEnvelopeSignature(envelope(signature), undefined, {
      trustedPublicKeys: [publicKey.export({ type: 'spki', format: 'pem' }).toString()],
    });
    expect(result.verified).toBe(true);
    expect(result.trusted).toBe(true);
    expect(result.method).toBe('dsse');
  });

  it('accepts a PEM public key carried in the DSSE keyid', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const signature = signBytes(null, pae, privateKey).toString('base64');
    const result = verifyEnvelopeSignature(envelope(signature, pem), undefined);
    expect(result.verified).toBe(true);
    expect(result.trusted).toBe(false);
  });

  it('reports an envelope with no signatures', () => {
    const result = verifyEnvelopeSignature(
      { payloadType: 'application/vnd.in-toto+json', payload: 'e30=', signatures: [] },
      undefined,
    );
    expect(result.verified).toBe(false);
    expect(result.error).toContain('no signatures');
  });

  it('rejects a signature made over a different payload', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const signature = signBytes(null, pae, privateKey).toString('base64');
    const tamperedEnvelope = envelope(signature);
    tamperedEnvelope.payload = Buffer.from(
      '{"predicateType":"https://slsa.dev/provenance/v0.2"}',
    ).toString('base64');
    const result = verifyEnvelopeSignature(tamperedEnvelope, undefined, {
      trustedPublicKeys: [publicKey.export({ type: 'spki', format: 'pem' }).toString()],
    });
    expect(result.verified).toBe(false);
    expect(result.error).toContain('does not verify');
  });

  it('exposes the key id on the verification result', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const signature = signBytes(null, pae, privateKey).toString('base64');
    const result = verifyEnvelopeSignature(envelope(signature, 'builder-key-1'), undefined, {
      trustedPublicKeys: [publicKey.export({ type: 'spki', format: 'pem' }).toString()],
    });
    expect(result.keyId).toBe('builder-key-1');
    expect(result.verified).toBe(true);
  });

  it('flags an expired signing certificate and caps the level at 2', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2050-01-01T00:00:00Z'));
    try {
      const report = verifySlsaProvenance(artifact, valid, {
        trustedCertificateSha256: [certificateFingerprint],
        requiredLevel: 3,
      });
      expect(report.signature.verified).toBe(true);
      expect(report.signature.certificateValid).toBe(false);
      expect(report.level).toBe(2);
      expect(codes(report)).toContain('provenance/certificate-expired');
    } finally {
      vi.useRealTimers();
    }
  });

  it('distrusts a signer when configured fingerprints do not match', () => {
    const report = verifySlsaProvenance(artifact, valid, {
      trustedCertificateSha256: ['00'.repeat(32)],
    });
    expect(report.signature.verified).toBe(true);
    expect(report.signature.trusted).toBe(false);
    expect(
      report.findings.find((finding) => finding.code === 'provenance/untrusted-signer')?.severity,
    ).toBe('error');
  });
});

describe('renderProvenanceReport', () => {
  it('renders the level, signer state, source, and verdict', () => {
    const report = verifySlsaProvenance(artifact, valid, {
      artifactName: 'artifact.txt',
      trustedCertificateSha256: [certificateFingerprint],
      requiredLevel: 3,
    });
    const text = renderProvenanceReport(report);
    expect(text).toContain('SLSA provenance verification — artifact.txt');
    expect(text).toContain('slsa level: 3');
    expect(text).toContain('signer trusted');
    expect(text).toContain('github.com/anchor-tools/stellar-toml-lint');
    expect(text).toContain('Result: pass');

    const failing = renderProvenanceReport(verifySlsaProvenance(artifact, tampered));
    expect(failing).toContain('Result: fail');
    expect(failing).toContain('provenance/signature-invalid');
  });
});
