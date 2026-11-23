import { describe, expect, it } from 'vitest';
import { DidResolutionVerifier, decodeBase58, encodeBase58 } from '../../src/crypto/didVerifier.js';

describe('DidResolutionVerifier', () => {
  it('encodes and decodes base58 accurately', () => {
    const data = new Uint8Array([0, 1, 2, 3, 255, 128, 64]);
    const encoded = encodeBase58(data);
    const decoded = decodeBase58(encoded);
    expect(decoded).toEqual(data);
  });

  it('resolves and validates did:key with Ed25519 multicodec', async () => {
    // Generate valid 32-byte Ed25519 pubkey
    const pubKeyBytes = new Uint8Array(32).fill(7);
    // Multicodec prefix for ed25519-pub is 0xed, 0x01 (varint 0xed01)
    const multicodec = new Uint8Array(34);
    multicodec[0] = 0xed;
    multicodec[1] = 0x01;
    multicodec.set(pubKeyBytes, 2);

    const base58Key = 'z' + encodeBase58(multicodec);
    const didUri = `did:key:${base58Key}`;

    const verifier = new DidResolutionVerifier();
    const resolution = await verifier.resolveDid(didUri);

    expect(resolution.resolved).toBe(true);
    expect(resolution.didDocument?.id).toBe(didUri);
    expect(resolution.verificationMethods.length).toBeGreaterThanOrEqual(1);
    expect(resolution.verificationMethods[0]?.type).toBe('Ed25519VerificationKey2020');
  });

  it('validates Verifiable Credential integrity and expiration', async () => {
    const verifier = new DidResolutionVerifier();

    const expiredVc = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'urn:uuid:credential-1',
      type: ['VerifiableCredential', 'AnchorAccreditation'],
      issuer: 'did:web:accredited.stellar.org',
      issuanceDate: '2023-01-01T00:00:00Z',
      expirationDate: '2023-06-01T00:00:00Z',
      credentialSubject: {
        id: 'did:web:anchor.example.com',
        complianceStatus: 'APPROVED',
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: '2023-01-01T00:00:00Z',
        verificationMethod: 'did:web:accredited.stellar.org#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'z3...mockProofValue',
      },
    };

    const result = await verifier.verifyCredential(expiredVc);
    expect(result.valid).toBe(false);
    expect(result.errors.some((err) => err.includes('expired'))).toBe(true);
  });

  it('audits stellar.toml DID declarations', async () => {
    const verifier = new DidResolutionVerifier();
    const tomlData = {
      ORGANIZATION: {
        NAME: 'Stellar Anchor Inc',
        DID: 'did:invalid:scheme',
      },
    };

    const audit = await verifier.auditTomlDids(tomlData);
    expect(audit.compliant).toBe(false);
    expect(audit.summary).toContain('did:invalid:scheme');
  });
});
