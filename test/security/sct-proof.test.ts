import { describe, expect, it } from 'vitest';
import {
  CT_LOG_OPERATORS,
  SCT_EXTENSION_OID,
  SECURITY_MISSING_EMBEDDED_SCT,
  SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
  checkSctProof,
  decodeSctList,
  encodeOid,
  extractEmbeddedSctList,
  sctProofRules,
  verifySctProof,
} from '../../src/security/sct-proof-verifier.js';

/** DER TLV with a definite length, supporting the two short forms tests need. */
function der(tag: number, content: Uint8Array): Buffer {
  const length = content.length;
  const header =
    length < 0x80
      ? Buffer.from([tag, length])
      : length < 0x100
        ? Buffer.from([tag, 0x81, length])
        : Buffer.from([tag, 0x82, (length >> 8) & 0xff, length & 0xff]);
  return Buffer.concat([header, Buffer.from(content)]);
}

const asn1Oid = (value: string): Buffer => der(0x06, encodeOid(value));

/** A certificate-shaped DER carrying the given extensions. */
function certificate(extensions: Buffer[]): Buffer {
  const extensionsSequence = der(0x30, Buffer.concat(extensions));
  const explicit = der(0xa3, extensionsSequence);
  const tbsCertificate = der(0x30, Buffer.concat([der(0x02, Buffer.from([0x01])), explicit]));
  return der(0x30, Buffer.concat([tbsCertificate, der(0x30, Buffer.alloc(0))]));
}

function sctExtension(value: Uint8Array): Buffer {
  return der(0x30, Buffer.concat([asn1Oid(SCT_EXTENSION_OID), der(0x04, value)]));
}

function uint16(value: number): Buffer {
  return Buffer.from([(value >> 8) & 0xff, value & 0xff]);
}

function uint64(value: number): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

interface SctOptions {
  logId: string;
  version?: number;
  timestamp?: number;
  hashAlgorithm?: number;
  signatureAlgorithm?: number;
  signature?: Buffer;
  extensions?: Buffer;
  /** Overrides the declared signature length, for truncation cases. */
  declaredSignatureLength?: number;
}

/** One RFC 6962 SCT, ready to frame into a list. */
function sct(options: SctOptions): Buffer {
  const extensions = options.extensions ?? Buffer.alloc(0);
  const signature = options.signature ?? Buffer.alloc(64, 7);
  return Buffer.concat([
    Buffer.from([options.version ?? 0]),
    Buffer.from(options.logId, 'hex'),
    uint64(options.timestamp ?? 1_700_000_000_000),
    uint16(extensions.length),
    extensions,
    Buffer.from([options.hashAlgorithm ?? 4, options.signatureAlgorithm ?? 3]),
    uint16(options.declaredSignatureLength ?? signature.length),
    signature,
  ]);
}

/** The SignedCertificateTimestampList framing RFC 6962 requires. */
function sctList(entries: Buffer[]): Buffer {
  const framed = Buffer.concat(
    entries.map((entry) => Buffer.concat([uint16(entry.length), entry])),
  );
  return Buffer.concat([uint16(framed.length), framed]);
}

const GOOGLE = CT_LOG_OPERATORS.find((log) => log.operator === 'Google')?.logId as string;
const CLOUDFLARE = CT_LOG_OPERATORS.find((log) => log.operator === 'Cloudflare')?.logId as string;

describe('encodeOid', () => {
  it('encodes a multi-byte arc the way DER requires', () => {
    // 1.3.6.1.4.1.11129.2.4.2 -> the CT extension OID.
    expect(Buffer.from(encodeOid(SCT_EXTENSION_OID)).toString('hex')).toBe(
      '2b06010401d6790204 02'.replace(/\s/g, ''),
    );
  });

  it('rejects anything that is not a dotted OID', () => {
    expect(() => encodeOid('1')).toThrow();
    expect(() => encodeOid('1.2.x')).toThrow();
  });
});

describe('extractEmbeddedSctList', () => {
  it('finds the CT extension anywhere in the DER tree', () => {
    const list = sctList([sct({ logId: GOOGLE })]);
    const found = extractEmbeddedSctList(certificate([sctExtension(list)]));
    expect(found === undefined ? undefined : Buffer.from(found).toString('hex')).toBe(
      list.toString('hex'),
    );
  });

  it('returns undefined when the extension is absent', () => {
    expect(extractEmbeddedSctList(certificate([]))).toBeUndefined();
  });

  it('unwraps a doubly OCTET-STRING-wrapped extension value', () => {
    const list = sctList([sct({ logId: GOOGLE })]);
    const wrapped = Buffer.concat([Buffer.from([0x04, list.length]), list]);
    const found = extractEmbeddedSctList(certificate([sctExtension(wrapped)]));
    expect(found === undefined ? undefined : Buffer.from(found).toString('hex')).toBe(
      list.toString('hex'),
    );
  });
});

describe('decodeSctList', () => {
  it('decodes version, log id, timestamp, and signature', () => {
    const entries = decodeSctList(sctList([sct({ logId: GOOGLE, timestamp: 1_700_000_000_000 })]));
    expect(entries).toHaveLength(1);
    expect(entries?.[0]).toMatchObject({
      version: 0,
      logId: GOOGLE,
      timestamp: 1_700_000_000_000,
      hashAlgorithm: 4,
      signatureAlgorithm: 3,
    });
    expect(entries?.[0]?.signature).toHaveLength(64);
  });

  it('decodes an empty list as an empty array', () => {
    expect(decodeSctList(sctList([]))).toEqual([]);
  });

  it('returns undefined for truncated or over-long framings', () => {
    expect(decodeSctList(Buffer.from([0x00]))).toBeUndefined();
    expect(decodeSctList(Buffer.from([0x00, 0x10, 0x00, 0x02, 0x01]))).toBeUndefined();
    // An SCT shorter than its fixed 43-byte head.
    const tiny = decodeSctList(Buffer.concat([uint16(3), uint16(1), Buffer.from([0])]));
    expect(tiny).toBeUndefined();
  });

  it('returns undefined when the signature overruns the entry', () => {
    const entry = sct({ logId: GOOGLE, declaredSignatureLength: 1000 });
    expect(decodeSctList(sctList([entry]))).toBeUndefined();
  });
});

describe('verifySctProof', () => {
  it('passes a certificate with SCTs from two public CT logs', () => {
    const value = sctList([sct({ logId: GOOGLE }), sct({ logId: CLOUDFLARE })]);
    expect(verifySctProof(certificate([sctExtension(value)]))).toEqual([]);
  });

  it('passes a single recognised log certificate', () => {
    const value = sctList([sct({ logId: GOOGLE })]);
    expect(verifySctProof(certificate([sctExtension(value)]))).toEqual([]);
  });

  it('flags a certificate with no embedded SCT list', () => {
    const diagnostics = verifySctProof(certificate([]), { path: 'anchor.example.com' });
    expect(diagnostics).toEqual([
      expect.objectContaining({
        rule: SECURITY_MISSING_EMBEDDED_SCT,
        severity: 'warning',
        category: 'network',
        path: 'anchor.example.com',
      }),
    ]);
  });

  it('flags an SCT from an unrecognised log operator', () => {
    const value = sctList([sct({ logId: 'ab'.repeat(32) })]);
    const diagnostics = verifySctProof(certificate([sctExtension(value)]));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
      severity: 'error',
    });
    expect(diagnostics[0]?.message).toContain('unrecognised');
  });

  it('flags a malformed SCT list', () => {
    const malformed = Buffer.from([0x00, 0x10, 0x00, 0x02, 0x01]);
    const diagnostics = verifySctProof(certificate([sctExtension(malformed)]));
    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: SECURITY_UNTRUSTED_CT_LOG_SIGNATURE, severity: 'error' }),
    ]);
    expect(diagnostics[0]?.message).toContain('malformed');
  });

  it('flags a truncated signature and an unknown hash algorithm', () => {
    const truncated = sct({ logId: GOOGLE, declaredSignatureLength: 4096 });
    expect(verifySctProof(certificate([sctExtension(sctList([truncated]))]))[0]?.message).toContain(
      'malformed',
    );

    const weakHash = sct({ logId: GOOGLE, hashAlgorithm: 0 });
    const diagnostics = verifySctProof(certificate([sctExtension(sctList([weakHash]))]));
    expect(diagnostics[0]?.rule).toBe(SECURITY_UNTRUSTED_CT_LOG_SIGNATURE);

    const oddAlgorithm = sct({ logId: GOOGLE, signatureAlgorithm: 9 });
    expect(verifySctProof(certificate([sctExtension(sctList([oddAlgorithm]))]))[0]?.rule).toBe(
      SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
    );

    const emptySignature = sct({ logId: GOOGLE, signature: Buffer.alloc(0) });
    expect(verifySctProof(certificate([sctExtension(sctList([emptySignature]))]))[0]?.rule).toBe(
      SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
    );
  });

  it('accepts a caller-supplied private log registry', () => {
    const privateLog = 'cd'.repeat(32);
    const value = sctList([sct({ logId: privateLog })]);
    expect(
      verifySctProof(certificate([sctExtension(value)]), {
        knownLogs: [{ operator: 'Private CA', logId: privateLog }],
      }),
    ).toEqual([]);
  });

  it('honours --off and severity overrides', () => {
    expect(
      verifySctProof(certificate([]), {
        rules: { [SECURITY_MISSING_EMBEDDED_SCT]: 'off' },
      }),
    ).toEqual([]);

    expect(
      verifySctProof(certificate([]), {
        rules: {
          [SECURITY_MISSING_EMBEDDED_SCT]: 'error',
        },
      })[0]?.severity,
    ).toBe('error');

    const untrusted = sctList([sct({ logId: 'ef'.repeat(32) })]);
    expect(
      verifySctProof(certificate([sctExtension(untrusted)]), {
        rules: { [SECURITY_UNTRUSTED_CT_LOG_SIGNATURE]: 'off' },
      }),
    ).toEqual([]);
    expect(
      verifySctProof(certificate([sctExtension(untrusted)]), {
        rules: { [SECURITY_UNTRUSTED_CT_LOG_SIGNATURE]: 'warning' },
      })[0]?.severity,
    ).toBe('warning');
  });

  it('returns nothing at all when every rule is switched off', () => {
    expect(
      verifySctProof(certificate([]), {
        rules: {
          [SECURITY_MISSING_EMBEDDED_SCT]: 'off',
          [SECURITY_UNTRUSTED_CT_LOG_SIGNATURE]: 'off',
        },
      }),
    ).toEqual([]);
  });

  it('accepts a base64 certificate string', () => {
    const value = sctList([sct({ logId: GOOGLE })]);
    const base64 = certificate([sctExtension(value)]).toString('base64');
    expect(verifySctProof(base64)).toEqual([]);
  });
});

describe('checkSctProof', () => {
  const goodCertificate = certificate([
    sctExtension(sctList([sct({ logId: GOOGLE }), sct({ logId: CLOUDFLARE })])),
  ]);
  const bareCertificate = certificate([]);

  const doc = {
    WEB_AUTH_ENDPOINT: 'https://auth.example.com/auth',
    HORIZON_URL: 'https://horizon.example.com',
    DOCUMENTATION: { ORG_URL: 'https://anchor.example.com' },
  };

  it('probes every declared HTTPS host and reports by host', async () => {
    const probed: string[] = [];
    const probe = async (host: string): Promise<Uint8Array | null> => {
      probed.push(host);
      return host === 'auth.example.com' ? bareCertificate : goodCertificate;
    };

    const diagnostics = await checkSctProof(doc, { probe });
    expect(probed.sort()).toEqual([
      'anchor.example.com',
      'auth.example.com',
      'horizon.example.com',
    ]);
    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: SECURITY_MISSING_EMBEDDED_SCT, path: 'auth.example.com' }),
    ]);
  });

  it('adds caller-named hosts and deduplicates them', async () => {
    const probed = new Set<string>();
    const probe = async (host: string): Promise<Uint8Array | null> => {
      probed.add(host);
      return goodCertificate;
    };

    await checkSctProof({}, { probe, hosts: ['example.com', 'example.com'] });
    expect([...probed]).toEqual(['example.com']);
  });

  it('skips hosts whose certificate could not be observed', async () => {
    const probe = async (): Promise<Uint8Array | null> => null;
    expect(await checkSctProof(doc, { probe })).toEqual([]);
  });

  it('treats a throwing probe as unobservable', async () => {
    const probe = async (): Promise<Uint8Array | null> => {
      throw new Error('handshake failed');
    };
    expect(await checkSctProof(doc, { probe })).toEqual([]);
  });

  it('opens no sockets when both rules are off, or when there is nothing to probe', async () => {
    let calls = 0;
    const probe = async (): Promise<Uint8Array | null> => {
      calls++;
      return null;
    };

    await checkSctProof(doc, {
      probe,
      rules: {
        [SECURITY_MISSING_EMBEDDED_SCT]: 'off',
        [SECURITY_UNTRUSTED_CT_LOG_SIGNATURE]: 'off',
      },
    });
    await checkSctProof({}, { probe });
    expect(calls).toBe(0);
  });

  it('honours severity overrides through the audit entry point', async () => {
    const probe = async (): Promise<Uint8Array | null> => bareCertificate;
    const diagnostics = await checkSctProof(
      { WEB_AUTH_ENDPOINT: doc.WEB_AUTH_ENDPOINT },
      {
        probe,
        rules: { [SECURITY_MISSING_EMBEDDED_SCT]: 'error' },
      },
    );
    expect(diagnostics[0]?.severity).toBe('error');
  });
});

describe('sctProofRules', () => {
  it('registers the two rule ids and their severities', () => {
    expect(sctProofRules.map((rule) => ({ id: rule.id, severity: rule.severity }))).toEqual([
      { id: SECURITY_MISSING_EMBEDDED_SCT, severity: 'warning' },
      { id: SECURITY_UNTRUSTED_CT_LOG_SIGNATURE, severity: 'error' },
    ]);
  });
});
