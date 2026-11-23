import { beforeAll, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { gzipSync } from 'node:zlib';
import { ArchiveGpgVerifier, type ArchiveGpgStatus } from '../src/overlay/archiveGpgVerifier.js';

const ARCHIVE = 'https://history.example.test/prd/core-live/core_live_001/';
const SEQUENCE = 63;
const MANIFEST_URL = new URL('.well-known/stellar-history.json', ARCHIVE).toString();
const PAYLOAD_URL = new URL('ledger/00/00/00/ledger-0000003f.xdr.gz', ARCHIVE).toString();
const SIGNATURE_URL = `${PAYLOAD_URL}.sig`;
const PAYLOAD = new Uint8Array(gzipSync(Buffer.from('valid ledger XDR fixture')));
const KEY_DATE = new Date('2020-01-01T00:00:00.000Z');
const SIGNATURE_DATE = new Date('2020-01-02T00:00:00.000Z');

interface KeyFixture {
  privateKey: openpgp.PrivateKey;
  publicKey: string;
  fingerprint: string;
  revocationCertificate: string;
  algorithm: string;
  keyBits?: number;
  signingSubkeyID?: openpgp.KeyID;
  signingSubkeyFingerprint?: string;
}

let rsa: KeyFixture;
let ed25519: KeyFixture;
let unrelated: KeyFixture;
let weakRsa: KeyFixture;
let expired: KeyFixture;
let rsaSignature: string;
let edSignature: string;
let unrelatedSignature: string;
let weakSignature: string;
let expiredSignature: string;
let revokedPublicKey: string;
let revokedSignature: string;
let unsupportedKey: KeyFixture;
let unsupportedSignature: string;
let ed25519Subkey: KeyFixture;
let ed25519SubkeySignature: string;
let weakSubkey: KeyFixture;
let weakSubkeySignature: string;

async function generateKey(options: {
  type: 'rsa' | 'ecc';
  rsaBits?: number;
  curve?: openpgp.EllipticCurveName;
  keyExpirationTime?: number;
  subkeys?: openpgp.SubkeyOptions[];
}): Promise<KeyFixture> {
  const generated = await openpgp.generateKey({
    ...options,
    userIDs: [{ name: 'Archive verifier test fixture', email: 'fixture@example.invalid' }],
    date: KEY_DATE,
    format: 'object',
  });
  const info = generated.publicKey.getAlgorithmInfo();
  const signingSubkey = options.subkeys?.length
    ? generated.publicKey
        .getKeys()
        .find((key) => key.getFingerprint() !== generated.publicKey.getFingerprint())
    : undefined;
  return {
    privateKey: generated.privateKey,
    publicKey: generated.publicKey.armor(),
    fingerprint: generated.publicKey.getFingerprint(),
    revocationCertificate: generated.revocationCertificate,
    algorithm: info.algorithm,
    ...(info.bits === undefined ? {} : { keyBits: info.bits }),
    ...(signingSubkey === undefined
      ? {}
      : {
          signingSubkeyID: signingSubkey.getKeyID(),
          signingSubkeyFingerprint: signingSubkey.getFingerprint(),
        }),
  };
}

async function sign(
  fixture: KeyFixture,
  payload: Uint8Array,
  date = SIGNATURE_DATE,
  signingKeyID?: openpgp.KeyID,
  config?: openpgp.PartialConfig,
): Promise<string> {
  const message = await openpgp.createMessage({ binary: payload });
  const output = await openpgp.sign({
    message,
    signingKeys: [fixture.privateKey],
    ...(signingKeyID === undefined ? {} : { signingKeyIDs: [signingKeyID] }),
    detached: true,
    format: 'armored',
    date,
    ...(config === undefined ? {} : { config }),
  });
  return typeof output === 'string' ? output : await new Response(output).text();
}

function manifestResponse(sequence = SEQUENCE): Response {
  return new Response(JSON.stringify({ version: 1, currentLedger: sequence, currentBuckets: [] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function archiveFetch(
  options: {
    payload?: Uint8Array;
    signature?: string | Uint8Array;
    manifest?: Response;
    signatureStatus?: number;
    payloadStatus?: number;
    signatureContentType?: string;
    payloadContentType?: string;
    payloadContentEncoding?: string;
    onRequest?: (url: string, init?: RequestInit) => void;
  } = {},
): typeof fetch {
  return (async (input, init) => {
    const url = String(input);
    options.onRequest?.(url, init);
    if (url === MANIFEST_URL) return options.manifest?.clone() ?? manifestResponse();
    if (url === PAYLOAD_URL) {
      return new Response(options.payload ?? PAYLOAD, {
        status: options.payloadStatus ?? 200,
        headers: {
          'content-type': options.payloadContentType ?? 'application/gzip',
          ...(options.payloadContentEncoding === undefined
            ? {}
            : { 'content-encoding': options.payloadContentEncoding }),
        },
      });
    }
    if (url === SIGNATURE_URL) {
      if (options.signatureStatus !== undefined && options.signatureStatus !== 200) {
        return new Response('missing', { status: options.signatureStatus });
      }
      const signature = options.signature ?? rsaSignature;
      return new Response(typeof signature === 'string' ? signature : signature, {
        status: 200,
        headers: {
          'content-type': options.signatureContentType ?? 'application/pgp-signature',
        },
      });
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
}

async function verifier(fetchImpl?: typeof fetch, now?: Date): Promise<ArchiveGpgVerifier> {
  return new ArchiveGpgVerifier({
    ...(fetchImpl === undefined ? {} : { fetchImpl }),
    ...(now === undefined ? {} : { now }),
  });
}

beforeAll(async () => {
  rsa = await generateKey({ type: 'rsa', rsaBits: 2048 });
  ed25519 = await generateKey({ type: 'ecc', curve: 'ed25519Legacy' });
  unrelated = await generateKey({ type: 'ecc', curve: 'ed25519Legacy' });
  weakRsa = await generateKey({ type: 'rsa', rsaBits: 2047 });
  expired = await generateKey({
    type: 'ecc',
    curve: 'ed25519Legacy',
    keyExpirationTime: 60,
  });
  unsupportedKey = await generateKey({ type: 'ecc', curve: 'nistP256' });
  ed25519Subkey = await generateKey({
    type: 'rsa',
    rsaBits: 2048,
    subkeys: [{ type: 'ecc', curve: 'ed25519Legacy', sign: true }],
  });
  weakSubkey = await generateKey({
    type: 'rsa',
    rsaBits: 2048,
    subkeys: [{ type: 'rsa', rsaBits: 2047, sign: true }],
  });
  rsaSignature = await sign(rsa, PAYLOAD);
  edSignature = await sign(ed25519, PAYLOAD);
  unrelatedSignature = await sign(unrelated, PAYLOAD);
  weakSignature = await sign(weakRsa, PAYLOAD);
  expiredSignature = await sign(expired, PAYLOAD, new Date(KEY_DATE.getTime() + 1000));
  unsupportedSignature = await sign(unsupportedKey, PAYLOAD);
  ed25519SubkeySignature = await sign(
    ed25519Subkey,
    PAYLOAD,
    SIGNATURE_DATE,
    ed25519Subkey.signingSubkeyID,
  );
  weakSubkeySignature = await sign(
    weakSubkey,
    PAYLOAD,
    SIGNATURE_DATE,
    weakSubkey.signingSubkeyID,
    { ...openpgp.config, minRSABits: 0 },
  );
  const revokedPair = await openpgp.revokeKey({
    key: unrelated.privateKey,
    revocationCertificate: unrelated.revocationCertificate,
    date: new Date(KEY_DATE.getTime() + 10_000),
    format: 'object',
  });
  revokedPublicKey = revokedPair.publicKey.armor();
  revokedSignature = unrelatedSignature;
}, 60_000);

describe('ArchiveGpgVerifier cryptography', () => {
  it('performs real detached RSA verification and reports unknown identity trust', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: rsa.publicKey,
    });

    expect(result).toMatchObject({
      ok: true,
      status: 'verified',
      cryptographicallyValid: true,
      identityTrust: 'unknown',
      keySource: 'provided',
      signers: [
        {
          primaryFingerprint: rsa.fingerprint,
          algorithm: rsa.algorithm,
          keyBits: 2048,
        },
      ],
    });
  });

  it('accepts Ed25519 signing keys', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: edSignature,
      publicKey: ed25519.publicKey,
    });

    expect(result.status).toBe('verified');
    expect(result.signers[0]?.algorithm.toLowerCase()).toMatch(/^eddsa(?:legacy)?$/);
  });

  it('reports and accepts the actual Ed25519 signing subkey', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: ed25519SubkeySignature,
      publicKey: ed25519Subkey.publicKey,
    });

    expect(result.status).toBe('verified');
    expect(result.signers[0]).toMatchObject({
      fingerprint: ed25519Subkey.signingSubkeyFingerprint,
      primaryFingerprint: ed25519Subkey.fingerprint,
    });
    expect(result.signers[0]?.fingerprint).not.toBe(result.signers[0]?.primaryFingerprint);
  });

  it('marks a fingerprint as trusted only when it was explicitly pinned', async () => {
    const valid = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: rsa.publicKey,
      trustedFingerprint: rsa.fingerprint.toUpperCase(),
    });
    const mismatch = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: rsa.publicKey,
      trustedFingerprint: unrelated.fingerprint,
    });

    expect(valid.identityTrust).toBe('trusted');
    expect(mismatch).toMatchObject({
      ok: false,
      status: 'untrusted-key',
      cryptographicallyValid: true,
      identityTrust: 'mismatch',
    });
  });

  it('rejects payload bytes changed after signing', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: new Uint8Array([...PAYLOAD, 0x99]),
      signature: rsaSignature,
      publicKey: rsa.publicKey,
    });
    expect(result.status).toBe('invalid-signature');
    expect(result.cryptographicallyValid).toBe(false);
  });

  it('rejects a signature from an unrelated key', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: unrelatedSignature,
      publicKey: rsa.publicKey,
    });
    expect(result.status).toBe('invalid-signature');
  });

  it('rejects RSA keys below 2048 bits', async () => {
    expect(weakRsa.keyBits).toBe(2047);
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: weakSignature,
      publicKey: weakRsa.publicKey,
    });
    expect(result.status).toBe('weak-key');
    expect(result.cryptographicallyValid).toBe(false);
  });

  it('rejects a weak signing subkey even when its primary key is strong', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: weakSubkeySignature,
      publicKey: weakSubkey.publicKey,
    });

    expect(weakSubkey.keyBits).toBe(2048);
    expect(result.status).toBe('weak-key');
  });

  it('rejects expired signing keys', async () => {
    const result = await (
      await verifier(undefined, new Date('2026-01-01T00:00:00.000Z'))
    ).verifyDetached({
      payload: PAYLOAD,
      signature: expiredSignature,
      publicKey: expired.publicKey,
    });
    expect(result.status).toBe('expired-key');
  });

  it('rejects a cryptographically revoked public key', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: revokedSignature,
      publicKey: revokedPublicKey,
    });
    expect(result.status).toBe('revoked-key');
  });

  it('rejects unsupported elliptic-curve signing algorithms', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: unsupportedSignature,
      publicKey: unsupportedKey.publicKey,
    });
    expect(result.status).toBe('unsupported-algorithm');
  });

  it('rejects a signature with multiple independent signers as ambiguous', async () => {
    const message = await openpgp.createMessage({ binary: PAYLOAD });
    const output = await openpgp.sign({
      message,
      signingKeys: [rsa.privateKey, ed25519.privateKey],
      detached: true,
      format: 'armored',
      date: SIGNATURE_DATE,
    });
    const multiSignature = typeof output === 'string' ? output : await new Response(output).text();
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: multiSignature,
      publicKey: `${rsa.publicKey}\n${ed25519.publicKey}`,
    });
    expect(result.status).toBe('ambiguous-signer');
  });

  it('rejects malformed signatures and malformed public key rings', async () => {
    const verifierInstance = await verifier();
    const malformedSignature = await verifierInstance.verifyDetached({
      payload: PAYLOAD,
      signature: 'not an OpenPGP signature',
      publicKey: rsa.publicKey,
    });
    const malformedKey = await verifierInstance.verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nmalformed',
    });
    const privateKey = await verifierInstance.verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: rsa.privateKey.armor(),
    });
    const corruptRing = await verifierInstance.verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: `${rsa.publicKey}\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nmalformed\n-----END PGP PUBLIC KEY BLOCK-----`,
    });

    expect(malformedSignature.status).toBe('malformed-signature');
    expect(malformedKey.status).toBe('invalid-key');
    expect(privateKey.status).toBe('invalid-key');
    expect(corruptRing.status).toBe('invalid-key');
  });

  it('reports missing public keys and rejects empty payloads', async () => {
    const verifierInstance = await verifier();
    const missing = await verifierInstance.verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
    });
    const empty = await verifierInstance.verifyDetached({
      payload: new Uint8Array(),
      signature: rsaSignature,
      publicKey: rsa.publicKey,
    });

    expect(missing.status).toBe('missing-key');
    expect(empty.status).toBe('invalid-signature');
  });

  it('handles a public key ring and selects the signer by signature key ID', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: edSignature,
      publicKey: `${rsa.publicKey}\n${ed25519.publicKey}`,
    });
    expect(result.status).toBe('verified');
    expect(result.signers[0]?.primaryFingerprint).toBe(ed25519.fingerprint);
  });

  it('detects a bad trusted fingerprint format', async () => {
    const result = await (
      await verifier()
    ).verifyDetached({
      payload: PAYLOAD,
      signature: rsaSignature,
      publicKey: rsa.publicKey,
      trustedFingerprint: 'not-a-fingerprint',
    });
    expect(result).toMatchObject({
      status: 'invalid-key',
      cryptographicallyValid: true,
      identityTrust: 'unknown',
    });
  });
});

describe('ArchiveGpgVerifier archive discovery and transport', () => {
  it('reads the Stellar manifest, locates the latest ledger checkpoint, and verifies its .sig sidecar', async () => {
    const requested: string[] = [];
    const result = await (
      await verifier(archiveFetch({ onRequest: (url) => requested.push(url) }))
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(result).toMatchObject({
      ok: true,
      status: 'verified',
      checkpointSequence: SEQUENCE,
      payloadUrl: PAYLOAD_URL,
      signatureUrl: SIGNATURE_URL,
      manifestUrl: MANIFEST_URL,
    });
    expect(requested).toEqual([MANIFEST_URL, SIGNATURE_URL, PAYLOAD_URL]);
  });

  it('returns missing-signature instead of treating an unsigned archive as verified', async () => {
    const result = await (
      await verifier(archiveFetch({ signatureStatus: 404 }))
    ).verifyArchive({
      archiveUrl: ARCHIVE,
      publicKey: rsa.publicKey,
    });
    expect(result).toMatchObject({ ok: false, status: 'missing-signature' });
  });

  it('requires the caller to provide the key; it does not retrieve one from the archive host', async () => {
    const requests: string[] = [];
    const result = await (
      await verifier(archiveFetch({ onRequest: (url) => requests.push(url) }))
    ).verifyArchive({ archiveUrl: ARCHIVE });
    expect(result.status).toBe('missing-key');
    expect(requests).toEqual([]);
  });

  it('rejects an oversized public key before making archive requests', async () => {
    const requests: string[] = [];
    const result = await new ArchiveGpgVerifier({
      fetchImpl: archiveFetch({ onRequest: (url) => requests.push(url) }),
      maxPublicKeyBytes: 32,
    }).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(result.status).toBe('oversized-response');
    expect(requests).toEqual([]);
  });

  it('reports malformed and missing manifests', async () => {
    const badManifest = await (
      await verifier(
        archiveFetch({
          manifest: new Response('{', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const missingManifest = await (
      await verifier(
        archiveFetch({
          manifest: new Response('missing', { status: 404 }),
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(badManifest.status).toBe('malformed-manifest');
    expect(missingManifest.status).toBe('missing-manifest');
  });

  it('rejects manifests with invalid checkpoint fields or unsupported version', async () => {
    for (const body of [
      { version: 3, currentLedger: SEQUENCE },
      { version: 1, currentLedger: 64 },
      { version: 1, currentLedger: '63' },
    ]) {
      const result = await (
        await verifier(
          archiveFetch({
            manifest: new Response(JSON.stringify(body), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }),
          }),
        )
      ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
      expect(result.status).toBe('malformed-manifest');
    }
  });

  it('reports unavailable payloads, HTTP failures, and unexpected content types', async () => {
    const missingPayload = await (
      await verifier(archiveFetch({ payloadStatus: 404 }))
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const badSignatureType = await (
      await verifier(
        archiveFetch({
          signatureContentType: 'text/html',
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const badPayloadType = await (
      await verifier(
        archiveFetch({
          payloadContentType: 'text/html',
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const encodedPayload = await (
      await verifier(archiveFetch({ payloadContentEncoding: 'gzip' }))
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(missingPayload.status).toBe('missing-checkpoint');
    expect(badSignatureType.status).toBe('unexpected-content-type');
    expect(badPayloadType.status).toBe('unexpected-content-type');
    expect(encodedPayload.status).toBe('unexpected-content-type');
  });

  it('rejects a corrupt or non-XDR-aligned gzip checkpoint before signature verification', async () => {
    const corrupt = await (
      await verifier(
        archiveFetch({
          payload: new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]),
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const misaligned = await (
      await verifier(
        archiveFetch({
          payload: new Uint8Array(gzipSync(Buffer.from('abc'))),
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(corrupt.status).toBe('malformed-checkpoint');
    expect(misaligned.status).toBe('malformed-checkpoint');
  });

  it('rejects redirects and unsafe URLs', async () => {
    const redirected = await (
      await verifier(
        (async () =>
          new Response('', {
            status: 302,
            headers: { location: 'https://other.example.test/' },
          })) as typeof fetch,
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const insecure = await (
      await verifier()
    ).verifyArchive({
      archiveUrl: 'http://127.0.0.1/private',
      publicKey: rsa.publicKey,
    });
    const local = await (
      await verifier()
    ).verifyArchive({
      archiveUrl: 'https://localhost/archive/',
      publicKey: rsa.publicKey,
    });
    const ipv6Loopback = await (
      await verifier()
    ).verifyArchive({
      archiveUrl: 'https://[::1]/archive/',
      publicKey: rsa.publicKey,
    });

    expect(redirected.status).toBe('unsafe-url');
    expect(insecure.status).toBe('unsafe-url');
    expect(local.status).toBe('unsafe-url');
    expect(ipv6Loopback.status).toBe('unsafe-url');
    const loopbackIp = await (
      await verifier()
    ).verifyArchive({
      archiveUrl: 'https://127.0.0.1/archive/',
      publicKey: rsa.publicKey,
    });
    expect(loopbackIp.status).toBe('unsafe-url');
  });

  it('enforces response size limits while streaming', async () => {
    const result = await (
      await verifier(archiveFetch({ payload: new Uint8Array(32) }))
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const limited = await new ArchiveGpgVerifier({
      fetchImpl: archiveFetch({ payload: new Uint8Array(32) }),
      maxPayloadBytes: 16,
    }).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(result.status).not.toBe('oversized-response');
    expect(limited.status).toBe('oversized-response');
  });

  it('reports request timeouts and non-404 HTTP failures', async () => {
    const timeoutFetch = ((_input: Parameters<typeof fetch>[0], init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        if (init?.signal?.aborted) {
          reject(new Error('aborted'));
          return;
        }
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      })) as typeof fetch;
    const timeout = await new ArchiveGpgVerifier({
      fetchImpl: timeoutFetch,
      timeoutMs: 1,
    }).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });
    const httpError = await (
      await verifier(
        archiveFetch({
          manifest: new Response('server error', { status: 503 }),
        }),
      )
    ).verifyArchive({ archiveUrl: ARCHIVE, publicKey: rsa.publicKey });

    expect(timeout.status).toBe('timeout');
    expect(httpError.status).toBe('http-error');
  });

  it('uses an explicitly supplied signature URL when configured', async () => {
    const explicitSignature = 'https://signatures.example.test/core/ledger.sig';
    const fetchImpl = (async (input) => {
      if (String(input) === MANIFEST_URL) return manifestResponse();
      if (String(input) === PAYLOAD_URL) return new Response(PAYLOAD, { status: 200 });
      if (String(input) === explicitSignature) {
        return new Response(rsaSignature, {
          status: 200,
          headers: { 'content-type': 'application/pgp-signature' },
        });
      }
      return new Response('', { status: 404 });
    }) as typeof fetch;
    const result = await (
      await verifier(fetchImpl)
    ).verifyArchive({
      archiveUrl: ARCHIVE,
      publicKey: rsa.publicKey,
      signatureUrl: explicitSignature,
    });
    expect(result.status).toBe('verified');
    expect(result.signatureUrl).toBe(explicitSignature);
  });
});

describe('archive GPG result states', () => {
  it('keeps verification statuses explicit', () => {
    const statuses: ArchiveGpgStatus[] = [
      'verified',
      'invalid-signature',
      'missing-signature',
      'expired-key',
      'weak-key',
      'unsupported-algorithm',
      'ambiguous-signer',
    ];
    expect(new Set(statuses).size).toBe(statuses.length);
  });

  it('rejects invalid timeout and size limits in library options', () => {
    expect(() => new ArchiveGpgVerifier({ timeoutMs: 0 })).toThrow(RangeError);
    expect(() => new ArchiveGpgVerifier({ maxPayloadBytes: Number.POSITIVE_INFINITY })).toThrow(
      RangeError,
    );
    expect(() => new ArchiveGpgVerifier({ now: new Date(Number.NaN) })).toThrow(RangeError);
  });
});
