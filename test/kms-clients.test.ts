import { describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { AwsKmsClient, isAwsKmsKeyId } from '../src/gitops/awsKmsClient.js';
import { GcpKmsClient, gcpAlgorithm, isGcpKmsKeyId } from '../src/gitops/gcpKmsClient.js';
import { AzureKeyVaultClient, isAzureKeyVaultKeyId } from '../src/gitops/azureKeyVaultClient.js';
import { createKmsClient, detectKmsProvider } from '../src/gitops/kmsClientFactory.js';
import {
  KmsAuthorizationError,
  KmsThrottlingError,
  parseDerSignature,
  signatureToStellarFormat,
  withKmsRetry,
} from '../src/gitops/kmsTypes.js';

const AWS_KEY = 'arn:aws:kms:us-east-1:111122223333:key/1234abcd';

type Handler = (input: Parameters<typeof fetch>[0], init?: RequestInit) => Promise<Response>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function bodyOf(init?: RequestInit): Record<string, unknown> {
  return JSON.parse(String(init?.body)) as Record<string, unknown>;
}

function headersOf(init?: RequestInit): Record<string, string> {
  return (init?.headers ?? {}) as Record<string, string>;
}

function ed25519Fixture(): {
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
  publicKeyDer: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKeyDer: Buffer.from(publicKey.export({ format: 'der', type: 'spki' })),
  };
}

describe('AWS KMS adapter', () => {
  it('detects KMS ARNs', () => {
    expect(isAwsKmsKeyId(AWS_KEY)).toBe(true);
    expect(isAwsKmsKeyId('arn:aws:kms:eu-west-1:111122223333:alias/signing')).toBe(true);
    expect(isAwsKmsKeyId('projects/p/locations/global/keyRings/r/cryptoKeys/k')).toBe(false);
  });

  it('describes and signs through SigV4 without exposing credentials', async () => {
    const fixture = ed25519Fixture();
    const seen: Array<{ target: string; authorization: string; body: Record<string, unknown> }> =
      [];
    const fetchImpl: Handler = async (_input, init) => {
      const headers = headersOf(init);
      const target = headers['x-amz-target'] ?? '';
      const body = bodyOf(init);
      seen.push({ target, authorization: headers.authorization ?? '', body });

      expect(headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\//);
      expect(headers.authorization).not.toContain('top-secret');
      expect(headers['x-amz-security-token']).toBe('session-token');

      if (target.endsWith('DescribeKey')) {
        return json({
          KeyMetadata: {
            KeyId: '1234abcd',
            Arn: AWS_KEY,
            KeyUsage: 'SIGN_VERIFY',
            KeyState: 'Enabled',
            KeySpec: 'ECC_NIST_ED25519',
            SigningAlgorithms: ['ECC_NIST_ED25519'],
          },
        });
      }
      if (target.endsWith('GetPublicKey')) {
        return json({ PublicKey: fixture.publicKeyDer.toString('base64') });
      }
      if (target.endsWith('Sign')) {
        const message = Buffer.from(String(body.Message), 'base64');
        return json({
          KeyId: AWS_KEY,
          SigningAlgorithm: 'ECC_NIST_ED25519',
          Signature: cryptoSign(null, message, fixture.privateKey).toString('base64'),
        });
      }
      return json({ __type: 'InvalidActionException', message: target }, 400);
    };

    const client = new AwsKmsClient({
      keyId: AWS_KEY,
      credentials: {
        accessKeyId: 'AKIAEXAMPLE',
        secretAccessKey: 'top-secret',
        sessionToken: 'session-token',
      },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const descriptor = await client.describeKey();
    expect(descriptor.algorithm).toBe('ECC_NIST_ED25519');
    expect(descriptor.publicKey).toHaveLength(32);

    const digest = Buffer.alloc(32, 7);
    const result = await client.signDigest(digest);
    expect(result.signature).toHaveLength(64);
    expect(result.attempts).toBe(1);

    const sign = seen.find((entry) => entry.target.endsWith('Sign'));
    expect(sign?.body.MessageType).toBe('RAW');
    expect(sign?.body.SigningAlgorithm).toBe('ECC_NIST_ED25519');
    expect(sign?.body.Message).toBe(digest.toString('base64'));
  });

  it('retries throttle responses and reports the attempt count', async () => {
    const fixture = ed25519Fixture();
    const delays: number[] = [];
    let signCalls = 0;

    const fetchImpl: Handler = async (_input, init) => {
      const target = headersOf(init)['x-amz-target'] ?? '';
      if (target.endsWith('DescribeKey')) {
        return json({
          KeyMetadata: {
            KeyId: '1234abcd',
            Arn: AWS_KEY,
            KeyUsage: 'SIGN_VERIFY',
            KeyState: 'Enabled',
            KeySpec: 'ECC_NIST_ED25519',
          },
        });
      }
      if (target.endsWith('GetPublicKey')) {
        return json({ PublicKey: fixture.publicKeyDer.toString('base64') });
      }

      signCalls++;
      if (signCalls === 1) {
        return json({ __type: 'ThrottlingException', message: 'slow down' }, 429, {
          'retry-after': '0',
        });
      }
      const message = Buffer.from(String(bodyOf(init).Message), 'base64');
      return json({ Signature: cryptoSign(null, message, fixture.privateKey).toString('base64') });
    };

    const client = new AwsKmsClient({
      keyId: AWS_KEY,
      credentials: { accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'top-secret' },
      fetchImpl: fetchImpl as unknown as typeof fetch,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        sleep: async (ms) => {
          delays.push(ms);
        },
        random: () => 0.5,
      },
    });

    const result = await client.signDigest(Buffer.alloc(32, 1));
    expect(signCalls).toBe(2);
    expect(result.attempts).toBe(2);
    expect(delays).toEqual([0]);
  });

  it('does not retry an authorization failure and never echoes the secret', async () => {
    const fetchImpl = vi.fn(async () =>
      json({ __type: 'AccessDeniedException', message: 'User is not authorized' }, 403),
    );
    const client = new AwsKmsClient({
      keyId: AWS_KEY,
      credentials: { accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'top-secret' },
      fetchImpl: fetchImpl as unknown as typeof fetch,
      retry: { maxAttempts: 5 },
    });

    await expect(client.describeKey()).rejects.toBeInstanceOf(KmsAuthorizationError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const error = await client.describeKey().catch((failure: unknown) => failure);
    expect(String(error)).not.toContain('top-secret');
  });
});

describe('Google Cloud KMS adapter', () => {
  it('maps only the Stellar-compatible algorithms', () => {
    expect(gcpAlgorithm('EC_SIGN_ED25519')).toBe('ECC_NIST_ED25519');
    expect(gcpAlgorithm('EC_SIGN_SECP256K1_SHA256')).toBe('ECC_SECG_P256K1');
    expect(gcpAlgorithm('RSA_SIGN_PKCS1_2048_SHA256')).toBeUndefined();
    expect(
      isGcpKmsKeyId('projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1'),
    ).toBe(true);
  });

  it('sends Ed25519 as data and secp256k1 as a sha256 digest', async () => {
    const ed = ed25519Fixture();
    const edPem = ed.publicKeyDer
      ? `-----BEGIN PUBLIC KEY-----\n${ed.publicKeyDer.toString('base64')}\n-----END PUBLIC KEY-----\n`
      : '';
    const bodies: Array<Record<string, unknown>> = [];

    const fetchImpl: Handler = async (input, init) => {
      const url = String(input);
      expect(headersOf(init).authorization).toBe('Bearer test-token');
      if (url.endsWith('/publicKey')) {
        return json({
          pem: edPem,
          algorithm: 'EC_SIGN_ED25519',
          name: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
        });
      }
      if (url.endsWith(':asymmetricSign')) {
        const body = bodyOf(init);
        bodies.push(body);
        const data = Buffer.from(String(body.data), 'base64');
        return json({ signature: cryptoSign(null, data, ed.privateKey).toString('base64') });
      }
      return json({ error: { code: 404, message: 'unexpected' } }, 404);
    };

    const client = new GcpKmsClient({
      keyId: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
      accessToken: 'test-token',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const descriptor = await client.describeKey();
    expect(descriptor.algorithm).toBe('ECC_NIST_ED25519');
    const result = await client.signDigest(Buffer.alloc(32, 3));
    expect(result.signature).toHaveLength(64);
    expect(bodies[0]).toHaveProperty('data');
    expect(bodies[0]).not.toHaveProperty('digest');
  });

  it('sends a digest for EC keys and rejects unauthorized responses', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    let signBody: Record<string, unknown> | undefined;

    const fetchImpl: Handler = async (input, init) => {
      if (String(input).endsWith('/publicKey')) {
        return json({ pem, algorithm: 'EC_SIGN_SECP256K1_SHA256' });
      }
      signBody = bodyOf(init);
      return json({ signature: Buffer.alloc(70, 1).toString('base64') });
    };

    const client = new GcpKmsClient({
      keyId: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2',
      accessToken: 'test-token',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const descriptor = await client.describeKey();
    expect(descriptor.algorithm).toBe('ECC_SECG_P256K1');
    await client.signDigest(Buffer.alloc(32, 9));
    expect(signBody).toHaveProperty('digest');
    expect(signBody).not.toHaveProperty('data');

    const unauthorized = new GcpKmsClient({
      keyId: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2',
      accessToken: 'bad-token',
      fetchImpl: (async () =>
        json(
          { error: { code: 401, status: 'UNAUTHENTICATED', message: 'bad token' } },
          401,
        )) as unknown as typeof fetch,
    });
    await expect(unauthorized.describeKey()).rejects.toBeInstanceOf(KmsAuthorizationError);
  });
});

describe('Azure Key Vault adapter', () => {
  const KEY_URL = 'https://institutional.vault.azure.net/keys/stellar-signer/v1';

  it('detects key URLs and maps P-256K to secp256k1', () => {
    expect(isAzureKeyVaultKeyId(KEY_URL)).toBe(true);
    expect(isAzureKeyVaultKeyId('https://example.com/keys/x')).toBe(false);
  });

  it('describes an EC key and sends ES256K over the key URL', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const jwk = publicKey.export({ format: 'jwk' }) as { x?: string; y?: string };
    const der = cryptoSign('sha256', Buffer.from('preimage'), privateKey);
    let signBody: Record<string, unknown> | undefined;

    const fetchImpl: Handler = async (input, init) => {
      expect(headersOf(init).authorization).toBe('Bearer azure-token');
      if (init?.method === 'GET') {
        return json({
          key: {
            kid: KEY_URL,
            kty: 'EC',
            crv: 'P-256K',
            x: jwk.x,
            y: jwk.y,
          },
          attributes: { enabled: true },
        });
      }
      signBody = bodyOf(init);
      return json({ kid: KEY_URL, value: der.toString('base64url') });
    };

    const client = new AzureKeyVaultClient({
      keyId: KEY_URL,
      accessToken: 'azure-token',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const descriptor = await client.describeKey();
    expect(descriptor.algorithm).toBe('ECC_SECG_P256K1');
    expect(descriptor.publicKey).toHaveLength(33);

    const digest = Buffer.alloc(32, 4);
    const result = await client.signDigest(digest);
    expect(result.signature.equals(der)).toBe(true);
    expect(signBody?.alg).toBe('ES256K');
    expect(signBody?.value).toBe(digest.toString('base64url'));
  });

  it('rejects an unauthorized vault response', async () => {
    const client = new AzureKeyVaultClient({
      keyId: KEY_URL,
      accessToken: 'azure-token',
      fetchImpl: (async () =>
        json(
          { error: { code: 'Forbidden', message: 'no kms sign permission' } },
          403,
        )) as unknown as typeof fetch,
    });
    await expect(client.describeKey()).rejects.toBeInstanceOf(KmsAuthorizationError);
  });
});

describe('provider detection and retry policy', () => {
  it('picks an adapter from the key identifier', () => {
    expect(detectKmsProvider(AWS_KEY)).toBe('aws');
    expect(detectKmsProvider('projects/p/locations/global/keyRings/r/cryptoKeys/k')).toBe('gcp');
    expect(detectKmsProvider('https://v.vault.azure.net/keys/k/v1')).toBe('azure');
    expect(() => detectKmsProvider('not-a-key')).toThrow(/Unrecognised KMS key identifier/);
  });

  it('returns the matching client class', () => {
    expect(createKmsClient(AWS_KEY)).toBeInstanceOf(AwsKmsClient);
    expect(createKmsClient('projects/p/locations/global/keyRings/r/cryptoKeys/k')).toBeInstanceOf(
      GcpKmsClient,
    );
    expect(createKmsClient('https://v.vault.azure.net/keys/k/v1')).toBeInstanceOf(
      AzureKeyVaultClient,
    );
  });

  it('honours Retry-After and gives up at maxAttempts', async () => {
    const waits: number[] = [];
    let calls = 0;
    const result = await withKmsRetry(
      async (attempt) => {
        calls = attempt;
        if (attempt < 3) {
          throw new KmsThrottlingError('throttled', { retryAfterMs: 25 });
        }
        return 'ok';
      },
      {
        maxAttempts: 5,
        sleep: async (ms) => {
          waits.push(ms);
        },
      },
    );

    expect(result).toBe('ok');
    expect(calls).toBe(3);
    expect(waits).toEqual([25, 25]);

    await expect(
      withKmsRetry(
        async () => {
          throw new KmsThrottlingError('still throttled');
        },
        { maxAttempts: 2, sleep: async () => {} },
      ),
    ).rejects.toBeInstanceOf(KmsThrottlingError);
  });

  it('does not retry non-retryable errors', async () => {
    let calls = 0;
    await expect(
      withKmsRetry(
        async () => {
          calls++;
          throw new KmsAuthorizationError('denied');
        },
        { maxAttempts: 5, sleep: async () => {} },
      ),
    ).rejects.toBeInstanceOf(KmsAuthorizationError);
    expect(calls).toBe(1);
  });
});

describe('ECDSA DER conversion', () => {
  it('round-trips a DER signature into 64 bytes and back', () => {
    const r = Buffer.concat([Buffer.from([0x00, 0x80]), Buffer.alloc(31, 0x11)]);
    const s = Buffer.alloc(32, 0x22);
    const der = Buffer.concat([
      Buffer.from([0x30, r.length + s.length + 4, 0x02, r.length]),
      r,
      Buffer.from([0x02, s.length]),
      s,
    ]);

    const parsed = parseDerSignature(der);
    expect(parsed.r.length).toBeGreaterThan(0);

    const converted = signatureToStellarFormat(der, 'ECC_SECG_P256K1');
    expect(converted.format).toBe('der-converted');
    expect(converted.signature).toHaveLength(64);
  });
});
