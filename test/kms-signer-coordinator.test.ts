import { describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
  Account,
  Asset,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import { CloudKmsSignerCoordinator } from '../src/gitops/kmsSignerCoordinator.js';
import {
  KmsAuthorizationError,
  KmsThrottlingError,
  KmsUnsupportedAlgorithmError,
  parsePublicKey,
  type KmsClient,
  type KmsKeyDescriptor,
  type KmsSignResult,
} from '../src/gitops/kmsTypes.js';

const PASSPHRASE = Networks.TESTNET;

function envelope(): string {
  const account = new Account(Keypair.random().publicKey(), '1');
  return new TransactionBuilder(account, { fee: '100', networkPassphrase: PASSPHRASE })
    .addOperation(
      Operation.payment({
        destination: Keypair.random().publicKey(),
        asset: Asset.native(),
        amount: '1',
      }),
    )
    .setTimeout(30)
    .build()
    .toXDR();
}

function ed25519Kms(
  options: {
    sign?: (digest: Buffer) => Promise<KmsSignResult>;
    algorithm?: KmsKeyDescriptor['algorithm'];
  } = {},
): {
  client: KmsClient;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
  publicKey: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const parsed = parsePublicKey(pem, 'pem');
  const descriptor: KmsKeyDescriptor = {
    provider: 'aws',
    keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
    resourceName: 'arn:aws:kms:us-east-1:111122223333:key/test',
    algorithm: options.algorithm ?? 'ECC_NIST_ED25519',
    publicKey: parsed.publicKey,
    publicKeyPem: parsed.publicKeyPem,
    keyState: 'Enabled',
    keyUsage: 'SIGN_VERIFY',
  };

  const client: KmsClient = {
    provider: 'aws',
    describeKey: async () => descriptor,
    signDigest:
      options.sign ??
      (async (digest) => ({
        signature: cryptoSign(null, digest, privateKey),
        attempts: 1,
      })),
  };
  return { client, privateKey, publicKey: parsed.publicKey };
}

function secp256k1Kms(): {
  client: KmsClient;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
} {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const parsed = parsePublicKey(pem, 'pem');
  const descriptor: KmsKeyDescriptor = {
    provider: 'gcp',
    keyId: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
    resourceName: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
    algorithm: 'ECC_SECG_P256K1',
    publicKey: parsed.publicKey,
    publicKeyPem: parsed.publicKeyPem,
  };

  return {
    privateKey,
    client: {
      provider: 'gcp',
      describeKey: async () => descriptor,
      signDigest: async () => ({
        // GCP hands back DER; the coordinator must pack it into 64 bytes.
        signature: cryptoSign('sha256', signatureBaseOf(), privateKey),
        attempts: 1,
      }),
    },
  };
}

/**
 * Recovers the signature pre-image from a digest by rebuilding the envelope
 * the test signed. Tests only use one envelope, so it is rebuilt on demand.
 */
let cachedEnvelope: string | undefined;
function signatureBaseOf(): Buffer {
  cachedEnvelope ??= testEnvelope;
  const tx = TransactionBuilder.fromXDR(cachedEnvelope, PASSPHRASE);
  return tx.signatureBase();
}

const testEnvelope = envelope();

function accountResponse(signerKey: string, weight: number, threshold = 2): Response {
  return new Response(
    JSON.stringify({
      thresholds: { low_threshold: 1, med_threshold: threshold, high_threshold: 3 },
      signers: [{ key: signerKey, weight, type: 'ed25519_public_key' }],
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('CloudKmsSignerCoordinator', () => {
  it('signs an envelope, packs a valid DecoratedSignature, and meets quorum', async () => {
    const kms = ed25519Kms();
    const tx = TransactionBuilder.fromXDR(testEnvelope, PASSPHRASE);
    const signer = (await import('@stellar/stellar-base')).StrKey.encodeEd25519PublicKey(
      kms.publicKey,
    );
    const fetchImpl = vi.fn(async () => accountResponse(signer, 3, 2));

    const report = await new CloudKmsSignerCoordinator({
      keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
      envelope: testEnvelope,
      networkPassphrase: PASSPHRASE,
      client: kms.client,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    }).run();

    expect(report.ok).toBe(true);
    expect(report.key.algorithm).toBe('ECC_NIST_ED25519');
    expect(report.key.stellarAddress).toBe(signer);
    expect(report.key.hint).toBe(kms.publicKey.subarray(-4).toString('hex'));
    expect(report.transaction.hash).toBe(tx.hash().toString('hex'));
    expect(report.signature?.length).toBe(64);
    expect(report.signature?.format).toBe('raw');
    expect(report.signature?.verified).toBe(true);
    expect(report.quorum.checked).toBe(true);
    expect(report.quorum.met).toBe(true);
    expect(report.quorum.signerWeight).toBe(3);
    expect(report.checks.every((check) => check.ok)).toBe(true);

    const decorated = xdr.DecoratedSignature.fromXDR(report.signature!.decoratedXdr, 'base64');
    expect(decorated.hint().toString('hex')).toBe(report.key.hint);
    expect(decorated.signature().length).toBe(64);
  });

  it('fails when the KMS key weight is below the account threshold', async () => {
    const kms = ed25519Kms();
    const { StrKey } = await import('@stellar/stellar-base');
    const signer = StrKey.encodeEd25519PublicKey(kms.publicKey);

    const report = await new CloudKmsSignerCoordinator({
      keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
      envelope: testEnvelope,
      networkPassphrase: PASSPHRASE,
      threshold: 'high',
      client: kms.client,
      fetchImpl: (async () => accountResponse(signer, 2, 3)) as unknown as typeof fetch,
    }).run();

    expect(report.ok).toBe(false);
    expect(report.quorum.checked).toBe(true);
    expect(report.quorum.met).toBe(false);
    expect(report.quorum.thresholdName).toBe('high');
    expect(report.checks.find((check) => check.id === 'quorum')?.ok).toBe(false);
  });

  it('reports an unreadable Horizon account as a failed quorum check', async () => {
    const kms = ed25519Kms();
    const report = await new CloudKmsSignerCoordinator({
      keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
      envelope: testEnvelope,
      networkPassphrase: PASSPHRASE,
      client: kms.client,
      fetchImpl: (async () => new Response('{}', { status: 503 })) as unknown as typeof fetch,
    }).run();

    expect(report.ok).toBe(false);
    expect(report.quorum.checked).toBe(false);
    expect(report.quorum.reason).toContain('HTTP 503');
    expect(report.warnings).toEqual([]);
  });

  it('skips the Horizon audit entirely with skipQuorumCheck', async () => {
    const kms = ed25519Kms();
    const fetchImpl = vi.fn();
    const report = await new CloudKmsSignerCoordinator({
      keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
      envelope: testEnvelope,
      networkPassphrase: PASSPHRASE,
      client: kms.client,
      skipQuorumCheck: true,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    }).run();

    expect(report.ok).toBe(true);
    expect(report.quorum.checked).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(report.warnings.join(' ')).toContain('skipped');
  });

  it('converts a secp256k1 DER signature into 64 Stellar bytes and verifies it', async () => {
    const kms = secp256k1Kms();
    const report = await new CloudKmsSignerCoordinator({
      keyId: 'projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
      envelope: testEnvelope,
      networkPassphrase: PASSPHRASE,
      client: kms.client,
    }).run();

    expect(report.ok).toBe(true);
    expect(report.key.algorithm).toBe('ECC_SECG_P256K1');
    expect(report.signature?.format).toBe('der-converted');
    expect(report.signature?.length).toBe(64);
    expect(report.signature?.verified).toBe(true);
    expect(report.quorum.checked).toBe(false);
    expect(report.quorum.reason).toContain('secp256k1');
  });

  it('surfaces provider authorization failures instead of pretending to sign', async () => {
    const kms = ed25519Kms({
      sign: async () => {
        throw new KmsAuthorizationError('AccessDeniedException: not authorized to kms:Sign', {
          provider: 'aws',
        });
      },
    });

    await expect(
      new CloudKmsSignerCoordinator({
        keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
        envelope: testEnvelope,
        networkPassphrase: PASSPHRASE,
        client: kms.client,
      }).run(),
    ).rejects.toBeInstanceOf(KmsAuthorizationError);
  });

  it('propagates throttling after the adapter exhausts its retries', async () => {
    const kms = ed25519Kms({
      sign: async () => {
        throw new KmsThrottlingError('ThrottlingException', { provider: 'aws', status: 429 });
      },
    });

    await expect(
      new CloudKmsSignerCoordinator({
        keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
        envelope: testEnvelope,
        networkPassphrase: PASSPHRASE,
        client: kms.client,
      }).run(),
    ).rejects.toBeInstanceOf(KmsThrottlingError);
  });

  it('records retry attempts in the signature report', async () => {
    const kms = ed25519Kms();
    const sign = kms.client.signDigest;
    kms.client.signDigest = async (digest) => ({ ...(await sign(digest)), attempts: 3 });

    const report = await new CloudKmsSignerCoordinator({
      keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
      envelope: testEnvelope,
      networkPassphrase: PASSPHRASE,
      client: kms.client,
      skipQuorumCheck: true,
    }).run();

    expect(report.signature?.attempts).toBe(3);
  });

  it('rejects an unsupported key algorithm before signing', async () => {
    const kms = ed25519Kms();
    const descriptor = await kms.client.describeKey();
    kms.client.describeKey = async () => ({
      ...descriptor,
      algorithm: 'RSA_2048' as KmsKeyDescriptor['algorithm'],
    });

    await expect(
      new CloudKmsSignerCoordinator({
        keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
        envelope: testEnvelope,
        networkPassphrase: PASSPHRASE,
        client: kms.client,
        skipQuorumCheck: true,
      }).run(),
    ).rejects.toBeInstanceOf(KmsUnsupportedAlgorithmError);
  });

  it('rejects an envelope that is not valid XDR', async () => {
    const kms = ed25519Kms();
    await expect(
      new CloudKmsSignerCoordinator({
        keyId: 'arn:aws:kms:us-east-1:111122223333:key/test',
        envelope: 'not-an-envelope',
        networkPassphrase: PASSPHRASE,
        client: kms.client,
        skipQuorumCheck: true,
      }).run(),
    ).rejects.toMatchObject({ code: 'invalid-envelope' });
  });
});
