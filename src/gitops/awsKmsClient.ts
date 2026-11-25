/**
 * AWS KMS adapter.
 *
 * Talks the KMS JSON API directly (`TrentService.DescribeKey`, `GetPublicKey`,
 * `Sign`) through SigV4, so the package keeps its two runtime dependencies and
 * an anchor can audit the exact request it sends to the HSM.
 *
 * Credentials come only from the standard AWS environment variables. They are
 * read at call time, never stored on the descriptor, and never appear in an
 * error message.
 */
import { createHash, createHmac } from 'node:crypto';
import {
  KmsAuthorizationError,
  KmsError,
  KmsUnsupportedAlgorithmError,
  base64,
  isKmsKeyAlgorithm,
  kmsHttpError,
  parsePublicKey,
  withKmsRetry,
  type KmsClient,
  type KmsKeyAlgorithm,
  type KmsKeyDescriptor,
  type KmsProvider,
  type KmsRetryOptions,
  type KmsSignResult,
} from './kmsTypes.js';

const SERVICE = 'kms';
const TARGET_PREFIX = 'TrentService';
const JSON_CONTENT_TYPE = 'application/x-amz-json-1.1';

/** Standard environment credentials. */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface AwsKmsClientOptions {
  keyId: string;
  region?: string;
  endpoint?: string;
  credentials?: AwsCredentials | (() => Promise<AwsCredentials>);
  fetchImpl?: typeof fetch;
  retry?: KmsRetryOptions;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

interface AwsKeyMetadata {
  KeyId?: string;
  Arn?: string;
  KeyUsage?: string;
  KeyState?: string;
  KeySpec?: string;
  CustomerMasterKeySpec?: string;
  SigningAlgorithms?: string[];
}

/** True for a KMS key ARN (including the `alias/` and `key/` resource forms). */
export function isAwsKmsKeyId(value: string): boolean {
  return /^arn:aws(?:-[a-z]+)?:kms:[a-z0-9-]+:\d{12}:(?:key|alias)\//.test(value);
}

function regionFromArn(keyId: string): string | undefined {
  if (!isAwsKmsKeyId(keyId)) return undefined;
  return keyId.split(':')[3];
}

function applyAlgorithm(
  key: { algorithm?: KmsKeyAlgorithm; signingAlgorithm?: string },
  keySpec: string | undefined,
  signingAlgorithms: readonly string[] | undefined,
): void {
  if (keySpec === 'ECC_NIST_ED25519' || keySpec === 'ED25519') {
    key.algorithm = 'ECC_NIST_ED25519';
    key.signingAlgorithm = 'ECC_NIST_ED25519';
    return;
  }
  if (keySpec === 'ECC_SECG_P256K1') {
    key.algorithm = 'ECC_SECG_P256K1';
    key.signingAlgorithm =
      signingAlgorithms?.find((algorithm) => /ECDSA/i.test(algorithm)) ?? 'ECDSA_SHA_256';
    return;
  }
  if (keySpec !== undefined) {
    throw new KmsUnsupportedAlgorithmError(
      `AWS KMS key ${keySpec} is not a Stellar-compatible Ed25519 or secp256k1 key`,
      { provider: 'aws' },
    );
  }
}

export class AwsKmsClient implements KmsClient {
  readonly provider: KmsProvider = 'aws';
  private readonly keyId: string;
  private readonly region: string;
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;
  private readonly retry: KmsRetryOptions;
  private readonly env: NodeJS.ProcessEnv;
  private readonly now: () => Date;
  private readonly credentialProvider: AwsCredentials | (() => Promise<AwsCredentials>);
  private descriptor?: KmsKeyDescriptor;

  constructor(options: AwsKmsClientOptions) {
    this.keyId = options.keyId;
    this.env = options.env ?? process.env;
    this.region =
      options.region ??
      regionFromArn(options.keyId) ??
      this.env.AWS_REGION ??
      this.env.AWS_DEFAULT_REGION ??
      'us-east-1';
    this.endpoint =
      options.endpoint ??
      this.env.AWS_ENDPOINT_URL_KMS ??
      this.env.AWS_KMS_ENDPOINT ??
      `https://kms.${this.region}.amazonaws.com`;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.retry = options.retry ?? {};
    this.now = options.now ?? (() => new Date());
    this.credentialProvider = options.credentials ?? (async () => this.credentialsFromEnv());
  }

  async describeKey(): Promise<KmsKeyDescriptor> {
    if (this.descriptor !== undefined) return this.descriptor;

    const described = await this.call<{ KeyMetadata?: AwsKeyMetadata } & AwsKeyMetadata>(
      'DescribeKey',
      { KeyId: this.keyId },
    );
    // The KMS JSON API wraps the metadata; accept a flat fixture too so the
    // adapter is usable behind a lightweight mock endpoint.
    const metadata = described.KeyMetadata ?? described;
    if (metadata.KeyUsage !== undefined && metadata.KeyUsage !== 'SIGN_VERIFY') {
      throw new KmsUnsupportedAlgorithmError(
        `AWS KMS key usage is ${metadata.KeyUsage}; Stellar signing requires SIGN_VERIFY`,
        { provider: 'aws' },
      );
    }
    if (metadata.KeyState !== undefined && metadata.KeyState !== 'Enabled') {
      throw new KmsError(
        'key-not-enabled',
        `AWS KMS key state is ${metadata.KeyState}; it must be Enabled to sign`,
        { provider: 'aws' },
      );
    }

    const keySpec = metadata.KeySpec ?? metadata.CustomerMasterKeySpec;
    const algorithm: Partial<KmsKeyDescriptor> = {};
    applyAlgorithm(algorithm, keySpec, metadata.SigningAlgorithms);
    if (!isKmsKeyAlgorithm(algorithm.algorithm ?? '')) {
      throw new KmsUnsupportedAlgorithmError(
        `AWS KMS key ${this.keyId} reports no supported key spec`,
        { provider: 'aws' },
      );
    }

    const publicKeyResponse = await this.call<{ PublicKey?: string }>('GetPublicKey', {
      KeyId: this.keyId,
    });
    if (typeof publicKeyResponse.PublicKey !== 'string') {
      throw new KmsError('invalid-public-key', 'AWS KMS GetPublicKey returned no public key', {
        provider: 'aws',
      });
    }

    const parsed = parsePublicKey(Buffer.from(publicKeyResponse.PublicKey, 'base64'), 'der');
    this.descriptor = {
      provider: 'aws',
      keyId: this.keyId,
      resourceName: metadata.Arn ?? this.keyId,
      algorithm: algorithm.algorithm as KmsKeyAlgorithm,
      publicKey: parsed.publicKey,
      publicKeyPem: parsed.publicKeyPem,
      ...(metadata.KeyState !== undefined ? { keyState: metadata.KeyState } : {}),
      ...(metadata.KeyUsage !== undefined ? { keyUsage: metadata.KeyUsage } : {}),
      ...(algorithm.signingAlgorithm !== undefined
        ? { signingAlgorithm: algorithm.signingAlgorithm }
        : {}),
      ...(metadata.KeyId !== undefined ? { version: metadata.KeyId } : {}),
    };
    return this.descriptor;
  }

  async signDigest(digest: Buffer): Promise<KmsSignResult> {
    const descriptor = await this.describeKey();
    const ed25519 = descriptor.algorithm === 'ECC_NIST_ED25519';
    let attempts = 0;
    const response = await this.call<{
      Signature?: string;
      KeyId?: string;
      SigningAlgorithm?: string;
    }>(
      'Sign',
      {
        KeyId: descriptor.resourceName,
        Message: base64(digest),
        // Ed25519 hashes at the algorithm level, so the 32-byte digest is sent
        // as-is. ECDSA_SHA_256 accepts a pre-computed digest explicitly.
        MessageType: ed25519 ? 'RAW' : 'DIGEST',
        SigningAlgorithm:
          descriptor.signingAlgorithm ?? (ed25519 ? 'ECC_NIST_ED25519' : 'ECDSA_SHA_256'),
      },
      (attempt) => {
        attempts = attempt;
      },
    );

    if (typeof response.Signature !== 'string') {
      throw new KmsError('invalid-signature', 'AWS KMS Sign returned no signature', {
        provider: 'aws',
      });
    }

    return {
      signature: Buffer.from(response.Signature, 'base64'),
      attempts,
      ...(response.KeyId !== undefined ? { keyVersion: response.KeyId } : {}),
      ...(response.SigningAlgorithm !== undefined
        ? { signingAlgorithm: response.SigningAlgorithm }
        : {}),
    };
  }

  private credentialsFromEnv(): AwsCredentials {
    const accessKeyId = this.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = this.env.AWS_SECRET_ACCESS_KEY;
    if (accessKeyId === undefined || accessKeyId === '' || secretAccessKey === undefined) {
      throw new KmsAuthorizationError(
        'AWS credentials are not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY ' +
          '(and AWS_SESSION_TOKEN for temporary credentials) using the standard AWS provider.',
        { provider: 'aws' },
      );
    }
    return {
      accessKeyId,
      secretAccessKey,
      ...(this.env.AWS_SESSION_TOKEN !== undefined && this.env.AWS_SESSION_TOKEN !== ''
        ? { sessionToken: this.env.AWS_SESSION_TOKEN }
        : {}),
    };
  }

  /** One SigV4-signed JSON request, retried on throttling and 5xx only. */
  private async call<T>(
    action: string,
    body: Record<string, unknown>,
    onAttempt?: (attempt: number) => void,
  ): Promise<T> {
    return withKmsRetry(async (attempt) => {
      onAttempt?.(attempt);
      const credentials = await this.credentials();
      const target = `${TARGET_PREFIX}.${action}`;
      const payload = JSON.stringify(body);
      const headers = this.signRequest(credentials, target, payload);
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers,
        body: payload,
      });

      if (!response.ok) {
        throw await kmsHttpError(response, 'aws');
      }
      return (await response.json()) as T;
    }, this.retry);
  }

  private async credentials(): Promise<AwsCredentials> {
    return typeof this.credentialProvider === 'function'
      ? this.credentialProvider()
      : this.credentialProvider;
  }

  /** Builds SigV4 headers. The secret is used for HMACs and then discarded. */
  private signRequest(
    credentials: AwsCredentials,
    target: string,
    payload: string,
  ): Record<string, string> {
    const url = new URL(this.endpoint);
    const host = url.host;
    const amzDate = this.now()
      .toISOString()
      .replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const headers: Record<string, string> = {
      'content-type': JSON_CONTENT_TYPE,
      host,
      'x-amz-date': amzDate,
      'x-amz-target': target,
    };
    if (credentials.sessionToken !== undefined) {
      headers['x-amz-security-token'] = credentials.sessionToken;
    }

    const signedHeaderNames = Object.keys(headers).sort();
    const signedHeaders = signedHeaderNames.join(';');
    const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headers[name]}\n`).join('');
    const payloadHash = createHash('sha256').update(payload).digest('hex');

    const canonicalRequest = [
      'POST',
      url.pathname === '' ? '/' : url.pathname,
      sortedQuery(url.searchParams),
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join('\n');

    const scope = `${dateStamp}/${this.region}/${SERVICE}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      scope,
      createHash('sha256').update(canonicalRequest).digest('hex'),
    ].join('\n');

    const signingKey = hmac(
      hmac(hmac(hmac(`AWS4${credentials.secretAccessKey}`, dateStamp), this.region), SERVICE),
      'aws4_request',
    );
    const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

    return {
      ...headers,
      authorization:
        `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, ` +
        `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    };
  }
}

function hmac(key: string | Buffer, value: string): Buffer {
  return createHmac('sha256', key).update(value).digest();
}

function sortedQuery(params: URLSearchParams): string {
  const entries = [...params.entries()].sort(([a, aValue], [b, bValue]) =>
    a === b ? aValue.localeCompare(bValue) : a.localeCompare(b),
  );
  return entries.map(([key, value]) => `${encodeRfc3986(key)}=${encodeRfc3986(value)}`).join('&');
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}
