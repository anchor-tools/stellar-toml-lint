/**
 * Google Cloud KMS adapter.
 *
 * Uses the Cloud KMS REST API over an OAuth 2.0 bearer token. The token comes
 * from Google's standard credential sources: `GOOGLE_OAUTH_ACCESS_TOKEN` for
 * pre-issued tokens, `GOOGLE_APPLICATION_CREDENTIALS` for a service-account
 * JSON key, or the GCE metadata server under Application Default Credentials.
 * No token is retained on a descriptor or included in an error.
 */
import { readFileSync } from 'node:fs';
import { createSign } from 'node:crypto';
import {
  KmsAuthorizationError,
  KmsError,
  KmsUnsupportedAlgorithmError,
  base64,
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

const API_ROOT = 'https://cloudkms.googleapis.com/v1';
const CLOUD_KMS_SCOPE = 'https://www.googleapis.com/auth/cloudkms';
const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';

export interface GcpKmsClientOptions {
  keyId: string;
  accessToken?: string | (() => Promise<string>);
  endpoint?: string;
  fetchImpl?: typeof fetch;
  retry?: KmsRetryOptions;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

interface ServiceAccount {
  client_email?: string;
  private_key?: string;
  token_uri?: string;
}

interface CachedToken {
  token: string;
  expiresAt: number;
}

/** True for a Cloud KMS crypto key or crypto key version resource name. */
export function isGcpKmsKeyId(value: string): boolean {
  return /^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+(?:\/cryptoKeyVersions\/[^/]+)?$/.test(
    value,
  );
}

/** Maps a Cloud KMS algorithm name onto the two Stellar-compatible families. */
export function gcpAlgorithm(value: string): KmsKeyAlgorithm | undefined {
  if (value === 'EC_SIGN_ED25519') return 'ECC_NIST_ED25519';
  if (value === 'EC_SIGN_SECP256K1_SHA256') return 'ECC_SECG_P256K1';
  return undefined;
}

export class GcpKmsClient implements KmsClient {
  readonly provider: KmsProvider = 'gcp';
  private readonly keyId: string;
  private readonly apiRoot: string;
  private readonly fetchImpl: typeof fetch;
  private readonly retry: KmsRetryOptions;
  private readonly env: NodeJS.ProcessEnv;
  private readonly now: () => Date;
  private readonly tokenProvider: string | (() => Promise<string>) | undefined;
  private cachedToken?: CachedToken;
  private descriptor?: KmsKeyDescriptor;
  private resolvedVersion?: string;

  constructor(options: GcpKmsClientOptions) {
    this.keyId = options.keyId;
    this.apiRoot = options.endpoint ?? API_ROOT;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.retry = options.retry ?? {};
    this.env = options.env ?? process.env;
    this.now = options.now ?? (() => new Date());
    this.tokenProvider = options.accessToken;
    if (!isGcpKmsKeyId(options.keyId)) {
      throw new KmsError(
        'unsupported-key-id',
        `Google Cloud KMS key must look like projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>[/cryptoKeyVersions/<version>]`,
        { provider: 'gcp' },
      );
    }
  }

  async describeKey(): Promise<KmsKeyDescriptor> {
    if (this.descriptor !== undefined) return this.descriptor;

    const version = await this.versionName();
    const response = await this.get<{ pem?: string; algorithm?: string; name?: string }>(
      `${version}/publicKey`,
    );

    if (typeof response.pem !== 'string' || typeof response.algorithm !== 'string') {
      throw new KmsError(
        'invalid-public-key',
        'Google Cloud KMS publicKey returned no PEM or algorithm',
        { provider: 'gcp' },
      );
    }

    const algorithm = gcpAlgorithm(response.algorithm);
    if (algorithm === undefined) {
      throw new KmsUnsupportedAlgorithmError(
        `Google Cloud KMS algorithm ${response.algorithm} is not Ed25519 or secp256k1`,
        { provider: 'gcp' },
      );
    }

    const parsed = parsePublicKey(response.pem, 'pem');
    this.descriptor = {
      provider: 'gcp',
      keyId: this.keyId,
      resourceName: response.name ?? version,
      algorithm,
      publicKey: parsed.publicKey,
      publicKeyPem: parsed.publicKeyPem,
      keyUsage: 'ASYMMETRIC_SIGN',
      signingAlgorithm: response.algorithm,
      version,
    };
    return this.descriptor;
  }

  async signDigest(digest: Buffer): Promise<KmsSignResult> {
    const descriptor = await this.describeKey();
    const version = this.resolvedVersion ?? (await this.versionName());
    const body =
      descriptor.algorithm === 'ECC_NIST_ED25519'
        ? // Ed25519 in Cloud KMS only accepts `data`; the 32-byte Stellar
          // digest is passed through unchanged.
          { data: base64(digest) }
        : { digest: { sha256: base64(digest) } };

    let attempts = 0;
    const response = await this.post<{ signature?: string; name?: string }>(
      `${version}:asymmetricSign`,
      body,
      (attempt) => {
        attempts = attempt;
      },
    );
    if (typeof response.signature !== 'string') {
      throw new KmsError('invalid-signature', 'Google Cloud KMS returned no signature', {
        provider: 'gcp',
      });
    }

    return {
      signature: Buffer.from(response.signature, 'base64'),
      attempts,
      ...(descriptor.version !== undefined ? { keyVersion: descriptor.version } : {}),
      ...(descriptor.signingAlgorithm !== undefined
        ? { signingAlgorithm: descriptor.signingAlgorithm }
        : {}),
    };
  }

  /** Resolves a bare crypto key to its primary version resource name. */
  private async versionName(): Promise<string> {
    if (this.resolvedVersion !== undefined) return this.resolvedVersion;
    if (/\/cryptoKeyVersions\/[^/]+$/.test(this.keyId)) {
      this.resolvedVersion = this.keyId;
      return this.resolvedVersion;
    }

    const response = await this.get<{ primary?: { name?: string } }>(this.keyId);
    const primary = response.primary?.name;
    if (typeof primary !== 'string' || primary === '') {
      throw new KmsError(
        'key-not-enabled',
        `Google Cloud KMS key ${this.keyId} has no primary version to sign with`,
        { provider: 'gcp' },
      );
    }
    this.resolvedVersion = primary;
    return primary;
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  private async post<T>(
    path: string,
    body: Record<string, unknown>,
    onAttempt?: (attempt: number) => void,
  ): Promise<T> {
    return this.request<T>('POST', path, body, onAttempt);
  }

  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    body?: Record<string, unknown>,
    onAttempt?: (attempt: number) => void,
  ): Promise<T> {
    return withKmsRetry(async (attempt) => {
      onAttempt?.(attempt);
      const token = await this.accessToken();
      const url = path.startsWith('https://') ? path : `${this.apiRoot}/${path}`;
      const response = await this.fetchImpl(url, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });

      if (!response.ok) throw await kmsHttpError(response, 'gcp');
      return (await response.json()) as T;
    }, this.retry);
  }

  private async accessToken(): Promise<string> {
    if (this.cachedToken !== undefined && this.cachedToken.expiresAt > this.now().getTime()) {
      return this.cachedToken.token;
    }
    if (typeof this.tokenProvider === 'string') return this.tokenProvider;
    if (typeof this.tokenProvider === 'function') return this.tokenProvider();

    const envToken = this.env.GOOGLE_OAUTH_ACCESS_TOKEN ?? this.env.GCP_ACCESS_TOKEN;
    if (envToken !== undefined && envToken !== '') return envToken;

    const credentialsFile = this.env.GOOGLE_APPLICATION_CREDENTIALS;
    if (credentialsFile !== undefined && credentialsFile !== '') {
      return this.serviceAccountToken(credentialsFile);
    }

    // Application Default Credentials on GCE/GKE/Cloud Run.
    try {
      const host = this.env.GCE_METADATA_HOST ?? 'metadata.google.internal';
      const response = await this.fetchImpl(
        `http://${host}/computeMetadata/v1/instance/service-accounts/default/token`,
        { headers: { 'metadata-flavor': 'Google' } },
      );
      if (response.ok) {
        const body = (await response.json()) as { access_token?: string; expires_in?: number };
        if (typeof body.access_token === 'string') {
          this.cachedToken = {
            token: body.access_token,
            expiresAt: this.now().getTime() + (body.expires_in ?? 60) * 1000,
          };
          return body.access_token;
        }
      }
    } catch {
      // Falls through to the actionable credential error below.
    }

    throw new KmsAuthorizationError(
      'Google Cloud credentials are not configured. Set GOOGLE_OAUTH_ACCESS_TOKEN or ' +
        'GOOGLE_APPLICATION_CREDENTIALS, or run under Application Default Credentials.',
      { provider: 'gcp' },
    );
  }

  /** Exchanges a service-account JSON key for a scoped OAuth token. */
  private async serviceAccountToken(file: string): Promise<string> {
    let account: ServiceAccount;
    try {
      account = JSON.parse(readFileSync(file, 'utf8')) as ServiceAccount;
    } catch {
      throw new KmsAuthorizationError(
        'GOOGLE_APPLICATION_CREDENTIALS could not be read as a service-account JSON key',
        { provider: 'gcp' },
      );
    }
    if (typeof account.client_email !== 'string' || typeof account.private_key !== 'string') {
      throw new KmsAuthorizationError(
        'GOOGLE_APPLICATION_CREDENTIALS is missing client_email or private_key',
        { provider: 'gcp' },
      );
    }

    const tokenUri = account.token_uri ?? DEFAULT_TOKEN_URI;
    const issuedAt = Math.floor(this.now().getTime() / 1000);
    const header = base64UrlJson({ alg: 'RS256', typ: 'JWT' });
    const claims = base64UrlJson({
      iss: account.client_email,
      scope: CLOUD_KMS_SCOPE,
      aud: tokenUri,
      iat: issuedAt,
      exp: issuedAt + 3600,
    });
    const signingInput = `${header}.${claims}`;
    const signer = createSign('RSA-SHA256');
    signer.update(signingInput);
    const jwt = `${signingInput}.${signer.sign(account.private_key, 'base64url')}`;

    const response = await this.fetchImpl(tokenUri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
      }).toString(),
    });
    if (!response.ok) {
      throw await kmsHttpError(response, 'gcp');
    }

    const body = (await response.json()) as { access_token?: string; expires_in?: number };
    if (typeof body.access_token !== 'string') {
      throw new KmsAuthorizationError('Google token exchange returned no access_token', {
        provider: 'gcp',
      });
    }
    this.cachedToken = {
      token: body.access_token,
      expiresAt: this.now().getTime() + Math.max(60, (body.expires_in ?? 3600) - 60) * 1000,
    };
    return body.access_token;
  }
}

function base64UrlJson(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}
