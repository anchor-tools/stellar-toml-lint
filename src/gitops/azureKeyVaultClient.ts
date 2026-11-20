/**
 * Azure Key Vault / Managed HSM adapter.
 *
 * A key identifier is the vault URL plus the key name and optional version:
 * `https://my-vault.vault.azure.net/keys/stellar-signer/<version>`. The public
 * key and signature endpoints are reached with a bearer token from
 * `AZURE_ACCESS_TOKEN` or an `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` /
 * `AZURE_CLIENT_SECRET` service principal, both standard environment sources.
 */
import { trimTrailingSlashes } from '../strings.js';
import {
  KmsAuthorizationError,
  KmsError,
  KmsUnsupportedAlgorithmError,
  base64Url,
  compressEcPoint,
  decodeBase64,
  kmsHttpError,
  withKmsRetry,
  type KmsClient,
  type KmsKeyAlgorithm,
  type KmsKeyDescriptor,
  type KmsProvider,
  type KmsRetryOptions,
  type KmsSignResult,
} from './kmsTypes.js';

const API_VERSION = '7.4';

export interface AzureKeyVaultClientOptions {
  keyId: string;
  accessToken?: string | (() => Promise<string>);
  fetchImpl?: typeof fetch;
  retry?: KmsRetryOptions;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

interface CachedToken {
  token: string;
  expiresAt: number;
}

interface AzureKeyBundle {
  key?: {
    kid?: string;
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };
  attributes?: {
    enabled?: boolean;
  };
}

/** True for a Key Vault or Managed HSM key identifier URL. */
export function isAzureKeyVaultKeyId(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      /(^|\.)(vault\.azure\.net|managedhsm\.azure\.net)$/i.test(url.hostname) &&
      /^\/keys\/[^/]+(?:\/[^/]+)?\/?$/.test(url.pathname)
    );
  } catch {
    return false;
  }
}

/** Maps an Azure key curve to a Stellar-compatible algorithm. */
export function azureAlgorithm(bundle: AzureKeyBundle): KmsKeyAlgorithm | undefined {
  const crv = bundle.key?.crv;
  if (crv === 'P-256K' || crv === 'secp256k1') return 'ECC_SECG_P256K1';
  if (crv === 'Ed25519' || bundle.key?.kty === 'OKP') return 'ECC_NIST_ED25519';
  return undefined;
}

export class AzureKeyVaultClient implements KmsClient {
  readonly provider: KmsProvider = 'azure';
  private readonly keyId: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly retry: KmsRetryOptions;
  private readonly env: NodeJS.ProcessEnv;
  private readonly now: () => Date;
  private readonly tokenProvider: string | (() => Promise<string>) | undefined;
  private cachedToken?: CachedToken;
  private descriptor?: KmsKeyDescriptor;

  constructor(options: AzureKeyVaultClientOptions) {
    if (!isAzureKeyVaultKeyId(options.keyId)) {
      throw new KmsError(
        'unsupported-key-id',
        'Azure key identifier must be https://<vault>.vault.azure.net/keys/<name>[/<version>]',
        { provider: 'azure' },
      );
    }
    this.keyId = trimTrailingSlashes(options.keyId);
    this.baseUrl = this.keyId;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.retry = options.retry ?? {};
    this.env = options.env ?? process.env;
    this.now = options.now ?? (() => new Date());
    this.tokenProvider = options.accessToken;
  }

  async describeKey(): Promise<KmsKeyDescriptor> {
    if (this.descriptor !== undefined) return this.descriptor;

    const bundle = await this.get<AzureKeyBundle>(`${this.baseUrl}?api-version=${API_VERSION}`);
    if (bundle.attributes?.enabled === false) {
      throw new KmsError('key-not-enabled', 'Azure key is disabled; enable it to sign', {
        provider: 'azure',
      });
    }

    const algorithm = azureAlgorithm(bundle);
    if (algorithm === undefined) {
      throw new KmsUnsupportedAlgorithmError(
        `Azure key type ${bundle.key?.kty ?? 'unknown'}/${bundle.key?.crv ?? 'unknown'} is not Ed25519 or secp256k1`,
        { provider: 'azure' },
      );
    }

    let publicKey: Buffer;
    if (algorithm === 'ECC_NIST_ED25519') {
      if (typeof bundle.key?.x !== 'string') {
        throw new KmsError('invalid-public-key', 'Azure key is missing its x coordinate', {
          provider: 'azure',
        });
      }
      publicKey = Buffer.from(bundle.key.x, 'base64url');
    } else {
      if (typeof bundle.key?.x !== 'string' || typeof bundle.key?.y !== 'string') {
        throw new KmsError('invalid-public-key', 'Azure EC key is missing x or y coordinates', {
          provider: 'azure',
        });
      }
      publicKey = compressEcPoint(
        Buffer.from(bundle.key.x, 'base64url'),
        Buffer.from(bundle.key.y, 'base64url'),
      );
    }

    const kid = bundle.key?.kid ?? this.baseUrl;
    this.descriptor = {
      provider: 'azure',
      keyId: this.keyId,
      resourceName: kid,
      algorithm,
      publicKey,
      publicKeyPem: publicKeyPem(publicKey, algorithm),
      keyState: 'enabled',
      keyUsage: 'sign',
      signingAlgorithm: algorithm === 'ECC_NIST_ED25519' ? 'EdDSA' : 'ES256K',
      version: kid,
    };
    return this.descriptor;
  }

  async signDigest(digest: Buffer): Promise<KmsSignResult> {
    const descriptor = await this.describeKey();
    const algorithm = descriptor.algorithm === 'ECC_NIST_ED25519' ? 'EdDSA' : 'ES256K';
    let attempts = 0;
    const response = await this.post<{ kid?: string; value?: string }>(
      `${descriptor.resourceName}/sign?api-version=${API_VERSION}`,
      { alg: algorithm, value: base64Url(digest) },
      (attempt) => {
        attempts = attempt;
      },
    );

    if (typeof response.value !== 'string') {
      throw new KmsError('invalid-signature', 'Azure Key Vault sign returned no value', {
        provider: 'azure',
      });
    }

    return {
      signature: decodeBase64(response.value),
      attempts,
      ...(response.kid !== undefined ? { keyVersion: response.kid } : {}),
      signingAlgorithm: algorithm,
    };
  }

  private async get<T>(url: string): Promise<T> {
    return this.request<T>('GET', url);
  }

  private async post<T>(
    url: string,
    body: Record<string, unknown>,
    onAttempt?: (attempt: number) => void,
  ): Promise<T> {
    return this.request<T>('POST', url, body, onAttempt);
  }

  private async request<T>(
    method: 'GET' | 'POST',
    url: string,
    body?: Record<string, unknown>,
    onAttempt?: (attempt: number) => void,
  ): Promise<T> {
    return withKmsRetry(async (attempt) => {
      onAttempt?.(attempt);
      const token = await this.accessToken();
      const response = await this.fetchImpl(url, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) throw await kmsHttpError(response, 'azure');
      return (await response.json()) as T;
    }, this.retry);
  }

  private async accessToken(): Promise<string> {
    if (this.cachedToken !== undefined && this.cachedToken.expiresAt > this.now().getTime()) {
      return this.cachedToken.token;
    }
    if (typeof this.tokenProvider === 'string') return this.tokenProvider;
    if (typeof this.tokenProvider === 'function') return this.tokenProvider();

    const envToken = this.env.AZURE_ACCESS_TOKEN;
    if (envToken !== undefined && envToken !== '') return envToken;

    const tenant = this.env.AZURE_TENANT_ID;
    const clientId = this.env.AZURE_CLIENT_ID;
    const clientSecret = this.env.AZURE_CLIENT_SECRET;
    if (
      tenant === undefined ||
      tenant === '' ||
      clientId === undefined ||
      clientId === '' ||
      clientSecret === undefined ||
      clientSecret === ''
    ) {
      throw new KmsAuthorizationError(
        'Azure credentials are not configured. Set AZURE_ACCESS_TOKEN or AZURE_TENANT_ID, ' +
          'AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET using the standard Azure provider.',
        { provider: 'azure' },
      );
    }

    const authority = this.env.AZURE_AUTHORITY_HOST ?? 'https://login.microsoftonline.com';
    const response = await this.fetchImpl(
      `${authority.replace(/\/+$/, '')}/${tenant}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: clientId,
          client_secret: clientSecret,
          scope: 'https://vault.azure.net/.default',
        }).toString(),
      },
    );
    if (!response.ok) throw await kmsHttpError(response, 'azure');

    const body = (await response.json()) as { access_token?: string; expires_in?: number };
    if (typeof body.access_token !== 'string') {
      throw new KmsAuthorizationError('Azure token exchange returned no access_token', {
        provider: 'azure',
      });
    }
    this.cachedToken = {
      token: body.access_token,
      expiresAt: this.now().getTime() + Math.max(60, (body.expires_in ?? 3600) - 60) * 1000,
    };
    return body.access_token;
  }
}

/**
 * Builds the SubjectPublicKeyInfo PEM Azure's JWK coordinates do not supply.
 *
 * The ASN.1 prefixes are fixed for the two curves the harness accepts, which
 * keeps this dependency-free while still producing a key Node can verify.
 */
function publicKeyPem(publicKey: Buffer, algorithm: KmsKeyAlgorithm): string {
  const prefix =
    algorithm === 'ECC_NIST_ED25519'
      ? Buffer.from('302a300506032b6570032100', 'hex')
      : Buffer.concat([Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex')]);
  const der = Buffer.concat([prefix, publicKey]);
  return `-----BEGIN PUBLIC KEY-----\n${wrap(der.toString('base64'))}\n-----END PUBLIC KEY-----\n`;
}

function wrap(base64: string): string {
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) lines.push(base64.slice(i, i + 64));
  return lines.join('\n');
}
