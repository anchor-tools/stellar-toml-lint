/**
 * Picks a Cloud KMS adapter from the shape of the key identifier.
 *
 * Keeping detection here means the CLI and the programmable API share exactly
 * one rule for what an AWS ARN, a Cloud KMS resource name, and an Azure key
 * URL look like. Credentials are never part of the decision.
 */
import { AwsKmsClient, isAwsKmsKeyId, type AwsKmsClientOptions } from './awsKmsClient.js';
import { GcpKmsClient, isGcpKmsKeyId, type GcpKmsClientOptions } from './gcpKmsClient.js';
import {
  AzureKeyVaultClient,
  isAzureKeyVaultKeyId,
  type AzureKeyVaultClientOptions,
} from './azureKeyVaultClient.js';
import { KmsError, type KmsClient, type KmsProvider } from './kmsTypes.js';

/** Identifies the provider that owns `keyId`, or throws a usage error. */
export function detectKmsProvider(keyId: string): KmsProvider {
  if (isAwsKmsKeyId(keyId)) return 'aws';
  if (isGcpKmsKeyId(keyId)) return 'gcp';
  if (isAzureKeyVaultKeyId(keyId)) return 'azure';

  throw new KmsError(
    'unsupported-key-id',
    `Unrecognised KMS key identifier. Expected an AWS KMS ARN, a Google Cloud KMS ` +
      `resource name (projects/.../cryptoKeys/...), or an Azure Key Vault key URL.`,
  );
}

/** Options accepted by {@link createKmsClient}; provider-specific fields win. */
export interface CreateKmsClientOptions {
  fetchImpl?: typeof fetch;
  retry?: AwsKmsClientOptions['retry'];
  env?: NodeJS.ProcessEnv;
  aws?: Omit<AwsKmsClientOptions, 'keyId'>;
  gcp?: Omit<GcpKmsClientOptions, 'keyId'>;
  azure?: Omit<AzureKeyVaultClientOptions, 'keyId'>;
}

/** Builds the adapter for `keyId`, configured from standard credentials. */
export function createKmsClient(keyId: string, options: CreateKmsClientOptions = {}): KmsClient {
  const provider = detectKmsProvider(keyId);
  switch (provider) {
    case 'aws':
      return new AwsKmsClient({
        keyId,
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.retry !== undefined ? { retry: options.retry } : {}),
        ...(options.env !== undefined ? { env: options.env } : {}),
        ...options.aws,
      });
    case 'gcp':
      return new GcpKmsClient({
        keyId,
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.retry !== undefined ? { retry: options.retry } : {}),
        ...(options.env !== undefined ? { env: options.env } : {}),
        ...options.gcp,
      });
    case 'azure':
      return new AzureKeyVaultClient({
        keyId,
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.retry !== undefined ? { retry: options.retry } : {}),
        ...(options.env !== undefined ? { env: options.env } : {}),
        ...options.azure,
      });
  }
}
