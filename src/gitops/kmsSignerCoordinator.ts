/**
 * Cloud KMS multi-signature hardware signer coordinator.
 *
 * The coordinator takes a Stellar transaction envelope, asks a cloud HSM to
 * sign the envelope's 32-byte hash, proves the response is a structurally valid
 * `DecoratedSignature`, verifies it cryptographically, and finally checks the
 * matching Stellar account signer weight against the account's threshold on
 * Horizon. That is the full chain an anchor needs before trusting a KMS key as
 * a quorum member, without ever handling a raw private key.
 */
import {
  FeeBumpTransaction,
  Networks,
  TransactionBuilder,
  xdr,
  type Transaction,
} from '@stellar/stellar-base';
import { trimTrailingSlashes } from '../strings.js';
import { createKmsClient, type CreateKmsClientOptions } from './kmsClientFactory.js';
import {
  KmsError,
  KmsUnsupportedAlgorithmError,
  base64,
  isKmsKeyAlgorithm,
  redactSecrets,
  signatureHint,
  signatureToStellarFormat,
  stellarAddressFor,
  verifySignature,
  type KmsClient,
  type KmsKeyAlgorithm,
  type KmsProvider,
  type KmsRetryOptions,
} from './kmsTypes.js';

/** Threshold level a transaction needs; operations use `medium` by default. */
export type KmsThresholdLevel = 'low' | 'medium' | 'high';

export interface CloudKmsSignerCoordinatorOptions {
  /** AWS ARN, Google Cloud KMS resource name, or Azure Key Vault key URL. */
  keyId: string;
  /** Base64 transaction envelope XDR to sign. */
  envelope: string;
  /** Network the envelope belongs to. Defaults to the Stellar public network. */
  networkPassphrase?: string;
  /** Horizon base URL; defaults from the network passphrase. */
  horizonUrl?: string;
  /** Account whose signer list is audited. Defaults to the envelope source. */
  accountId?: string;
  /** Override the Stellar `G...` signer matched against the KMS public key. */
  signerKey?: string;
  /** Threshold the key must satisfy. Defaults to `medium`. */
  threshold?: KmsThresholdLevel;
  /** Skip the Horizon quorum audit (offline runs). */
  skipQuorumCheck?: boolean;
  /** Inject a client, e.g. a mock HSM or a preconfigured adapter. */
  client?: KmsClient;
  fetchImpl?: typeof fetch;
  retry?: KmsRetryOptions;
  env?: NodeJS.ProcessEnv;
  /** Provider-specific adapter overrides (endpoints, credentials sources). */
  clients?: CreateKmsClientOptions;
  /** Verify the returned signature locally. Defaults to true. */
  verifySignature?: boolean;
}

export interface KmsSignerCheck {
  id: 'key-configuration' | 'envelope' | 'signature-format' | 'signature-verification' | 'quorum';
  ok: boolean;
  message: string;
}

export interface KmsQuorumReport {
  checked: boolean;
  met: boolean;
  accountId?: string;
  signerKey?: string;
  signerWeight?: number;
  thresholdName: KmsThresholdLevel;
  threshold?: number;
  reason?: string;
}

export interface CloudKmsSignerReport {
  ok: boolean;
  key: {
    provider: KmsProvider;
    keyId: string;
    resourceName: string;
    algorithm: KmsKeyAlgorithm;
    publicKey: string;
    publicKeyHex: string;
    stellarAddress?: string;
    hint: string;
    keyState?: string;
    keyUsage?: string;
  };
  transaction: {
    type: 'transaction' | 'fee-bump';
    source: string;
    networkPassphrase: string;
    hash: string;
  };
  signature?: {
    value: string;
    decoratedXdr: string;
    length: number;
    format: 'raw' | 'der-converted';
    verified: boolean;
    attempts: number;
  };
  quorum: KmsQuorumReport;
  checks: KmsSignerCheck[];
  warnings: string[];
}

const THRESHOLD_FIELDS: Record<KmsThresholdLevel, string> = {
  low: 'low_threshold',
  medium: 'med_threshold',
  high: 'high_threshold',
};

/** Horizon instances the coordinator can derive without extra flags. */
const HORIZON_BY_NETWORK: Record<string, string> = {
  [Networks.PUBLIC]: 'https://horizon.stellar.org',
  [Networks.TESTNET]: 'https://horizon-testnet.stellar.org',
  [Networks.FUTURENET]: 'https://horizon-futurenet.stellar.org',
};

export class CloudKmsSignerCoordinator {
  private readonly options: CloudKmsSignerCoordinatorOptions;
  private readonly fetchImpl: typeof fetch;
  private client?: KmsClient;

  constructor(options: CloudKmsSignerCoordinatorOptions) {
    this.options = options;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async run(): Promise<CloudKmsSignerReport> {
    const networkPassphrase = this.options.networkPassphrase ?? Networks.PUBLIC;
    const checks: KmsSignerCheck[] = [];
    const warnings: string[] = [];

    let transaction: Transaction | FeeBumpTransaction;
    try {
      transaction = TransactionBuilder.fromXDR(this.options.envelope, networkPassphrase);
    } catch (error) {
      throw new KmsError(
        'invalid-envelope',
        `Envelope is not a valid base64 Stellar transaction for this network: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    const signatureBase = transaction.signatureBase();
    const digest = transaction.hash();
    const source =
      transaction instanceof FeeBumpTransaction
        ? transaction.innerTransaction.source
        : transaction.source;

    checks.push({
      id: 'envelope',
      ok: true,
      message: `Parsed ${transaction instanceof FeeBumpTransaction ? 'fee-bump ' : ''}transaction ${transaction.hash().toString('hex')}`,
    });

    const client = await this.resolveClient();
    const descriptor = await client.describeKey();
    checks.push({
      id: 'key-configuration',
      ok: true,
      message: `${descriptor.provider} key ${descriptor.resourceName} reports ${descriptor.algorithm}`,
    });

    const stellarAddress = stellarAddressFor(descriptor.publicKey);
    const signerKey = this.options.signerKey ?? stellarAddress;

    if (!isKmsKeyAlgorithm(descriptor.algorithm)) {
      throw new KmsUnsupportedAlgorithmError(
        `KMS key algorithm ${String(descriptor.algorithm)} cannot sign Stellar transactions`,
        { provider: descriptor.provider },
      );
    }

    const signResult = await client.signDigest(digest);
    const converted = signatureToStellarFormat(signResult.signature, descriptor.algorithm);
    const hint = signatureHint(descriptor.publicKey);
    const decorated = new xdr.DecoratedSignature({
      hint,
      signature: converted.signature,
    });
    const decoratedXdr = decorated.toXDR('base64');

    checks.push({
      id: 'signature-format',
      ok: true,
      message: `${converted.signature.length}-byte ${converted.format} signature packs into DecoratedSignature XDR`,
    });

    let verified = false;
    if (this.options.verifySignature !== false) {
      verified = verifySignature(
        descriptor.publicKeyPem,
        descriptor.algorithm,
        converted.signature,
        digest,
        signatureBase,
      );
      checks.push({
        id: 'signature-verification',
        ok: verified,
        message: verified
          ? 'KMS signature verifies against the transaction digest'
          : 'KMS signature does not verify against the transaction digest',
      });
    } else {
      warnings.push('Local signature verification was disabled');
    }

    const quorum = await this.checkQuorum({
      accountId: this.options.accountId ?? source,
      signerKey,
      algorithm: descriptor.algorithm,
      networkPassphrase,
      warnings,
      checks,
    });

    return {
      ok: checks.every((check) => check.ok),
      key: {
        provider: descriptor.provider,
        keyId: descriptor.keyId,
        resourceName: descriptor.resourceName,
        algorithm: descriptor.algorithm,
        publicKey: base64(descriptor.publicKey),
        publicKeyHex: descriptor.publicKey.toString('hex'),
        ...(stellarAddress !== undefined ? { stellarAddress } : {}),
        hint: hint.toString('hex'),
        ...(descriptor.keyState !== undefined ? { keyState: descriptor.keyState } : {}),
        ...(descriptor.keyUsage !== undefined ? { keyUsage: descriptor.keyUsage } : {}),
      },
      transaction: {
        type: transaction instanceof FeeBumpTransaction ? 'fee-bump' : 'transaction',
        source,
        networkPassphrase,
        hash: digest.toString('hex'),
      },
      signature: {
        value: base64(converted.signature),
        decoratedXdr,
        length: converted.signature.length,
        format: converted.format,
        verified,
        attempts: signResult.attempts ?? 1,
      },
      quorum,
      checks,
      warnings,
    };
  }

  private async resolveClient(): Promise<KmsClient> {
    if (this.client !== undefined) return this.client;
    if (this.options.client !== undefined) {
      this.client = this.options.client;
      return this.client;
    }

    const options: CreateKmsClientOptions = {
      fetchImpl: this.fetchImpl,
      ...(this.options.retry !== undefined ? { retry: this.options.retry } : {}),
      ...(this.options.env !== undefined ? { env: this.options.env } : {}),
      ...this.options.clients,
    };
    this.client = createKmsClient(this.options.keyId, options);
    return this.client;
  }

  /**
   * Reads the account's signer list from Horizon and compares the KMS key's
   * weight with the threshold the requested operation class needs.
   *
   * A failure here is a failed check, not an exception: an operator needs the
   * signature report even when Horizon is unreachable.
   */
  private async checkQuorum(input: {
    accountId: string;
    signerKey: string | undefined;
    algorithm: KmsKeyAlgorithm;
    networkPassphrase: string;
    warnings: string[];
    checks: KmsSignerCheck[];
  }): Promise<KmsQuorumReport> {
    const thresholdName = this.options.threshold ?? 'medium';
    const base: KmsQuorumReport = {
      checked: false,
      met: false,
      accountId: input.accountId,
      thresholdName,
    };

    if (this.options.skipQuorumCheck === true) {
      input.warnings.push('Horizon quorum check skipped (--no-quorum)');
      return { ...base, reason: 'skipped' };
    }

    if (input.signerKey === undefined) {
      const reason =
        input.algorithm === 'ECC_SECG_P256K1'
          ? 'secp256k1 keys have no Stellar G... account encoding; pass --signer-key to audit quorum'
          : 'KMS public key could not be mapped to a Stellar account signer';
      input.warnings.push(reason);
      return { ...base, reason };
    }

    base.signerKey = input.signerKey;
    const horizonUrl = this.options.horizonUrl ?? HORIZON_BY_NETWORK[input.networkPassphrase];
    if (horizonUrl === undefined) {
      const reason = `No Horizon URL is known for ${input.networkPassphrase}; pass --horizon to audit quorum`;
      input.warnings.push(reason);
      return { ...base, reason };
    }

    try {
      const response = await this.fetchImpl(
        `${trimTrailingSlashes(horizonUrl)}/accounts/${input.accountId}`,
      );
      if (!response.ok) {
        const reason = `Horizon returned HTTP ${response.status} for account ${input.accountId}`;
        input.checks.push({ id: 'quorum', ok: false, message: reason });
        return { ...base, reason };
      }

      const body = (await response.json()) as {
        thresholds?: Record<string, number>;
        signers?: Array<{ key?: string; weight?: number; type?: string }>;
      };
      const threshold = body.thresholds?.[THRESHOLD_FIELDS[thresholdName]];
      const signer = body.signers?.find((entry) => entry.key === input.signerKey);

      if (threshold === undefined) {
        const reason = `Horizon response for ${input.accountId} has no ${THRESHOLD_FIELDS[thresholdName]}`;
        input.checks.push({ id: 'quorum', ok: false, message: reason });
        return { ...base, reason };
      }

      const weight = signer?.weight ?? 0;
      const met = weight >= threshold;
      input.checks.push({
        id: 'quorum',
        ok: met,
        message: met
          ? `Signer ${input.signerKey} weight ${weight} meets the ${thresholdName} threshold ${threshold}`
          : `Signer ${input.signerKey} weight ${weight} is below the ${thresholdName} threshold ${threshold}`,
      });

      return {
        ...base,
        checked: true,
        met,
        signerWeight: weight,
        threshold,
        ...(met ? {} : { reason: 'insufficient-signer-weight' }),
      };
    } catch (error) {
      const reason = redactSecrets(
        `Horizon quorum check failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      input.checks.push({ id: 'quorum', ok: false, message: reason });
      return { ...base, reason };
    }
  }
}

/** Convenience wrapper for one-shot checks. */
export function runCloudKmsSignerCheck(
  options: CloudKmsSignerCoordinatorOptions,
): Promise<CloudKmsSignerReport> {
  return new CloudKmsSignerCoordinator(options).run();
}
