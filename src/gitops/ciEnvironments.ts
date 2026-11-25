/**
 * Deployment environment profiles for the multi-environment CI matrix.
 *
 * Anchors that run several tenants of the same stack (local development,
 * staging, testnet, production) publish one `stellar.toml` per tenant. Each
 * profile here records which Stellar network that tenant is allowed to talk to,
 * so CI can catch the classic copy-paste failure: a staging file that still
 * points at the public network, or a production file that advertises a testnet
 * Horizon.
 */

import { parse } from 'smol-toml';
import { SourceIndex } from '../source-index.js';
import type { Diagnostic } from '../types.js';

export const PUBLIC_NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
export const TESTNET_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';
export const FUTURENET_NETWORK_PASSPHRASE = 'Test SDF Future Network ; October 2022';
export const STANDALONE_NETWORK_PASSPHRASE = 'Standalone Network ; February 2017';

export type CiEnvironmentName = 'development' | 'staging' | 'testnet' | 'public';

export interface CiEnvironmentProfile {
  name: CiEnvironmentName;
  /** Human label used in scorecards and job names. */
  label: string;
  /** Passphrases a file for this environment may declare. */
  allowedPassphrases: readonly string[];
  /**
   * Whether a missing `NETWORK_PASSPHRASE` is acceptable. SEP-1 consumers
   * assume the public network when it is absent, so only `public` may omit it.
   */
  passphraseOptional: boolean;
  /** Whether the generated workflow enables `--check-network` by default. */
  checkNetworkByDefault: boolean;
  /** Whether hostnames that look like non-production tenants are flagged. */
  rejectNonProductionHosts: boolean;
}

export const CI_ENVIRONMENTS: Readonly<Record<CiEnvironmentName, CiEnvironmentProfile>> = {
  development: {
    name: 'development',
    label: 'Development',
    allowedPassphrases: [
      STANDALONE_NETWORK_PASSPHRASE,
      TESTNET_NETWORK_PASSPHRASE,
      FUTURENET_NETWORK_PASSPHRASE,
    ],
    passphraseOptional: false,
    checkNetworkByDefault: false,
    rejectNonProductionHosts: false,
  },
  staging: {
    name: 'staging',
    label: 'Staging',
    allowedPassphrases: [TESTNET_NETWORK_PASSPHRASE, FUTURENET_NETWORK_PASSPHRASE],
    passphraseOptional: false,
    checkNetworkByDefault: false,
    rejectNonProductionHosts: false,
  },
  testnet: {
    name: 'testnet',
    label: 'Testnet',
    allowedPassphrases: [TESTNET_NETWORK_PASSPHRASE],
    passphraseOptional: false,
    checkNetworkByDefault: true,
    rejectNonProductionHosts: false,
  },
  public: {
    name: 'public',
    label: 'Production (public network)',
    allowedPassphrases: [PUBLIC_NETWORK_PASSPHRASE],
    passphraseOptional: true,
    checkNetworkByDefault: true,
    rejectNonProductionHosts: true,
  },
};

export const CI_ENVIRONMENT_NAMES = Object.keys(CI_ENVIRONMENTS) as CiEnvironmentName[];

/** Aliases accepted on the command line, e.g. `--matrix dev,prod`. */
const ALIASES: Readonly<Record<string, CiEnvironmentName>> = {
  dev: 'development',
  development: 'development',
  local: 'development',
  stage: 'staging',
  staging: 'staging',
  test: 'testnet',
  testnet: 'testnet',
  public: 'public',
  pubnet: 'public',
  mainnet: 'public',
  prod: 'public',
  production: 'public',
};

/** Resolves a user-supplied environment name, or `undefined` if unknown. */
export function resolveCiEnvironment(name: string): CiEnvironmentName | undefined {
  return ALIASES[name.trim().toLowerCase()];
}

/**
 * Parses a comma-separated `--matrix` value into unique, known environments,
 * preserving the order given. Throws on an unknown or empty list so the CLI can
 * report a usage error instead of silently generating a smaller matrix.
 */
export function parseCiMatrix(value: string): CiEnvironmentName[] {
  const names: CiEnvironmentName[] = [];
  for (const raw of value.split(',')) {
    if (raw.trim() === '') continue;
    const resolved = resolveCiEnvironment(raw);
    if (resolved === undefined) {
      throw new Error(
        `Unknown environment "${raw.trim()}". Expected one of: ${CI_ENVIRONMENT_NAMES.join(', ')}`,
      );
    }
    if (!names.includes(resolved)) names.push(resolved);
  }
  if (names.length === 0) throw new Error('--matrix expects at least one environment');
  return names;
}

/** Well-known SDF Horizon hosts and the network each one serves. */
const KNOWN_HORIZON_HOSTS: Readonly<Record<string, string>> = {
  'horizon.stellar.org': PUBLIC_NETWORK_PASSPHRASE,
  'horizon.stellar.lobstr.co': PUBLIC_NETWORK_PASSPHRASE,
  'horizon-testnet.stellar.org': TESTNET_NETWORK_PASSPHRASE,
  'horizon-futurenet.stellar.org': FUTURENET_NETWORK_PASSPHRASE,
};

/** Hostname labels that betray a non-production tenant. */
const NON_PRODUCTION_LABEL =
  /^(?:dev|develop|development|staging|stage|stg|test|testnet|qa|uat|sandbox|local|futurenet)$/;

/** Keys whose values are URLs a wallet will contact. */
const URL_KEYS = [
  'FEDERATION_SERVER',
  'AUTH_SERVER',
  'TRANSFER_SERVER',
  'TRANSFER_SERVER_SEP0024',
  'KYC_SERVER',
  'WEB_AUTH_ENDPOINT',
  'DIRECT_PAYMENT_SERVER',
  'ANCHOR_QUOTE_SERVER',
  'HORIZON_URL',
] as const;

function hostOf(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function isLocalHost(host: string): boolean {
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === '0.0.0.0' ||
    host === '[::1]' ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(?:1[6-9]|2\d|3[01])\./.test(host)
  );
}

function looksNonProduction(host: string): boolean {
  if (isLocalHost(host)) return true;
  return host.split('.').some((label) => NON_PRODUCTION_LABEL.test(label));
}

function networkName(passphrase: string): string {
  switch (passphrase) {
    case PUBLIC_NETWORK_PASSPHRASE:
      return 'public';
    case TESTNET_NETWORK_PASSPHRASE:
      return 'testnet';
    case FUTURENET_NETWORK_PASSPHRASE:
      return 'futurenet';
    case STANDALONE_NETWORK_PASSPHRASE:
      return 'standalone';
    default:
      return 'custom';
  }
}

/**
 * Asserts that a tenant's `stellar.toml` only references the Stellar network
 * its environment is allowed to use.
 *
 * Returns diagnostics in the linter's own shape (rule ids under `ci/`), so they
 * flow through the same SARIF and scorecard reporters as SEP-1 findings. A file
 * that fails to parse yields no isolation findings — the linter already reports
 * the syntax error and there is nothing to inspect.
 */
export function checkNetworkIsolation(
  source: string,
  environment: CiEnvironmentName,
): Diagnostic[] {
  const profile = CI_ENVIRONMENTS[environment];
  // Strip a byte order mark so columns match the linter's own positions.
  const text = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  let doc: Record<string, unknown>;
  try {
    doc = parse(text) as Record<string, unknown>;
  } catch {
    return [];
  }
  const index = new SourceIndex(text);
  const at = (path: string) => {
    const position = index.get(path);
    return position ? { position } : {};
  };
  const diagnostics: Diagnostic[] = [];
  const passphrase = doc.NETWORK_PASSPHRASE;

  if (typeof passphrase === 'string') {
    if (!profile.allowedPassphrases.includes(passphrase)) {
      diagnostics.push({
        rule: 'ci/network-passphrase-mismatch',
        severity: 'error',
        category: 'network',
        message: `The ${profile.label} environment declares the ${networkName(passphrase)} network passphrase`,
        path: 'NETWORK_PASSPHRASE',
        ...at('NETWORK_PASSPHRASE'),
        suggestion: `Use ${profile.allowedPassphrases.map((p) => `"${p}"`).join(' or ')} for ${environment}.`,
      });
    }
  } else if (!profile.passphraseOptional) {
    diagnostics.push({
      rule: 'ci/network-passphrase-missing',
      severity: 'error',
      category: 'network',
      message: `The ${profile.label} environment omits NETWORK_PASSPHRASE, so wallets will assume the public network`,
      suggestion: `Declare NETWORK_PASSPHRASE = "${profile.allowedPassphrases[0]}".`,
    });
  }

  const horizonHost = hostOf(doc.HORIZON_URL);
  const horizonNetwork = horizonHost === undefined ? undefined : KNOWN_HORIZON_HOSTS[horizonHost];
  if (horizonNetwork !== undefined && !profile.allowedPassphrases.includes(horizonNetwork)) {
    diagnostics.push({
      rule: 'ci/horizon-network-mismatch',
      severity: 'error',
      category: 'network',
      message: `HORIZON_URL points at ${horizonHost}, a ${networkName(horizonNetwork)} Horizon, in the ${profile.label} environment`,
      path: 'HORIZON_URL',
      ...at('HORIZON_URL'),
      suggestion: `Point HORIZON_URL at a Horizon instance serving the ${environment} network.`,
    });
  }

  if (profile.rejectNonProductionHosts) {
    for (const key of URL_KEYS) {
      const host = hostOf(doc[key]);
      // Well-known SDF Horizons never match here; the check above judges them.
      if (host === undefined || !looksNonProduction(host)) continue;
      diagnostics.push({
        rule: 'ci/non-production-endpoint',
        severity: 'error',
        category: 'network',
        message: `${key} uses ${host}, which looks like a development or staging host, in the production file`,
        path: key,
        ...at(key),
        suggestion: 'Replace it with the production endpoint before deploying.',
      });
    }
  }

  return diagnostics;
}
