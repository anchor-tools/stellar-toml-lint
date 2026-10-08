import type { Diagnostic } from './types.js';

const PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

/** The Horizon instance serving the network a passphrase names; mainnet by default. */
export function horizonUrlFor(passphrase: string | undefined): string {
  return passphrase === TESTNET_PASSPHRASE
    ? 'https://horizon-testnet.stellar.org'
    : 'https://horizon.stellar.org';
}

/**
 * The authorization flags Horizon reports for an account.
 *
 * SEP-8 regulated assets rely on two of them: `auth_required`, which lets the
 * issuer approve who may hold the asset, and `auth_revocable`, which lets the
 * issuer freeze a holder.
 */
export interface IssuerFlags {
  authRequired: boolean;
  authRevocable: boolean;
}

/**
 * Fetches the flags of one issuer account from Horizon.
 *
 * Returns `undefined` — never throws — when the flags cannot be verified: a
 * 404 (account does not exist), a non-200 response, or an unparseable body
 * give the caller nothing to assert, so it degrades those to a warning.
 */
export async function checkIssuerFlags(
  issuerId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IssuerFlags | undefined> {
  try {
    const response = await fetchImpl(`${horizonUrl}/accounts/${issuerId}`);
    if (!response.ok) return undefined;
    const body = (await response.json()) as { flags?: Record<string, unknown> };
    const flags = body.flags;
    if (typeof flags !== 'object' || flags === null) return undefined;
    return {
      authRequired: flags.auth_required === true,
      authRevocable: flags.auth_revocable === true,
    };
  } catch {
    return undefined;
  }
}

export interface IssuerLockStatus {
  masterKeyWeight: number;
  medThreshold: number;
  highThreshold: number;
  activeSignerWeight: number;
  locked: boolean;
}

/** Fetches the issuer's signing weights and reports whether it can still mint. */
export async function checkIssuerLockStatus(
  issuerId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IssuerLockStatus | undefined> {
  try {
    const response = await fetchImpl(`${horizonUrl}/accounts/${encodeURIComponent(issuerId)}`);
    if (!response.ok) return undefined;

    const body = (await response.json()) as Record<string, unknown>;
    const thresholdData = body.thresholds;
    const signers = body.signers;
    if (
      !Number.isInteger(body.master_key_weight) ||
      (body.master_key_weight as number) < 0 ||
      typeof thresholdData !== 'object' ||
      thresholdData === null ||
      Array.isArray(thresholdData) ||
      !Array.isArray(signers)
    ) {
      return undefined;
    }

    const thresholds = thresholdData as Record<string, unknown>;
    if (
      !Number.isInteger(thresholds.med_threshold) ||
      (thresholds.med_threshold as number) < 0 ||
      !Number.isInteger(thresholds.high_threshold) ||
      (thresholds.high_threshold as number) < 0
    ) {
      return undefined;
    }

    let activeSignerWeight = 0;
    for (const signer of signers) {
      if (typeof signer !== 'object' || signer === null || Array.isArray(signer)) return undefined;
      const signerData = signer as Record<string, unknown>;
      if (
        typeof signerData.key !== 'string' ||
        !Number.isInteger(signerData.weight) ||
        (signerData.weight as number) < 0
      ) {
        return undefined;
      }
      if (signerData.key !== issuerId) activeSignerWeight += signerData.weight as number;
    }

    const masterKeyWeight = body.master_key_weight as number;
    const medThreshold = thresholds.med_threshold as number;
    const highThreshold = thresholds.high_threshold as number;
    return {
      masterKeyWeight,
      medThreshold,
      highThreshold,
      activeSignerWeight,
      locked:
        masterKeyWeight === 0 &&
        activeSignerWeight < medThreshold &&
        activeSignerWeight < highThreshold,
    };
  } catch {
    return undefined;
  }
}

export async function checkNetworkAccounts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : PUBLIC_PASSPHRASE;
  const horizonUrl = horizonUrlFor(passphrase);

  const accountsToCheck: { id: string; path: string }[] = [];

  if (typeof doc.SIGNING_KEY === 'string') {
    accountsToCheck.push({ id: doc.SIGNING_KEY, path: 'SIGNING_KEY' });
  }

  if (Array.isArray(doc.ACCOUNTS)) {
    doc.ACCOUNTS.forEach((acc, index) => {
      if (typeof acc === 'string') {
        accountsToCheck.push({ id: acc, path: `ACCOUNTS[${index}]` });
      }
    });
  }

  for (const acc of accountsToCheck) {
    try {
      const response = await fetchImpl(`${horizonUrl}/accounts/${acc.id}`);
      if (response.status === 404) {
        diagnostics.push({
          rule: 'network/account-exists',
          severity: 'warning',
          category: 'network',
          message: `Account ${acc.id} does not exist on the network`,
          path: acc.path,
          suggestion: 'Ensure the account is created and funded on the correct network.',
        });
      }
    } catch {
      diagnostics.push({
        rule: 'network/account-exists',
        severity: 'warning',
        category: 'network',
        message: `Could not verify account ${acc.id} due to a network error`,
        path: acc.path,
      });
    }
  }

  return diagnostics;
}
