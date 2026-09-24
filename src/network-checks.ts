import type { Diagnostic } from './types.js';

const PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

export async function checkNetworkAccounts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : PUBLIC_PASSPHRASE;

  let horizonUrl: string;
  if (passphrase === TESTNET_PASSPHRASE) {
    horizonUrl = 'https://horizon-testnet.stellar.org';
  } else {
    horizonUrl = 'https://horizon.stellar.org';
  }

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
