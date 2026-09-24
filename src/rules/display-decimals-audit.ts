import {
  Account,
  Contract,
  Keypair,
  Networks,
  scValToNative,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import type { Diagnostic, LintOptions, Position, Rule } from '../types.js';

const MAX_CLASSIC_DECIMALS = 7;

export interface DisplayDecimalsAuditOptions {
  fetchImpl?: typeof fetch;
  includeClassic?: boolean;
  networkPassphrase?: string;
  rpcUrl?: string;
  rules?: LintOptions['rules'];
}

function currenciesOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  return currencies.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

function reportSeverity(
  rule: string,
  defaultSeverity: 'error' | 'warning',
  rules: LintOptions['rules'],
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : defaultSeverity;
}

function networkPassphraseOf(doc: Record<string, unknown>): string | undefined {
  return typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
}

export function sorobanRpcUrl(networkPassphrase: string | undefined): string | undefined {
  switch (networkPassphrase) {
    case Networks.PUBLIC:
      return 'https://soroban-rpc.mainnet.stellar.org';
    case Networks.TESTNET:
      return 'https://soroban-testnet.stellar.org';
    case Networks.FUTURENET:
      return 'https://rpc-futurenet.stellar.org';
    default:
      return undefined;
  }
}

function classicDiagnostics(
  doc: Record<string, unknown>,
  locate: (path: string) => Position | undefined,
  rules: LintOptions['rules'],
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  currenciesOf(doc).forEach((entry, index) => {
    if (entry.toml !== undefined || entry.contract !== undefined) return;
    if (
      typeof entry.display_decimals !== 'number' ||
      entry.display_decimals <= MAX_CLASSIC_DECIMALS
    ) {
      return;
    }

    const rule = 'currencies/display-decimals-exceeds-network-limit';
    const severity = reportSeverity(rule, 'error', rules);
    if (!severity) return;
    const path = `CURRENCIES[${index}].display_decimals`;
    diagnostics.push({
      rule,
      severity,
      category: 'currencies',
      message: `${path} is ${entry.display_decimals}; classic Stellar assets support at most 7 decimal places`,
      path,
      position: locate(path),
      suggestion: 'Set display_decimals to 7 or fewer for a classic asset.',
    });
  });
  return diagnostics;
}

async function contractDecimals(
  contract: string,
  networkPassphrase: string,
  rpcUrl: string,
  fetchImpl: typeof fetch,
): Promise<number | undefined> {
  try {
    const source = Keypair.random().publicKey();
    const transaction = new TransactionBuilder(new Account(source, '0'), {
      fee: '100',
      networkPassphrase,
    })
      .addOperation(new Contract(contract).call('decimals'))
      .setTimeout(30)
      .build();

    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: transaction.toXDR() },
      }),
    });
    if (!response.ok) return undefined;

    const body = (await response.json()) as { result?: { retval?: string } };
    const retval = body.result?.retval;
    if (typeof retval !== 'string') return undefined;

    const value = scValToNative(xdr.ScVal.fromXDR(retval, 'base64'));
    return typeof value === 'number' && Number.isInteger(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

export async function auditDisplayDecimals(
  doc: Record<string, unknown>,
  locate: (path: string) => Position | undefined,
  options: DisplayDecimalsAuditOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics =
    options.includeClassic === false ? [] : classicDiagnostics(doc, locate, options.rules);
  const networkPassphrase = options.networkPassphrase ?? networkPassphraseOf(doc);
  const rpcUrl = options.rpcUrl ?? sorobanRpcUrl(networkPassphrase);
  const fetchImpl = options.fetchImpl ?? fetch;
  if (!networkPassphrase || !rpcUrl) return diagnostics;

  const contracts = currenciesOf(doc).flatMap((entry, index) => {
    if (entry.toml !== undefined || typeof entry.contract !== 'string') return [];
    return [{ entry, path: `CURRENCIES[${index}]` }];
  });

  for (const { entry, path } of contracts) {
    if (typeof entry.display_decimals !== 'number') continue;
    const actual = await contractDecimals(
      entry.contract as string,
      networkPassphrase,
      rpcUrl,
      fetchImpl,
    );
    if (actual === undefined || actual === entry.display_decimals) continue;

    const rule = 'currencies/display-decimals-contract-mismatch';
    const severity = reportSeverity(rule, 'warning', options.rules);
    if (!severity) continue;
    diagnostics.push({
      rule,
      severity,
      category: 'currencies',
      message: `${path}.display_decimals is ${entry.display_decimals}, but the contract reports ${actual}`,
      path: `${path}.display_decimals`,
      position: locate(`${path}.display_decimals`),
      suggestion: `Set display_decimals to ${actual} to match the Soroban contract.`,
    });
  }

  return diagnostics;
}

export const displayDecimalsRules: Rule[] = [
  {
    id: 'currencies/display-decimals-exceeds-network-limit',
    category: 'currencies',
    severity: 'error',
    description:
      'Classic assets must not declare more than 7 display decimals when checking the network',
    run(ctx) {
      if (!ctx.options.checkNetwork) return;
      for (const diagnostic of classicDiagnostics(ctx.doc, ctx.locate, ctx.options.rules)) {
        ctx.report(diagnostic);
      }
    },
  },
  {
    id: 'currencies/display-decimals-contract-mismatch',
    category: 'currencies',
    severity: 'warning',
    description: 'A contract currency display_decimals value should match the Soroban contract',
    run() {},
  },
];
