import {
  Account,
  Asset,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
} from '@stellar/stellar-base';
import type { Transaction } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const UNDISCLOSED_FREEZING_RULE = 'security/undisclosed-asset-freezing-capability';
export const UNDISCLOSED_ASSET_FREEZING_RULE = UNDISCLOSED_FREEZING_RULE;

const SEP8_URL = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0008.md';

const DISCLOSURE_PATTERN =
  /freez|frozen|revok|revocab|blacklist|blocklist|authoriz|authoris|compliance|regulat|sanction|aml|restrict/i;

interface RecordValue {
  [key: string]: unknown;
}

export interface TrustlineSimulatorOptions {
  rules?: RuleOverrides;
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
}

export interface HorizonIssuerAuthorization {
  authRequired: boolean;
  authRevocable: boolean;
}

function isRecord(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function horizonUrlFor(passphrase: unknown): string {
  return passphrase === 'Test SDF Network ; September 2015'
    ? 'https://horizon-testnet.stellar.org'
    : 'https://horizon.stellar.org';
}

function severityFor(rule: string, rules?: RuleOverrides): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : 'error';
}

function textOf(entry: RecordValue): string {
  return ['desc', 'description', 'conditions', 'name', 'redemption_instructions']
    .map((field) => entry[field])
    .filter((value): value is string => typeof value === 'string')
    .join(' ');
}

export function hasFreezeDisclosure(entry: RecordValue): boolean {
  if (entry.regulated !== true) return false;
  return DISCLOSURE_PATTERN.test(textOf(entry));
}

export async function fetchIssuerAuthorization(
  issuer: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<HorizonIssuerAuthorization | undefined> {
  try {
    const base = horizonUrl.replace(/\/+$/, '');
    const response = await fetchImpl(`${base}/accounts/${encodeURIComponent(issuer)}`);
    if (!response.ok) return undefined;
    const body = (await response.json()) as unknown;
    if (!isRecord(body) || !isRecord(body.flags)) return undefined;
    return {
      authRequired: body.flags.auth_required === true,
      authRevocable: body.flags.auth_revocable === true,
    };
  } catch {
    return undefined;
  }
}

/**
 * Builds the unsigned `SetTrustLineFlagsOp` the issuer would submit to clear
 * the AUTHORIZED flag. Building it exercises the same asset/trustor operands
 * the network would validate, without touching a live ledger.
 */
export function buildTrustLineFreezeTransaction(
  issuer: string,
  assetCode: string,
  trustor: string = Keypair.random().publicKey(),
  networkPassphrase: string = Networks.PUBLIC,
): Transaction {
  return new TransactionBuilder(new Account(issuer, '0'), {
    fee: '100',
    networkPassphrase,
  })
    .addOperation(
      Operation.setTrustLineFlags({
        trustor,
        asset: new Asset(assetCode, issuer),
        flags: { authorized: false },
      }),
    )
    .setTimeout(30)
    .build();
}

function classicAssets(doc: Record<string, unknown>): {
  entry: RecordValue;
  issuer: string;
  code: string;
  index: number;
}[] {
  if (!Array.isArray(doc.CURRENCIES)) return [];
  const assets: { entry: RecordValue; issuer: string; code: string; index: number }[] = [];
  doc.CURRENCIES.forEach((raw, index) => {
    if (!isRecord(raw) || raw.toml !== undefined) return;
    if (typeof raw.issuer !== 'string' || typeof raw.code !== 'string') return;
    if (raw.code.toLowerCase() === 'native' || raw.code.toLowerCase() === 'xlm') return;
    assets.push({ entry: raw, issuer: raw.issuer, code: raw.code, index });
  });
  return assets;
}

/**
 * Audits classic issuers for the on-chain ability to revoke a trustline's
 * AUTHORIZED flag and verifies that the file discloses it.
 *
 * An issuer whose Horizon account has `auth_revocable` set can freeze every
 * holder. When the matching `[[CURRENCIES]]` entry is not `regulated = true`
 * with a description explaining the freeze authority, that capability is
 * undisclosed. Horizon outages are not findings.
 */
export async function simulateTrustlineFreezing(
  doc: Record<string, unknown>,
  fetchImplOrOptions: typeof fetch | TrustlineSimulatorOptions = fetch,
  extraOptions: TrustlineSimulatorOptions = {},
): Promise<Diagnostic[]> {
  const options =
    typeof fetchImplOrOptions === 'function'
      ? extraOptions
      : { ...fetchImplOrOptions, ...extraOptions };
  const defaultFetch = typeof fetchImplOrOptions === 'function' ? fetchImplOrOptions : fetch;
  const severity = severityFor(UNDISCLOSED_FREEZING_RULE, options.rules);
  if (severity === undefined) return [];

  const horizonUrl =
    options.horizonUrl ??
    (typeof doc.HORIZON_URL === 'string' ? doc.HORIZON_URL : horizonUrlFor(doc.NETWORK_PASSPHRASE));
  const transport = options.fetchImpl ?? defaultFetch;
  const diagnostics: Diagnostic[] = [];

  for (const { entry, issuer, code, index } of classicAssets(doc)) {
    const flags = await fetchIssuerAuthorization(issuer, horizonUrl, transport);
    if (flags === undefined || !flags.authRevocable) continue;

    try {
      buildTrustLineFreezeTransaction(issuer, code);
    } catch {
      continue;
    }

    if (hasFreezeDisclosure(entry)) continue;

    const base = `CURRENCIES[${index}]`;
    diagnostics.push({
      rule: UNDISCLOSED_FREEZING_RULE,
      severity,
      category: 'currencies',
      message: `Issuer ${issuer} can revoke AUTHORIZED_FLAG on ${code} holders, but ${base} does not disclose freezing under regulated = true`,
      path: `${base}.issuer`,
      helpUri: SEP8_URL,
      suggestion:
        'Set regulated = true and explain the freeze/revocation authority in desc (for example, AML or sanctions compliance), or clear AUTH_REVOCABLE on the issuer account.',
    });
  }

  return diagnostics;
}

export const simulateTrustLineFreeze = simulateTrustlineFreezing;
export const simulateTrustlineRevocation = simulateTrustlineFreezing;
export const checkTrustlineFreezing = simulateTrustlineFreezing;
export const auditTrustlineFreezing = simulateTrustlineFreezing;
export const auditTrustlineAuthorization = simulateTrustlineFreezing;
export const simulateTrustlineAuthorization = simulateTrustlineFreezing;
export const auditTrustlineSimulator = simulateTrustlineFreezing;
export const checkTrustlineSimulator = simulateTrustlineFreezing;

export const trustlineSimulatorRules: Rule[] = [
  {
    id: UNDISCLOSED_FREEZING_RULE,
    category: 'currencies',
    severity: 'error',
    description:
      'An issuer that can freeze trustlines must disclose that authority under regulated = true',
    run() {},
  },
];

export const trustlineSimulatorRuleIds: readonly string[] = trustlineSimulatorRules.map(
  (rule) => rule.id,
);
