/**
 * SEP-8 Dynamic Regulated Asset Compliance Approval Server Simulation Engine.
 *
 * Runs under opt-in --check-network --verify-sep8.
 *
 * Simulates the transaction compliance approval workflow for regulated assets
 * declared in stellar.toml:
 * 1. Generates synthetic payment transaction envelopes for regulated assets.
 * 2. Posts transaction envelopes to the declared `approval_server`.
 * 3. Validates response schemas and lifecycle states: success, revised, pending,
 *    rejected, action_required.
 * 4. Validates returned transaction XDR and interactive action URLs.
 */

import {
  Account,
  Asset,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { currenciesOf, isTomlPointer } from '../rules/currencies.js';

export const APPROVAL_SERVER_UNRESPONSIVE_RULE = 'sep8/approval-server-unresponsive';
export const INVALID_RESPONSE_STATUS_RULE = 'sep8/invalid-response-status';
export const INVALID_REVISED_TX_XDR_RULE = 'sep8/invalid-revised-tx-xdr';

const SEP8_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0008.md';

export const VALID_SEP8_STATUSES = new Set([
  'success',
  'revised',
  'pending',
  'rejected',
  'action_required',
]);

export interface Sep8Options {
  rules?: RuleOverrides;
  sourceAccount?: string;
  destinationAccount?: string;
  timeoutMs?: number;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Builds a synthetic payment transaction envelope for a regulated asset.
 */
export function buildSyntheticSep8Transaction(
  assetCode: string,
  assetIssuer?: string,
  networkPassphrase?: string,
  sourcePublicKey?: string,
  destPublicKey?: string,
): { txXdr: string; sourcePublicKey: string; destPublicKey: string } {
  const sourceKp = sourcePublicKey ? null : Keypair.random();
  const src = sourcePublicKey ?? sourceKp!.publicKey();
  const dst = destPublicKey ?? Keypair.random().publicKey();

  const account = new Account(src, '100');
  const asset =
    assetCode.toLowerCase() === 'native' || (!assetIssuer && assetCode.toUpperCase() === 'XLM')
      ? Asset.native()
      : new Asset(assetCode, assetIssuer ?? src);

  const passphrase = networkPassphrase ?? (Networks.PUBLIC as string);

  const tx = new TransactionBuilder(account, {
    fee: '100',
    networkPassphrase: passphrase,
  })
    .addOperation(
      Operation.payment({
        destination: dst,
        asset,
        amount: '10.0000000',
      }),
    )
    .setTimeout(300)
    .build();

  return {
    txXdr: tx.toXDR(),
    sourcePublicKey: src,
    destPublicKey: dst,
  };
}

/**
 * Validates whether a given string is a valid base64-encoded Stellar TransactionEnvelope XDR.
 */
export function isValidTransactionXdr(txXdrString: string): boolean {
  if (!isString(txXdrString) || txXdrString.trim() === '') return false;
  try {
    xdr.TransactionEnvelope.fromXDR(txXdrString.trim(), 'base64');
    return true;
  } catch {
    return false;
  }
}

/**
 * Posts synthetic transaction to the approval server and audits the response.
 */
async function auditApprovalServer(
  approvalServerUrl: string,
  currencyCode: string,
  currencyIssuer: string | undefined,
  networkPassphrase: string | undefined,
  path: string,
  fetchImpl: typeof fetch,
  options: Sep8Options,
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const timeoutMs = options.timeoutMs ?? 10_000;

  const { txXdr } = buildSyntheticSep8Transaction(
    currencyCode,
    currencyIssuer,
    networkPassphrase,
    options.sourceAccount,
    options.destinationAccount,
  );

  let response: Response;
  try {
    const postBody = JSON.stringify({ tx: txXdr });
    response = await fetchImpl(approvalServerUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: postBody,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const sev = severityFor(APPROVAL_SERVER_UNRESPONSIVE_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: APPROVAL_SERVER_UNRESPONSIVE_RULE,
        severity: sev,
        category: 'network',
        message: `SEP-8 approval server at "${approvalServerUrl}" is unresponsive: ${(error as Error).message}`,
        path,
        helpUri: SEP8_SPEC_URL,
        suggestion:
          'Verify that the SEP-8 approval_server is reachable and accepting POST requests with payment transaction envelopes.',
      });
    }
    return diagnostics;
  }

  if (!response.ok) {
    const sev = severityFor(APPROVAL_SERVER_UNRESPONSIVE_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: APPROVAL_SERVER_UNRESPONSIVE_RULE,
        severity: sev,
        category: 'network',
        message: `SEP-8 approval server at "${approvalServerUrl}" returned HTTP ${response.status}`,
        path,
        helpUri: SEP8_SPEC_URL,
        suggestion:
          'Ensure the approval server responds with HTTP 200 and a valid SEP-8 JSON payload.',
      });
    }
    return diagnostics;
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    const sev = severityFor(INVALID_RESPONSE_STATUS_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_RESPONSE_STATUS_RULE,
        severity: sev,
        category: 'network',
        message: `SEP-8 approval server at "${approvalServerUrl}" returned non-JSON response`,
        path,
        helpUri: SEP8_SPEC_URL,
        suggestion: 'SEP-8 approval servers must return valid JSON payloads.',
      });
    }
    return diagnostics;
  }

  if (!isRecord(body) || typeof body.status !== 'string') {
    const sev = severityFor(INVALID_RESPONSE_STATUS_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_RESPONSE_STATUS_RULE,
        severity: sev,
        category: 'network',
        message: `SEP-8 approval server response is missing a valid "status" field`,
        path,
        helpUri: SEP8_SPEC_URL,
        suggestion: `SEP-8 response status must be one of: ${Array.from(VALID_SEP8_STATUSES).join(', ')}.`,
      });
    }
    return diagnostics;
  }

  const status = body.status;
  if (!VALID_SEP8_STATUSES.has(status)) {
    const sev = severityFor(INVALID_RESPONSE_STATUS_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_RESPONSE_STATUS_RULE,
        severity: sev,
        category: 'network',
        message: `Invalid SEP-8 approval status "${status}" returned by "${approvalServerUrl}"`,
        path,
        helpUri: SEP8_SPEC_URL,
        suggestion: `Status must be one of: ${Array.from(VALID_SEP8_STATUSES).join(', ')}.`,
      });
    }
    return diagnostics;
  }

  // Validate status-specific requirements
  if (status === 'revised') {
    if (typeof body.tx !== 'string' || !isValidTransactionXdr(body.tx)) {
      const sev = severityFor(INVALID_REVISED_TX_XDR_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_REVISED_TX_XDR_RULE,
          severity: sev,
          category: 'network',
          message: `SEP-8 revised status response returned invalid or missing transaction XDR in "tx" field`,
          path,
          helpUri: SEP8_SPEC_URL,
          suggestion:
            'When status is "revised", the approval server must provide a valid base64-encoded TransactionEnvelope XDR in "tx".',
        });
      }
    }
  } else if (status === 'success') {
    if (body.tx !== undefined) {
      if (typeof body.tx !== 'string' || !isValidTransactionXdr(body.tx)) {
        const sev = severityFor(INVALID_REVISED_TX_XDR_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_REVISED_TX_XDR_RULE,
            severity: sev,
            category: 'network',
            message: `SEP-8 success status response contains malformed transaction XDR in "tx" field`,
            path,
            helpUri: SEP8_SPEC_URL,
            suggestion:
              'If "tx" is returned with "success" status, it must be a valid base64-encoded TransactionEnvelope XDR.',
          });
        }
      }
    }
  } else if (status === 'action_required') {
    if (!isString(body.action_url) || !isUrl(body.action_url)) {
      const sev = severityFor(INVALID_RESPONSE_STATUS_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_RESPONSE_STATUS_RULE,
          severity: sev,
          category: 'network',
          message: `SEP-8 action_required status response is missing a valid "action_url"`,
          path,
          helpUri: SEP8_SPEC_URL,
          suggestion:
            'When status is "action_required", the approval server must return a valid URL in "action_url".',
        });
      }
    }
  }

  return diagnostics;
}

/**
 * Simulates SEP-8 compliance approval server interactions for all regulated assets.
 */
export async function verifySep8(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep8Options = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const networkPassphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;

  const testedServers = new Set<string>();

  const currencies = currenciesOf(doc);
  for (const [index, entry] of currencies.entries()) {
    if (isTomlPointer(entry)) continue;

    const approvalServer = isString(entry.approval_server)
      ? entry.approval_server
      : entry.regulated === true && isString(doc.APPROVAL_SERVER)
        ? doc.APPROVAL_SERVER
        : undefined;

    if (!approvalServer || !isUrl(approvalServer)) continue;

    const code = isString(entry.code) ? entry.code : 'TEST';
    const issuer = isString(entry.issuer) ? entry.issuer : undefined;
    const path = isString(entry.approval_server)
      ? `CURRENCIES[${index}].approval_server`
      : 'APPROVAL_SERVER';

    testedServers.add(approvalServer);
    diagnostics.push(
      ...(await auditApprovalServer(
        approvalServer,
        code,
        issuer,
        networkPassphrase,
        path,
        fetchImpl,
        options,
      )),
    );
  }

  // If top-level APPROVAL_SERVER was defined and not yet tested
  if (
    isString(doc.APPROVAL_SERVER) &&
    isUrl(doc.APPROVAL_SERVER) &&
    !testedServers.has(doc.APPROVAL_SERVER)
  ) {
    diagnostics.push(
      ...(await auditApprovalServer(
        doc.APPROVAL_SERVER,
        'TEST',
        undefined,
        networkPassphrase,
        'APPROVAL_SERVER',
        fetchImpl,
        options,
      )),
    );
  }

  return diagnostics;
}

/** Registered rules for SEP-8 simulation engine */
export const sep8Rules: Rule[] = [
  {
    id: APPROVAL_SERVER_UNRESPONSIVE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-8 compliance approval server must be reachable and return HTTP 200',
    run() {},
  },
  {
    id: INVALID_RESPONSE_STATUS_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-8 approval server response must have a valid status and schema',
    run() {},
  },
  {
    id: INVALID_REVISED_TX_XDR_RULE,
    category: 'network',
    severity: 'error',
    description:
      'SEP-8 approval server revised transaction must be a valid TransactionEnvelope XDR',
    run() {},
  },
];

export const sep8RuleIds: readonly string[] = sep8Rules.map((rule) => rule.id);
