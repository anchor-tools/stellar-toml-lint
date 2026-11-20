/**
 * Asset clawback audit trail generator.
 *
 * Run as `stellar-toml-lint audit-clawbacks --asset <code:issuer>`.
 *
 * SEP-8 regulated assets rely on clawbacks being exercised only under legal
 * orders. This reads the issuer's operation history from Horizon, keeps the
 * `clawback` and `clawback_claimable_balance` operations, checks that each
 * transaction carries an audit reference in its memo, and emits JSON and
 * Markdown reports. Amounts are held as 7-decimal strings / BigInt stroops, so
 * no precision is lost.
 */

import { isString } from '../predicates.js';

export const DEFAULT_HORIZON = 'https://horizon.stellar.org';
const MAX_PAGES = 50;

export interface ClawbackAsset {
  code: string;
  issuer: string;
}

export interface ClawbackRecord {
  operationId: string;
  type: 'clawback' | 'clawback_claimable_balance';
  createdAt: string;
  transactionHash: string;
  /** Account the funds were clawed back from; absent for claimable balances. */
  from?: string;
  claimableBalanceId?: string;
  /** Exact amount; `null` for claimable balances, whose op carries no amount. */
  amount: string | null;
  memoType: string;
  memo?: string;
  hasAuditReference: boolean;
}

export interface ClawbackAuditReport {
  asset: ClawbackAsset;
  generatedFrom: string;
  totalClawbacks: number;
  totalAmount: string;
  totalAmountStroops: string;
  unreferenced: number;
  records: ClawbackRecord[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Parses `CODE:ISSUER`. */
export function parseAsset(value: string): ClawbackAsset {
  const [code, issuer, ...rest] = value.split(':');
  if (!code || !issuer || rest.length > 0 || !/^G[A-Z2-7]{55}$/.test(issuer)) {
    throw new Error(`Invalid asset "${value}". Expected CODE:ISSUER.`);
  }
  return { code, issuer };
}

/** Clawback-enabled currencies declared in a stellar.toml. */
export function findClawbackAssets(doc: Record<string, unknown>): ClawbackAsset[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  const out: ClawbackAsset[] = [];
  for (const c of currencies) {
    if (!isRecord(c) || !isString(c.code) || !isString(c.issuer)) continue;
    const flags = isRecord(c.flags) ? c.flags : {};
    if (c.clawback_enabled === true || flags.clawback_enabled === true) {
      out.push({ code: c.code, issuer: c.issuer });
    }
  }
  return out;
}

/** Converts a 7-decimal amount string to stroops without floating point. */
export function toStroops(amount: string): bigint {
  const [whole = '0', frac = ''] = amount.split('.');
  return BigInt(whole) * 10_000_000n + BigInt(frac.padEnd(7, '0').slice(0, 7) || '0');
}

export function fromStroops(stroops: bigint): string {
  const whole = stroops / 10_000_000n;
  const frac = (stroops % 10_000_000n).toString().padStart(7, '0');
  return `${whole}.${frac}`;
}

/**
 * An audit reference is a URL, a 64-hex hash (as text or a hash memo), or a
 * LEGAL:/ORDER:/CASE:/AUDIT: case reference.
 */
export function hasAuditReference(memoType: string, memo: string | undefined): boolean {
  if (memoType === 'hash' || memoType === 'return') return memo !== undefined && memo !== '';
  if (memoType !== 'text' || memo === undefined) return false;
  return (
    /^https?:\/\//i.test(memo) ||
    /\b[0-9a-f]{64}\b/i.test(memo) ||
    /^(LEGAL|ORDER|CASE|AUDIT)[-:]/i.test(memo)
  );
}

async function getJson(url: string, fetchImpl: typeof fetch): Promise<Record<string, unknown>> {
  const response = await fetchImpl(url);
  if (!response.ok) throw new Error(`Horizon returned HTTP ${response.status} for ${url}`);
  const body = (await response.json()) as unknown;
  if (!isRecord(body)) throw new Error(`Horizon returned an unexpected document for ${url}`);
  return body;
}

export class ClawbackAuditTrailGenerator {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly horizonUrl: string = DEFAULT_HORIZON,
  ) {}

  async generate(asset: ClawbackAsset): Promise<ClawbackAuditReport> {
    const base = this.horizonUrl.replace(/\/+$/, '');
    let url: string | undefined =
      `${base}/accounts/${asset.issuer}/operations?order=asc&limit=200&include_failed=false`;
    const records: ClawbackRecord[] = [];
    const memos = new Map<string, { type: string; memo?: string }>();

    for (let page = 0; url !== undefined && page < MAX_PAGES; page++) {
      const body = await getJson(url, this.fetchImpl);
      const embedded = isRecord(body._embedded) ? body._embedded.records : undefined;
      const ops = Array.isArray(embedded) ? embedded : [];
      for (const op of ops) {
        if (!isRecord(op)) continue;
        if (op.type !== 'clawback' && op.type !== 'clawback_claimable_balance') continue;
        // `clawback` operations name the asset; claimable-balance clawbacks do not,
        // so they are attributed to the issuer's history as a whole.
        if (op.type === 'clawback' && op.asset_code !== undefined && op.asset_code !== asset.code) {
          continue;
        }
        const hash = String(op.transaction_hash ?? '');
        let memo = memos.get(hash);
        if (memo === undefined) {
          const tx = await getJson(`${base}/transactions/${hash}`, this.fetchImpl);
          memo = {
            type: isString(tx.memo_type) ? tx.memo_type : 'none',
            ...(isString(tx.memo) ? { memo: tx.memo } : {}),
          };
          memos.set(hash, memo);
        }
        records.push({
          operationId: String(op.id),
          type: op.type,
          createdAt: String(op.created_at ?? ''),
          transactionHash: hash,
          ...(isString(op.from) ? { from: op.from } : {}),
          ...(isString(op.balance_id) ? { claimableBalanceId: op.balance_id } : {}),
          amount: isString(op.amount) ? fromStroops(toStroops(op.amount)) : null,
          memoType: memo.type,
          ...(memo.memo === undefined ? {} : { memo: memo.memo }),
          hasAuditReference: hasAuditReference(memo.type, memo.memo),
        });
      }
      const next =
        isRecord(body._links) && isRecord(body._links.next) ? body._links.next.href : undefined;
      url = ops.length > 0 && isString(next) ? next : undefined;
    }

    const total = records.reduce(
      (sum, r) => sum + (r.amount === null ? 0n : toStroops(r.amount)),
      0n,
    );
    return {
      asset,
      generatedFrom: base,
      totalClawbacks: records.length,
      totalAmount: fromStroops(total),
      totalAmountStroops: total.toString(),
      unreferenced: records.filter((r) => !r.hasAuditReference).length,
      records,
    };
  }
}

export function renderClawbackJson(report: ClawbackAuditReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function renderClawbackMarkdown(report: ClawbackAuditReport): string {
  const lines = [
    `# Clawback audit trail: ${report.asset.code}:${report.asset.issuer}`,
    '',
    `- Clawback operations: ${report.totalClawbacks}`,
    `- Total reclaimed (known amounts): ${report.totalAmount}`,
    `- Operations without an audit reference: ${report.unreferenced}`,
    '',
  ];
  if (report.records.length === 0) {
    lines.push('No clawback operations were found for this issuer.', '');
    return lines.join('\n');
  }
  lines.push(
    '| Date | Type | Target | Amount | Transaction | Audit reference |',
    '| --- | --- | --- | --- | --- | --- |',
  );
  for (const r of report.records) {
    const target = r.from ?? r.claimableBalanceId ?? '';
    lines.push(
      `| ${r.createdAt} | ${r.type} | ${target} | ${r.amount ?? 'n/a'} | ${r.transactionHash} | ${r.hasAuditReference ? 'yes' : 'MISSING'} |`,
    );
  }
  lines.push('');
  return lines.join('\n');
}
