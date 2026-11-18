import { StrKey } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  ReverseFederationVerifier,
  collectAnchorAccounts,
  renderReverseFederationReport,
  reverseFederationRuleIds,
  validateFederationRecord,
  validateMemo,
  verifyFederationSync,
} from '../../src/protocols/reverseFederationVerifier.js';

const ACCOUNT = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const OTHER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 7));
const MUXED = StrKey.encodeMed25519PublicKey(Buffer.alloc(40, 3));

const doc = {
  FEDERATION_SERVER: 'https://anchor.example.com/federation',
  ACCOUNTS: [ACCOUNT],
  CURRENCIES: [{ code: 'USD', issuer: OTHER }],
};

const address = (account: string): string => `user*${account.slice(0, 4)}.example.com`;

/** Builds a mock federation server from a name -> record map. */
function serverFetch(
  byName: Record<string, { account_id: string; memo_type?: string; memo?: string }>,
) {
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    const type = url.searchParams.get('type');
    const q = url.searchParams.get('q') ?? '';
    if (type === 'id') {
      const entry = Object.entries(byName).find(([, record]) => record.account_id === q);
      if (entry === undefined) return new Response('{"detail":"not found"}', { status: 404 });
      return new Response(JSON.stringify({ stellar_address: entry[0], ...entry[1] }));
    }
    const record = byName[q];
    if (record === undefined) return new Response('{"detail":"not found"}', { status: 404 });
    return new Response(JSON.stringify({ stellar_address: q, ...record }));
  }) as unknown as typeof fetch;
}

/** Forward(ACCOUNT) names OTHER, whose reverse maps back to OTHER: a mismatch. */
const mismatchFetch = (async (input: string | URL | Request) => {
  const url = new URL(String(input));
  const type = url.searchParams.get('type');
  const q = url.searchParams.get('q') ?? '';
  const record =
    type === 'id' && q === ACCOUNT
      ? { stellar_address: address(OTHER), account_id: ACCOUNT }
      : { stellar_address: address(OTHER), account_id: OTHER };
  return new Response(JSON.stringify(record));
}) as unknown as typeof fetch;

describe('validateMemo', () => {
  it('accepts valid text, id, and hash memos', () => {
    expect(validateMemo('text', 'hello')).toEqual([]);
    expect(validateMemo('id', '18446744073709551615')).toEqual([]);
    expect(validateMemo('hash', 'a'.repeat(64))).toEqual([]);
    expect(validateMemo(undefined, undefined)).toEqual([]);
  });

  it('rejects invalid memo shapes', () => {
    expect(validateMemo('memo', 'x')[0]?.code).toBe('memo/invalid-type');
    expect(validateMemo(undefined, 'x')[0]?.code).toBe('memo/invalid-type');
    expect(validateMemo('id', '18446744073709551616')[0]?.code).toBe('memo/invalid-value');
    expect(validateMemo('hash', 'abc')[0]?.code).toBe('memo/invalid-value');
    expect(validateMemo('text', 'x'.repeat(29))[0]?.code).toBe('memo/invalid-value');
    expect(validateMemo('text', undefined)[0]?.code).toBe('memo/missing');
  });
});

describe('validateFederationRecord', () => {
  it('accepts public and muxed account IDs', () => {
    expect(
      validateFederationRecord({ stellar_address: 'a*b.com', account_id: ACCOUNT }).record,
    ).toBeDefined();
    expect(
      validateFederationRecord({ stellar_address: 'a*b.com', account_id: MUXED }).record,
    ).toBeDefined();
  });

  it('rejects malformed records', () => {
    expect(validateFederationRecord(null).problems.length).toBe(1);
    expect(validateFederationRecord({ stellar_address: 'nope', account_id: 'X' }).problems).toEqual(
      [
        'stellar_address is missing or not "user*domain"',
        'account_id is not a valid Stellar public or muxed account',
      ],
    );
  });
});

describe('collectAnchorAccounts', () => {
  it('merges ACCOUNTS and currency issuers', () => {
    expect(collectAnchorAccounts(doc).sort()).toEqual([ACCOUNT, OTHER].sort());
  });
});

describe('ReverseFederationVerifier', () => {
  const verifier = (byName: Parameters<typeof serverFetch>[0]) =>
    new ReverseFederationVerifier(serverFetch(byName));

  it('registers rule ids', () => {
    expect(reverseFederationRuleIds).toContain('federation/reverse-mismatch');
    expect(reverseFederationRuleIds).toContain('federation/invalid-memo');
  });

  it('passes a consistent mapping with a valid memo', async () => {
    const byName = {
      [address(ACCOUNT)]: { account_id: ACCOUNT, memo_type: 'id', memo: '42' },
      [address(OTHER)]: { account_id: OTHER },
    };
    const report = await verifier(byName).verify(doc);
    expect(report.ok).toBe(true);
    expect(report.checks).toHaveLength(2);
    expect(report.checks.every((check) => check.consistent)).toBe(true);
    expect(renderReverseFederationReport(report)).toContain('clean');
  });

  it('reports a mismatched reverse mapping', async () => {
    const report = await new ReverseFederationVerifier(mismatchFetch).verify(doc);
    expect(report.ok).toBe(false);
    expect(report.findings.map((finding) => finding.code)).toContain('federation/reverse-mismatch');
  });

  it('reports an invalid memo', async () => {
    const byName = {
      [address(ACCOUNT)]: { account_id: ACCOUNT, memo_type: 'id', memo: 'not-a-number' },
      [address(OTHER)]: { account_id: OTHER },
    };
    const report = await verifier(byName).verify(doc);
    expect(report.findings.map((finding) => finding.code)).toContain('federation/invalid-memo');
  });

  it('reports a missing memo value', async () => {
    const byName = {
      [address(ACCOUNT)]: { account_id: ACCOUNT, memo_type: 'text' },
      [address(OTHER)]: { account_id: OTHER },
    };
    const report = await verifier(byName).verify(doc);
    expect(report.findings.map((finding) => finding.code)).toContain('federation/memo-missing');
  });

  it('handles muxed accounts supplied by the caller', async () => {
    const byName = { [address(MUXED)]: { account_id: MUXED } };
    const report = await new ReverseFederationVerifier(serverFetch(byName), {
      accounts: [MUXED],
    }).verify({ FEDERATION_SERVER: doc.FEDERATION_SERVER });
    expect(report.ok).toBe(true);
    expect(report.checks[0]?.consistent).toBe(true);
  });

  it('fails without an https FEDERATION_SERVER', async () => {
    const report = await new ReverseFederationVerifier(serverFetch({})).verify({});
    expect(report.findings[0]?.code).toBe('federation/reverse-missing-server');
  });

  it('emits lint diagnostics through verifyFederationSync', async () => {
    const { diagnostics, report } = await verifyFederationSync(
      doc,
      mismatchFetch as unknown as typeof fetch,
    );
    expect(report.ok).toBe(false);
    expect(diagnostics[0]?.category).toBe('network');
  });
});
