import { describe, expect, it } from 'vitest';
import { Keypair } from '@stellar/stellar-base';
import {
  APPROVAL_SERVER_UNRESPONSIVE_RULE,
  INVALID_RESPONSE_STATUS_RULE,
  INVALID_REVISED_TX_XDR_RULE,
  buildSyntheticSep8Transaction,
  isValidTransactionXdr,
  sep8Rules,
  verifySep8,
} from '../../src/protocols/sep8.js';
import { lint } from '../../src/lint.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const APPROVAL_URL = 'https://compliance.example.com/approve';

function regulatedDoc(extra = ''): Record<string, unknown> {
  const source = [
    'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code="REGUSD"',
    `issuer="${ISSUER}"`,
    'regulated=true',
    `approval_server="${APPROVAL_URL}"`,
    extra,
  ].join('\n');
  return lint(source).parsed ?? {};
}

function mockFetch(
  handler: (reqUrl: string, options?: RequestInit) => Promise<Response>,
): typeof fetch {
  return handler as unknown as typeof fetch;
}

describe('SEP-8 Compliance Approval Server Simulation Engine', () => {
  it('passes cleanly when approval server returns status "success"', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(JSON.stringify({ status: 'success' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('passes cleanly when approval server returns "success" with valid signed transaction XDR', async () => {
    const { txXdr } = buildSyntheticSep8Transaction('REGUSD', ISSUER);
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(JSON.stringify({ status: 'success', tx: txXdr, message: 'Approved' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('passes cleanly when approval server returns "revised" with valid transaction XDR', async () => {
    const { txXdr } = buildSyntheticSep8Transaction('REGUSD', ISSUER);
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'revised',
          tx: txXdr,
          message: 'Revised with compliance fee',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep8/invalid-revised-tx-xdr when "revised" status returns invalid XDR', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'revised',
          tx: 'not-valid-xdr-base64!',
          message: 'Revised',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INVALID_REVISED_TX_XDR_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts sep8/invalid-response-status when approval server returns unknown status', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'unknown_status_code',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INVALID_RESPONSE_STATUS_RULE,
        severity: 'error',
      }),
    );
  });

  it('passes cleanly when approval server returns "action_required" with valid action_url', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'action_required',
          action_url: 'https://compliance.example.com/kyc-flow',
          action_method: 'GET',
          message: 'Customer verification required',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep8/invalid-response-status when "action_required" is missing valid action_url', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'action_required',
          action_url: 'invalid-url',
          message: 'Action needed',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INVALID_RESPONSE_STATUS_RULE,
        severity: 'error',
      }),
    );
  });

  it('passes cleanly when approval server returns "pending" or "rejected"', async () => {
    const doc = regulatedDoc();
    const pendingFetch = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'pending',
          timeout: 5000,
          message: 'Approval pending compliance review',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    expect(await verifySep8(doc, pendingFetch)).toEqual([]);

    const rejectedFetch = mockFetch(async () => {
      return new Response(
        JSON.stringify({
          status: 'rejected',
          error: 'Transaction prohibited by regulatory freeze',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    expect(await verifySep8(doc, rejectedFetch)).toEqual([]);
  });

  it('asserts sep8/approval-server-unresponsive on HTTP error (500)', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response('Internal Server Error', { status: 500 });
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: APPROVAL_SERVER_UNRESPONSIVE_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts sep8/approval-server-unresponsive when network fetch throws', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      throw new Error('Connection refused');
    });

    const diagnostics = await verifySep8(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: APPROVAL_SERVER_UNRESPONSIVE_RULE,
        severity: 'error',
      }),
    );
  });

  it('honours rule severity overrides', async () => {
    const doc = regulatedDoc();
    const fetchImpl = mockFetch(async () => {
      return new Response(JSON.stringify({ status: 'invalid' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const offDiag = await verifySep8(doc, fetchImpl, {
      rules: { [INVALID_RESPONSE_STATUS_RULE]: 'off' },
    });
    expect(offDiag).toEqual([]);

    const warnDiag = await verifySep8(doc, fetchImpl, {
      rules: { [INVALID_RESPONSE_STATUS_RULE]: 'warning' },
    });
    expect(warnDiag).toContainEqual(
      expect.objectContaining({
        rule: INVALID_RESPONSE_STATUS_RULE,
        severity: 'warning',
      }),
    );
  });

  it('correctly builds synthetic test transaction and validates XDR', () => {
    const srcKp = Keypair.random();
    const dstKp = Keypair.random();
    const { txXdr, sourcePublicKey, destPublicKey } = buildSyntheticSep8Transaction(
      'REGUSD',
      ISSUER,
      'Test SDF Network ; September 2015',
      srcKp.publicKey(),
      dstKp.publicKey(),
    );

    expect(sourcePublicKey).toBe(srcKp.publicKey());
    expect(destPublicKey).toBe(dstKp.publicKey());
    expect(isValidTransactionXdr(txXdr)).toBe(true);
    expect(isValidTransactionXdr('invalid_xdr')).toBe(false);
  });

  it('registers all required SEP-8 rule definitions', () => {
    expect(sep8Rules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: APPROVAL_SERVER_UNRESPONSIVE_RULE, severity: 'error' },
      { id: INVALID_RESPONSE_STATUS_RULE, severity: 'error' },
      { id: INVALID_REVISED_TX_XDR_RULE, severity: 'error' },
    ]);
  });
});
