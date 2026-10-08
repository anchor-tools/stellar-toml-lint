import { Keypair } from '@stellar/stellar-base';
import { strict as assert } from 'node:assert';
import { describe, it } from 'vitest';
import { checkFixedSupplyIssuerLocks } from '../src/rules/fixed-supply-audit.js';

describe('fixed-supply issuer lock audit', () => {
  it('passes when the master key and minting signers are disabled', async () => {
    const issuer = Keypair.random().publicKey();
    const account = {
      master_key_weight: 0,
      thresholds: { med_threshold: 2, high_threshold: 3 },
      signers: [],
    };
    let calledUrl = '';
    const fetchStub = async (url: string | URL | Request) => {
      calledUrl = url.toString();
      return { ok: true, json: async () => account } as Response;
    };

    const diagnostics = await checkFixedSupplyIssuerLocks(
      { CURRENCIES: [{ code: 'USD', issuer, fixed_number: 1_000_000 }] },
      fetchStub as typeof fetch,
    );

    assert.equal(calledUrl, `https://horizon.stellar.org/accounts/${issuer}`);
    assert.deepEqual(diagnostics, []);
  });

  it('warns when the master key retains signing weight for a fixed supply', async () => {
    const issuer = Keypair.random().publicKey();
    const account = {
      master_key_weight: 1,
      thresholds: { med_threshold: 1, high_threshold: 2 },
      signers: [{ key: issuer, weight: 1 }],
    };
    const fetchStub = async () => ({ ok: true, json: async () => account }) as Response;

    const diagnostics = await checkFixedSupplyIssuerLocks(
      { CURRENCIES: [{ code: 'USD', issuer, fixed_number: 1_000_000 }] },
      fetchStub as unknown as typeof fetch,
    );

    assert.equal(diagnostics.length, 1);
    assert.equal(diagnostics[0]?.rule, 'currencies/fixed-supply-account-not-locked');
    assert.equal(diagnostics[0]?.severity, 'warning');
    assert.match(diagnostics[0]?.suggestion ?? '', /is_unlimited = true/);
  });

  it('warns when active signers collectively meet the medium threshold', async () => {
    const issuer = Keypair.random().publicKey();
    const account = {
      master_key_weight: 0,
      thresholds: { med_threshold: 2, high_threshold: 3 },
      signers: [
        { key: Keypair.random().publicKey(), weight: 1 },
        { key: Keypair.random().publicKey(), weight: 1 },
      ],
    };
    const fetchStub = async () => ({ ok: true, json: async () => account }) as Response;

    const diagnostics = await checkFixedSupplyIssuerLocks(
      { CURRENCIES: [{ code: 'USD', issuer, max_number: 1_000_000 }] },
      fetchStub as unknown as typeof fetch,
    );

    assert.equal(diagnostics[0]?.rule, 'currencies/fixed-supply-account-not-locked');
    assert.equal(diagnostics[0]?.severity, 'warning');
  });
});
