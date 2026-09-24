import { strict as assert } from 'node:assert';
import { describe, it } from 'vitest';
import { checkNetworkAccounts } from '../src/network-checks.js';

describe('network-checks', () => {
  it('is silent when account exists', async () => {
    const doc = { SIGNING_KEY: 'G123' };
    const fetchStub = async (/* url */) => {
      return { status: 200 } as Response;
    };

    const result = await checkNetworkAccounts(doc, fetchStub as unknown as typeof fetch);
    assert.equal(result.length, 0);
  });

  it('emits warning when account returns 404', async () => {
    const doc = { SIGNING_KEY: 'G123', ACCOUNTS: ['G456'] };
    const fetchStub = async (/* url */) => {
      return { status: 404 } as Response;
    };

    const result = await checkNetworkAccounts(doc, fetchStub as unknown as typeof fetch);
    assert.equal(result.length, 2);
    assert.equal(result[0]?.rule, 'network/account-exists');
    assert.equal(result[0]?.severity, 'warning');
    assert.equal(result[0]?.path, 'SIGNING_KEY');

    assert.equal(result[1]?.rule, 'network/account-exists');
    assert.equal(result[1]?.severity, 'warning');
    assert.equal(result[1]?.path, 'ACCOUNTS[0]');
  });

  it('degrades to warning and does not throw when fetch throws', async () => {
    const doc = { SIGNING_KEY: 'G123' };
    const fetchStub = async (/* url */) => {
      throw new Error('Network offline');
    };

    const result = await checkNetworkAccounts(doc, fetchStub as unknown as typeof fetch);
    assert.equal(result.length, 1);
    assert.equal(result[0]?.rule, 'network/account-exists');
    assert.equal(result[0]?.severity, 'warning');
    assert.equal(result[0]?.message, 'Could not verify account G123 due to a network error');
  });

  it('respects NETWORK_PASSPHRASE for URL selection', async () => {
    const doc = {
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
      SIGNING_KEY: 'G123',
    };
    let calledUrl = '';
    const fetchStub = async (url: string | URL | globalThis.Request) => {
      calledUrl = url.toString();
      return { status: 200 } as Response;
    };

    await checkNetworkAccounts(doc, fetchStub as typeof fetch);
    assert.ok(calledUrl.startsWith('https://horizon-testnet.stellar.org'));
  });
});
