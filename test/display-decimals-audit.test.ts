import { nativeToScVal } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import { auditDisplayDecimals } from '../src/rules/display-decimals-audit.js';
import { lint } from '../src/lint.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const NETWORK = 'Test SDF Network ; September 2015';

function contractSource(displayDecimals: number): string {
  return [
    `NETWORK_PASSPHRASE="${NETWORK}"`,
    '',
    '[[CURRENCIES]]',
    'code="TOKEN"',
    `contract="${CONTRACT}"`,
    `display_decimals=${displayDecimals}`,
  ].join('\n');
}

function rpcReturning(decimals: number): typeof fetch {
  const retval = nativeToScVal(decimals, { type: 'u32' }).toXDR('base64');
  return (async () =>
    new Response(JSON.stringify({ result: { retval } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
}

function audit(source: string, fetchImpl?: typeof fetch) {
  const result = lint(source);
  return auditDisplayDecimals(result.parsed ?? {}, () => undefined, {
    fetchImpl,
    networkPassphrase: NETWORK,
    rpcUrl: 'https://rpc.example.test',
  });
}

describe('display_decimals network audit', () => {
  it('accepts matching Soroban contract decimals', async () => {
    const diagnostics = await audit(contractSource(6), rpcReturning(6));

    expect(diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-contract-mismatch' }),
    );
  });

  it('reports mismatched Soroban contract decimals', async () => {
    const diagnostics = await audit(contractSource(6), rpcReturning(7));

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: 'currencies/display-decimals-contract-mismatch',
        severity: 'warning',
      }),
    );
  });

  it('reports classic display_decimals above seven only with network checks enabled', () => {
    const source = [
      'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      'issuer="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"',
      'display_decimals=8',
    ].join('\n');

    expect(lint(source).diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-exceeds-network-limit' }),
    );
    expect(lint(source, { checkNetwork: true }).diagnostics).toContainEqual(
      expect.objectContaining({
        rule: 'currencies/display-decimals-exceeds-network-limit',
        severity: 'error',
      }),
    );
  });

  it('does not query or report contract mismatches for classic assets', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return new Response();
    }) as unknown as typeof fetch;
    const diagnostics = await audit(
      [
        'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"',
        '',
        '[[CURRENCIES]]',
        'code="TOKEN"',
        'issuer="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"',
        'display_decimals=6',
      ].join('\n'),
      fetchImpl,
    );

    expect(calls).toBe(0);
    expect(diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-contract-mismatch' }),
    );
  });
});
