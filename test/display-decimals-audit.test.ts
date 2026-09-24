import { nativeToScVal } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { checkDisplayDecimals } from '../src/rules/display-decimals-audit.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const NETWORK = 'Test SDF Network ; September 2015';
const ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

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

describe('display_decimals network audit', () => {
  it('accepts matching Soroban contract decimals', async () => {
    const parsed = lint(contractSource(6)).parsed ?? {};
    const diagnostics = await checkDisplayDecimals(parsed, rpcReturning(6));

    expect(diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-contract-mismatch' }),
    );
  });

  it('reports mismatched Soroban contract decimals', async () => {
    const parsed = lint(contractSource(6)).parsed ?? {};
    const diagnostics = await checkDisplayDecimals(parsed, rpcReturning(7));

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: 'currencies/display-decimals-contract-mismatch',
        severity: 'warning',
      }),
    );
  });

  it('checks classic assets above seven only with --check-network', () => {
    const source = [
      `NETWORK_PASSPHRASE="${NETWORK}"`,
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      `issuer="${ACCOUNT}"`,
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
    const source = [
      `NETWORK_PASSPHRASE="${NETWORK}"`,
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      `issuer="${ACCOUNT}"`,
      'display_decimals=6',
    ].join('\n');

    const diagnostics = await checkDisplayDecimals(lint(source).parsed ?? {}, fetchImpl);
    expect(calls).toBe(0);
    expect(diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-contract-mismatch' }),
    );
  });
});
