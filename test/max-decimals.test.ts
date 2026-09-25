import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';

const ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';

function classicSource(displayDecimals: number): string {
  return [
    'VERSION="2.7.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code="USD"',
    `issuer="${ACCOUNT}"`,
    'is_unlimited=true',
    `display_decimals=${displayDecimals}`,
  ].join('\n');
}

function contractSource(displayDecimals: number): string {
  return [
    'VERSION="2.7.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code="TOKEN"',
    `contract="${CONTRACT}"`,
    'is_unlimited=true',
    `display_decimals=${displayDecimals}`,
  ].join('\n');
}

describe('max-decimals rule', () => {
  it('passes when display_decimals = 7', () => {
    const result = lint(classicSource(7));
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-exceeds-max' }),
    );
    expect(result.ok).toBe(true);
  });

  it('asserts currencies/display-decimals-exceeds-max when display_decimals = 8', () => {
    const result = lint(classicSource(8));
    const diagnostic = result.diagnostics.find(
      (d) => d.rule === 'currencies/display-decimals-exceeds-max',
    );
    expect(diagnostic).toBeDefined();
    expect(diagnostic?.severity).toBe('warning');
    expect(diagnostic?.category).toBe('currencies');
    expect(diagnostic?.path).toBe('CURRENCIES[0].display_decimals');
  });

  it('does not emit warning for Soroban contract asset with display_decimals > 7', () => {
    const result = lint(contractSource(8));
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-exceeds-max' }),
    );
  });

  it('does not emit warning for contract_id asset with display_decimals > 7', () => {
    const source = [
      'VERSION="2.7.0"',
      'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      `contract_id="${CONTRACT}"`,
      'is_unlimited=true',
      'display_decimals=9',
    ].join('\n');
    const result = lint(source);
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-exceeds-max' }),
    );
  });

  it('warns when native XLM asset configures display_decimals > 7', () => {
    const source = [
      'VERSION="2.7.0"',
      'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'code="native"',
      'display_decimals=8',
    ].join('\n');
    const result = lint(source);
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({
        rule: 'currencies/display-decimals-exceeds-max',
        severity: 'warning',
      }),
    );
  });

  it('passes when display_decimals is 0', () => {
    const result = lint(classicSource(0));
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-exceeds-max' }),
    );
  });

  it('ignores toml pointer currencies', () => {
    const source = [
      'VERSION="2.7.0"',
      'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'toml="https://example.com/.well-known/stellar.toml"',
    ].join('\n');
    const result = lint(source);
    expect(result.diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: 'currencies/display-decimals-exceeds-max' }),
    );
  });
});
