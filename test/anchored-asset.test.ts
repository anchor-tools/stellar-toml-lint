import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';

const ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

function source(fields: string): string {
  return [
    'VERSION="2.7.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code="AAA"',
    `issuer="${ACCOUNT}"`,
    'is_unlimited=true',
    fields,
  ].join('\n');
}

function rules(fields: string): string[] {
  return lint(source(fields)).diagnostics.map((diagnostic) => diagnostic.rule);
}

describe('anchored asset rules', () => {
  it('accepts a valid anchored currency', () => {
    const fields = 'is_asset_anchored=true\nanchor_asset_type="fiat"\nanchor_asset="USD"';
    const result = lint(source(fields));

    expect(rules(fields)).not.toContain('currencies/missing-anchor-asset-type');
    expect(result.diagnostics.map((diagnostic) => diagnostic.rule)).not.toContain(
      'currencies/missing-anchor-asset-code',
    );
  });

  it('requires anchor_asset_type for anchored currencies', () => {
    expect(rules('is_asset_anchored=true')).toContain('currencies/missing-anchor-asset-type');
  });

  it('rejects an invalid anchor_asset_type', () => {
    expect(rules('is_asset_anchored=true\nanchor_asset_type="dollars"')).toContain(
      'currencies/missing-anchor-asset-type',
    );
  });

  it('warns when anchor_asset is missing', () => {
    const result = lint(source('is_asset_anchored=true\nanchor_asset_type="crypto"'));
    const diagnostic = result.diagnostics.find(
      (entry) => entry.rule === 'currencies/missing-anchor-asset-code',
    );

    expect(diagnostic?.severity).toBe('warning');
  });

  it('ignores non-anchored currencies', () => {
    expect(rules('is_asset_anchored=false')).not.toContain('currencies/missing-anchor-asset-type');
    expect(rules('is_asset_anchored=false')).not.toContain('currencies/missing-anchor-asset-code');
  });
});
