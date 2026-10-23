import { describe, expect, it } from 'vitest';
import { lint } from '../../src/lint.js';
import type { Diagnostic, LintResult } from '../../src/types.js';

const DEAD = 'general/dead-configuration-key';

// Checksum-valid, taken from the shared fixtures: the issuer is irrelevant to
// this rule but a malformed one would drown the assertions in noise.
const ISSUER = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7';

function find(result: LintResult, rule: string): Diagnostic[] {
  return result.diagnostics.filter((diagnostic) => diagnostic.rule === rule);
}

describe('general/dead-configuration-key', () => {
  it('flags approval fields when the entry never declares regulated', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "USD"',
        `issuer = "${ISSUER}"`,
        'approval_server = "https://sep8.example.com"',
        'approval_criteria = "Licensed intermediary only"',
        '',
      ].join('\n'),
    );

    const diagnostics = find(result, DEAD);
    expect(diagnostics).toHaveLength(2);
    expect(diagnostics[0]).toMatchObject({
      rule: DEAD,
      severity: 'warning',
      category: 'general',
      path: 'CURRENCIES[0].approval_server',
    });
    expect(diagnostics[1]?.path).toBe('CURRENCIES[0].approval_criteria');
    expect(diagnostics[0]?.message).toContain(
      'CURRENCIES[0].approval_server is dead configuration',
    );
    expect(diagnostics[0]?.message).toContain('SEP-8 clients never read it');
    expect(diagnostics[0]?.position?.line).toBeGreaterThan(0);
    expect(diagnostics[0]?.helpUri).toContain('#');
    expect(diagnostics[0]?.suggestion).toContain('Set regulated = true on CURRENCIES[0]');
    expect(diagnostics[0]?.suggestion).toContain('remove approval_server');
  });

  it('flags approval fields when regulated is explicitly false', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "USD"',
        `issuer = "${ISSUER}"`,
        'regulated = false',
        'approval_server = "https://sep8.example.com"',
        '',
      ].join('\n'),
    );

    expect(find(result, DEAD)).toHaveLength(1);
  });

  it('flags a lone approval_criteria with no approval_server', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "USD"',
        `issuer = "${ISSUER}"`,
        'approval_criteria = "x"',
        '',
      ].join('\n'),
    );

    const diagnostics = find(result, DEAD);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.path).toBe('CURRENCIES[0].approval_criteria');
  });

  it('stays quiet when the entry is regulated', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "USD"',
        `issuer = "${ISSUER}"`,
        'regulated = true',
        'approval_server = "https://sep8.example.com"',
        'approval_criteria = "Licensed intermediary only"',
        '',
      ].join('\n'),
    );

    expect(find(result, DEAD)).toEqual([]);
  });

  it('flags every collateral field on an explicitly non-anchored entry', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "EUR"',
        `issuer = "${ISSUER}"`,
        'is_asset_anchored = false',
        'collateral_addresses = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"]',
        'collateral_address_messages = ["reserve attestation"]',
        'collateral_address_signatures = ["c2lnbmF0dXJl"]',
        '',
      ].join('\n'),
    );

    const diagnostics = find(result, DEAD);
    expect(diagnostics).toHaveLength(3);
    expect(diagnostics.map((diagnostic) => diagnostic.path)).toEqual([
      'CURRENCIES[0].collateral_addresses',
      'CURRENCIES[0].collateral_address_messages',
      'CURRENCIES[0].collateral_address_signatures',
    ]);
    expect(diagnostics[0]).toMatchObject({
      severity: 'warning',
      category: 'general',
    });
    expect(diagnostics[0]?.message).toContain('the collateral claim backs nothing');
    expect(diagnostics[0]?.suggestion).toContain('Set is_asset_anchored = true on CURRENCIES[0]');
    expect(diagnostics[0]?.suggestion).toContain('remove collateral_addresses');
  });

  it('stays quiet when anchoring is merely undeclared', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "EUR"',
        `issuer = "${ISSUER}"`,
        'collateral_addresses = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"]',
        '',
      ].join('\n'),
    );

    expect(find(result, DEAD)).toEqual([]);
  });

  it('stays quiet when the entry is asset-anchored', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "EUR"',
        `issuer = "${ISSUER}"`,
        'is_asset_anchored = true',
        'collateral_addresses = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"]',
        'collateral_address_messages = ["reserve attestation"]',
        'collateral_address_signatures = ["c2lnbmF0dXJl"]',
        '',
      ].join('\n'),
    );

    expect(find(result, DEAD)).toEqual([]);
  });

  it('names each entry with its own path across several currencies', () => {
    const result = lint(
      [
        '[[CURRENCIES]]',
        'code = "USD"',
        `issuer = "${ISSUER}"`,
        'approval_server = "https://sep8.example.com"',
        '',
        '[[CURRENCIES]]',
        'code = "EUR"',
        `issuer = "${ISSUER}"`,
        'is_asset_anchored = false',
        'collateral_addresses = ["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"]',
        '',
      ].join('\n'),
    );

    const diagnostics = find(result, DEAD);
    expect(diagnostics.map((diagnostic) => diagnostic.path)).toEqual([
      'CURRENCIES[0].approval_server',
      'CURRENCIES[1].collateral_addresses',
    ]);
    expect(diagnostics[0]?.position?.line).toBeGreaterThan(0);
    expect(diagnostics[1]?.position?.line).toBeGreaterThan(0);
    expect(diagnostics[1]?.position?.line).not.toBe(diagnostics[0]?.position?.line);
  });

  it('says nothing about a file with no currencies', () => {
    const result = lint(
      ['VERSION = "2.7.0"', '[DOCUMENTATION]', 'ORG_NAME = "Example"', ''].join('\n'),
    );

    expect(find(result, DEAD)).toEqual([]);
  });
});
