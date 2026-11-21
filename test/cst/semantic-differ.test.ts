import { describe, it, expect } from 'vitest';
import { SemanticTomlDiffer } from '../../src/cst/semanticDiffer.js';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const TOML_BASE = `
VERSION = "2.0.0"
SIGNING_KEY = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TRANSFER_SERVER = "https://api.example.com/sep24"
WEB_AUTH_ENDPOINT = "https://api.example.com/auth"

[DOCUMENTATION]
ORG_NAME = "Example Anchor Inc"
ORG_URL = "https://example.com"

[[CURRENCIES]]
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
status = "live"
display_decimals = 2

[[CURRENCIES]]
code = "EURC"
issuer = "GD6WNOYBQNVIJQHGJWDC5BNOA3HGDMYQR7F5H6GS5CXMWGQW45CXEURC"
status = "live"

[[VALIDATORS]]
PUBLIC_KEY = "GCFONE23SHHXTDALWSS4URNLHVII6IRQDTWNFHQVQWMQDA4KB7A4AGWC"
ALIAS = "validator-1"
`;

describe('SemanticTomlDiffer', () => {
  const differ = new SemanticTomlDiffer();

  it('detects no differences between identical files', () => {
    const result = differ.diffTexts(TOML_BASE, TOML_BASE);
    expect(result.hasDifferences).toBe(false);
    expect(result.hasBreakingChanges).toBe(false);
    expect(result.deltas.length).toBe(0);
    expect(result.breakingChanges.length).toBe(0);

    const textReport = differ.renderReport(result, 'text');
    expect(textReport).toContain('No semantic differences found.');
  });

  it('detects non-breaking additions and modifications', () => {
    const target = `
VERSION = "2.0.0"
SIGNING_KEY = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TRANSFER_SERVER = "https://api.example.com/sep24"
WEB_AUTH_ENDPOINT = "https://api.example.com/auth"

[DOCUMENTATION]
ORG_NAME = "Example Anchor Inc (Updated)"
ORG_URL = "https://example.com"
ORG_DESCRIPTION = "A premier Stellar anchor"

[[CURRENCIES]]
code = "USDC"
issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
status = "live"
display_decimals = 4

[[CURRENCIES]]
code = "EURC"
issuer = "GD6WNOYBQNVIJQHGJWDC5BNOA3HGDMYQR7F5H6GS5CXMWGQW45CXEURC"
status = "live"

[[CURRENCIES]]
code = "BTC"
issuer = "GBVOL67TMUQBGL4TZYNMY3ZQ5WGQY4R45CXMWGQW45CXBTCISSR9999"
status = "test"

[[VALIDATORS]]
PUBLIC_KEY = "GCFONE23SHHXTDALWSS4URNLHVII6IRQDTWNFHQVQWMQDA4KB7A4AGWC"
ALIAS = "validator-1"
`;
    const result = differ.diffTexts(TOML_BASE, target);
    expect(result.hasDifferences).toBe(true);
    expect(result.hasBreakingChanges).toBe(false);
    expect(result.summary.added).toBeGreaterThan(0);
    expect(result.summary.modified).toBeGreaterThan(0);

    // Added currency BTC
    const addedBtc = result.deltas.find((d) => d.path === 'CURRENCIES[code=BTC]');
    expect(addedBtc).toBeDefined();
    expect(addedBtc?.type).toBe('added');

    // Modified doc org name
    const modOrg = result.deltas.find((d) => d.path === 'DOCUMENTATION.ORG_NAME');
    expect(modOrg).toBeDefined();
    expect(modOrg?.type).toBe('modified');
  });

  it('detects breaking changes when asset issuer is modified', () => {
    const target = TOML_BASE.replace(
      'issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"',
      'issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"',
    );
    const result = differ.diffTexts(TOML_BASE, target);
    expect(result.hasBreakingChanges).toBe(true);
    const breaking = result.breakingChanges.find((bc) => bc.category === 'currency');
    expect(breaking).toBeDefined();
    expect(breaking?.message).toContain('Asset issuer for currency USDC changed');
  });

  it('detects breaking changes when a currency is removed', () => {
    // Remove EURC currency table
    const target = TOML_BASE.replace(
      /\[\[CURRENCIES\]\]\ncode = "EURC"[\s\S]*?status = "live"/,
      '',
    );
    const result = differ.diffTexts(TOML_BASE, target);
    expect(result.hasBreakingChanges).toBe(true);
    const breaking = result.breakingChanges.find((bc) => bc.message.includes('EURC'));
    expect(breaking).toBeDefined();
  });

  it('detects breaking changes when SIGNING_KEY is changed or removed', () => {
    const targetChanged = TOML_BASE.replace(
      'SIGNING_KEY = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"',
      'SIGNING_KEY = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"',
    );
    const resultChanged = differ.diffTexts(TOML_BASE, targetChanged);
    expect(resultChanged.hasBreakingChanges).toBe(true);
    expect(resultChanged.breakingChanges.some((bc) => bc.category === 'signing_key')).toBe(true);

    const targetRemoved = TOML_BASE.replace(
      'SIGNING_KEY = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"',
      '',
    );
    const resultRemoved = differ.diffTexts(TOML_BASE, targetRemoved);
    expect(resultRemoved.hasBreakingChanges).toBe(true);
  });

  it('detects breaking changes when SEP service endpoints are altered or removed', () => {
    const targetAltered = TOML_BASE.replace(
      'TRANSFER_SERVER = "https://api.example.com/sep24"',
      'TRANSFER_SERVER = "https://new-api.example.com/sep24"',
    );
    const resultAltered = differ.diffTexts(TOML_BASE, targetAltered);
    expect(resultAltered.hasBreakingChanges).toBe(true);
    expect(resultAltered.breakingChanges.some((bc) => bc.category === 'service_endpoint')).toBe(
      true,
    );

    const targetRemoved = TOML_BASE.replace(
      'WEB_AUTH_ENDPOINT = "https://api.example.com/auth"',
      '',
    );
    const resultRemoved = differ.diffTexts(TOML_BASE, targetRemoved);
    expect(resultRemoved.hasBreakingChanges).toBe(true);
  });

  it('detects breaking changes when a validator is removed from the quorum set', () => {
    const target = TOML_BASE.replace(/\[\[VALIDATORS\]\][\s\S]*?ALIAS = "validator-1"/, '');
    const result = differ.diffTexts(TOML_BASE, target);
    expect(result.hasBreakingChanges).toBe(true);
    expect(result.breakingChanges.some((bc) => bc.category === 'validator')).toBe(true);
  });

  it('renders reports in text, markdown, and JSON format', () => {
    const target = TOML_BASE.replace(
      'SIGNING_KEY = "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"',
      'SIGNING_KEY = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"',
    );
    const result = differ.diffTexts(TOML_BASE, target);

    const textFmt = differ.renderReport(result, 'text');
    expect(textFmt).toContain('CRITICAL BREAKING CHANGES');
    expect(textFmt).toContain('[modified]');

    const mdFmt = differ.renderReport(result, 'markdown');
    expect(mdFmt).toContain('## Semantic TOML Diff Report');
    expect(mdFmt).toContain('> [!CRITICAL] BREAKING CHANGES DETECTED:');

    const jsonFmt = differ.renderReport(result, 'json');
    const parsed = JSON.parse(jsonFmt);
    expect(parsed.hasBreakingChanges).toBe(true);
    expect(parsed.summary.breaking).toBe(1);
  });

  it('runs diff command via CLI', () => {
    const cliPath = path.resolve(__dirname, '../../dist/cli.js');
    const tmpSource = path.resolve(__dirname, '../../test/fixtures/valid.toml');
    const tmpTarget = path.resolve(__dirname, '../../test/fixtures/warnings-only.toml');

    // Run identical diff
    const procIdentical = spawnSync('node', [cliPath, 'diff', tmpSource, tmpSource], {
      encoding: 'utf-8',
    });
    expect(procIdentical.status).toBe(0);
    expect(procIdentical.stdout).toContain('No semantic differences found.');

    // Run different files with --format json (breaking changes present, exits 1)
    const procDiff = spawnSync(
      'node',
      [cliPath, 'diff', tmpSource, tmpTarget, '--format', 'json'],
      {
        encoding: 'utf-8',
      },
    );
    expect(procDiff.status).toBe(1); // Breaking changes exit 1
    const jsonOutput = JSON.parse(procDiff.stdout);
    expect(jsonOutput.hasDifferences).toBe(true);
    expect(jsonOutput.hasBreakingChanges).toBe(true);
  });
});
