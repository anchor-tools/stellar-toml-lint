import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { Diagnostic, LintResult } from '../src/types.js';
import { isLocalMockUrl } from '../src/rules/insecure-http.js';

const RULE = 'general/insecure-http-url';

function find(result: LintResult, rule = RULE): Diagnostic[] {
  return result.diagnostics.filter((d) => d.rule === rule);
}

describe('general/insecure-http-url', () => {
  it('passes when all endpoints and URLs use https://', () => {
    const toml = `
VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
HORIZON_URL="https://horizon.example.com"
TRANSFER_SERVER="https://api.example.com/sep6"
TRANSFER_SERVER_SEP0024="https://api.example.com/sep24"
KYC_SERVER="https://api.example.com/sep12"
WEB_AUTH_ENDPOINT="https://api.example.com/auth"

[DOCUMENTATION]
ORG_NAME="Example Org"
ORG_URL="https://example.com"
ORG_LOGO="https://example.com/logo.png"
ORG_PHYSICAL_ADDRESS_ATTESTATION="https://example.com/attestation.pdf"
ORG_TERMS_OF_SERVICE="https://example.com/terms"
ORG_PRIVACY_POLICY="https://example.com/privacy"

[[CURRENCIES]]
code="USD"
issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
status="live"
display_decimals=2
name="US Dollar"
image="https://example.com/usd.png"
attestation_of_reserve="https://example.com/reserve.pdf"
approval_server="https://example.com/sep8"
toml="https://example.com/.well-known/stellar.toml"

[[VALIDATORS]]
ALIAS="validator-1"
HOST="validator.example.com:11625"
PUBLIC_KEY="GBXHQL5SHDWJJ2WQXJZOVQBVVIFXLFQQFIKVWMU6XA7YZVMVMB5APS5X"
HISTORY="https://history.example.com/prd/core-live/core_live_001/"
`;
    const result = lint(toml);
    expect(find(result)).toEqual([]);
  });

  it('flags insecure http:// URLs on global endpoint fields', () => {
    const toml = `
VERSION="2.7.0"
TRANSFER_SERVER="http://api.example.com/sep6"
WEB_AUTH_ENDPOINT="http://auth.example.com"
HORIZON_URL="http://horizon.example.com"
`;
    const result = lint(toml);
    const diags = find(result);
    expect(diags.length).toBeGreaterThanOrEqual(3);

    const transferDiag = diags.find((d) => d.path === 'TRANSFER_SERVER');
    expect(transferDiag).toBeDefined();
    expect(transferDiag?.severity).toBe('error');
    expect(transferDiag?.rule).toBe(RULE);
    expect(transferDiag?.message).toContain(
      'TRANSFER_SERVER must use https:// instead of insecure http://',
    );
    expect(transferDiag?.suggestion).toContain('https://api.example.com/sep6');
    expect(transferDiag?.fix?.value).toBe('https://api.example.com/sep6');

    const authDiag = diags.find((d) => d.path === 'WEB_AUTH_ENDPOINT');
    expect(authDiag).toBeDefined();
    expect(authDiag?.severity).toBe('error');
    expect(authDiag?.suggestion).toContain('https://auth.example.com');
  });

  it('flags insecure http:// URLs in [DOCUMENTATION] table', () => {
    const toml = `
[DOCUMENTATION]
ORG_URL="http://example.com"
ORG_LOGO="http://example.com/logo.png"
ORG_TERMS_OF_SERVICE="http://example.com/terms"
`;
    const result = lint(toml);
    const diags = find(result);
    expect(diags).toHaveLength(3);

    const urlDiag = diags.find((d) => d.path === 'DOCUMENTATION.ORG_URL');
    expect(urlDiag).toBeDefined();
    expect(urlDiag?.severity).toBe('error');
    expect(urlDiag?.suggestion).toBe('Replace http://example.com with https://example.com.');
    expect(urlDiag?.fix?.value).toBe('https://example.com');
  });

  it('flags insecure http:// URLs in [[CURRENCIES]] array of tables', () => {
    const toml = `
[[CURRENCIES]]
code="TEST"
image="http://example.com/token.png"
toml="http://example.com/stellar.toml"
approval_server="http://example.com/sep8"
attestation_of_reserve="http://example.com/reserve.pdf"
`;
    const result = lint(toml);
    const diags = find(result);
    expect(diags).toHaveLength(4);

    const paths = diags.map((d) => d.path);
    expect(paths).toContain('CURRENCIES[0].image');
    expect(paths).toContain('CURRENCIES[0].toml');
    expect(paths).toContain('CURRENCIES[0].approval_server');
    expect(paths).toContain('CURRENCIES[0].attestation_of_reserve');
  });

  it('flags insecure http:// URLs in [[VALIDATORS]] table', () => {
    const toml = `
[[VALIDATORS]]
ALIAS="test-validator"
HOST="test.example.com:11625"
PUBLIC_KEY="GBXHQL5SHDWJJ2WQXJZOVQBVVIFXLFQQFIKVWMU6XA7YZVMVMB5APS5X"
HISTORY="http://history.example.com/archives/"
`;
    const result = lint(toml);
    const diags = find(result);
    expect(diags).toHaveLength(1);
    expect(diags[0]?.path).toBe('VALIDATORS[0].HISTORY');
    expect(diags[0]?.severity).toBe('error');
    expect(diags[0]?.fix?.value).toBe('https://history.example.com/archives/');
  });

  it('allows exceptions for local mock testing on localhost and loopback IPs', () => {
    const toml = `
WEB_AUTH_ENDPOINT="http://localhost:8080/auth"
TRANSFER_SERVER="http://127.0.0.1:8080/sep24"
KYC_SERVER="http://0.0.0.0:8080/sep12"
HORIZON_URL="http://[::1]:8000"
ANCHOR_QUOTE_SERVER="http://test.localhost:3000"

[DOCUMENTATION]
ORG_URL="http://localhost:3000"
`;
    const result = lint(toml);
    expect(find(result)).toEqual([]);
  });

  it('flags spoofed or deceptive domains that attempt to mimic localhost', () => {
    const toml = `
WEB_AUTH_ENDPOINT="http://localhost.attacker.com/auth"
TRANSFER_SERVER="http://127.0.0.1.attacker.com/sep24"
`;
    const result = lint(toml);
    const diags = find(result);
    expect(diags).toHaveLength(2);
  });

  it('respects rule overrides when disabled', () => {
    const toml = 'TRANSFER_SERVER="http://api.example.com/sep6"';
    const result = lint(toml, { rules: { [RULE]: 'off' } });
    expect(find(result)).toEqual([]);
  });

  it('isLocalMockUrl identifies local endpoints correctly', () => {
    expect(isLocalMockUrl('http://localhost')).toBe(true);
    expect(isLocalMockUrl('http://localhost:8080')).toBe(true);
    expect(isLocalMockUrl('http://127.0.0.1:8000/auth')).toBe(true);
    expect(isLocalMockUrl('http://127.0.1.1:8000')).toBe(true);
    expect(isLocalMockUrl('http://0.0.0.0:8000')).toBe(true);
    expect(isLocalMockUrl('http://[::1]:8000')).toBe(true);
    expect(isLocalMockUrl('http://dev.localhost')).toBe(true);
    expect(isLocalMockUrl('http://anchor.local')).toBe(true);
    expect(isLocalMockUrl('http://test.test')).toBe(true);

    expect(isLocalMockUrl('http://example.com')).toBe(false);
    expect(isLocalMockUrl('http://localhost.evil.com')).toBe(false);
    expect(isLocalMockUrl('http://127.0.0.1.nip.io')).toBe(false);
    expect(isLocalMockUrl('http://api.stellar.org')).toBe(false);
  });
});
