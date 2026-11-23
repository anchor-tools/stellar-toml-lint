import { describe, expect, it } from 'vitest';
import {
  CRYPTO_VERIFIERS,
  SIGNATURE_WITHOUT_DOMAIN_RULE,
  SIGNATURE_WITHOUT_EXPIRATION_RULE,
  SIGNATURE_WITHOUT_NONCE_RULE,
  SignatureReplayAuditor,
  auditSignatureReplay,
  renderSignatureReplayReport,
  signatureReplayRuleIds,
} from '../src/soroban/signatureReplayAuditor.js';
import { OP, buildWasm, funcType, u32 } from './fixtures/wasm-build.js';

const VOID = funcType([], []);

/** Builds a contract importing `imports` and calling them all from `verify`. */
function contract(imports: string[], strings: string[] = []): Uint8Array {
  return buildWasm({
    types: [VOID],
    imports: imports.map((field) => ({ module: 'env', name: field, type: 0 })),
    functions: [
      {
        type: 0,
        code: imports.flatMap((_, index) => [OP.CALL, ...u32(index)]),
      },
    ],
    exports: [{ name: 'verify', kind: 0x00, index: imports.length }],
    functionNames: ['verify'],
    ...(strings.length > 0 ? { data: strings.map((text) => ({ offset: 1024, bytes: text })) } : {}),
  });
}

const SECURE_IMPORTS = [
  'ed25519_verify',
  'get_contract_data',
  'put_contract_data',
  'get_network_id',
  'get_current_contract_address',
  'get_ledger_sequence',
];

describe('soroban signature replay auditor', () => {
  it('accepts a routine that consumes a nonce and binds domain and expiration', () => {
    const report = auditSignatureReplay(contract(SECURE_IMPORTS));
    expect(report.valid).toBe(true);
    expect(report.cryptoImports).toEqual(['ed25519_verify']);
    expect(report.routines).toHaveLength(1);
    expect(report.routines[0]).toMatchObject({
      function: 'verify',
      verifiers: ['ed25519_verify'],
      consumesNonce: true,
      domainSeparated: true,
      checksExpiration: true,
    });
    expect(report.findings).toEqual([]);
  });

  it('flags ed25519 verification with no nonce, domain or expiration checks', () => {
    const report = auditSignatureReplay(contract(['ed25519_verify']));
    expect(report.findings.map((finding) => finding.code).sort()).toEqual(
      [
        SIGNATURE_WITHOUT_DOMAIN_RULE,
        SIGNATURE_WITHOUT_EXPIRATION_RULE,
        SIGNATURE_WITHOUT_NONCE_RULE,
      ].sort(),
    );
    expect(report.findings.filter((f) => f.severity === 'error')).toHaveLength(2);
    expect(report.findings.find((f) => f.code === SIGNATURE_WITHOUT_NONCE_RULE)?.function).toBe(
      'verify',
    );
  });

  it('flags secp256k1 verification without replay protection', () => {
    const report = auditSignatureReplay(contract(['secp256k1_verify', 'get_ledger_sequence']));
    expect(report.cryptoImports).toContain('secp256k1_verify');
    expect(report.findings.map((finding) => finding.code)).toContain(SIGNATURE_WITHOUT_NONCE_RULE);
    expect(report.findings.map((finding) => finding.code)).toContain(SIGNATURE_WITHOUT_DOMAIN_RULE);
    expect(report.findings.map((finding) => finding.code)).not.toContain(
      SIGNATURE_WITHOUT_EXPIRATION_RULE,
    );
  });

  it('treats a read-only state lookup as an unconsumed nonce', () => {
    const report = auditSignatureReplay(
      contract([
        'ed25519_verify',
        'get_contract_data',
        'get_network_id',
        'get_current_contract_address',
        'get_ledger_sequence',
      ]),
    );
    expect(report.routines[0]?.consumesNonce).toBe(false);
    expect(report.routines[0]?.notes).toContain(
      'reads contract state but never writes the nonce back',
    );
    expect(report.findings.map((finding) => finding.code)).toContain(SIGNATURE_WITHOUT_NONCE_RULE);
  });

  it('accepts literal domain-separation strings when the host imports are absent', () => {
    const report = auditSignatureReplay(
      contract(
        ['ed25519_verify', 'get_contract_data', 'put_contract_data', 'get_ledger_sequence'],
        ['Stellar network passphrase', 'contract address domain'],
      ),
    );
    expect(report.routines[0]?.domainSeparated).toBe(true);
    expect(report.findings).toEqual([]);
  });

  it('accepts an expiration constant embedded in the data section', () => {
    const report = auditSignatureReplay(
      contract(
        [
          'ed25519_verify',
          'get_contract_data',
          'put_contract_data',
          'get_network_id',
          'get_current_contract_address',
        ],
        ['signature expiration ledger'],
      ),
    );
    expect(report.routines[0]?.checksExpiration).toBe(true);
    expect(report.findings).toEqual([]);
  });

  it('reports no routines when the contract never verifies a signature', () => {
    const report = auditSignatureReplay(contract(['get_contract_data']));
    expect(report.cryptoImports).toEqual([]);
    expect(report.routines).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it('reports a malformed binary instead of throwing', () => {
    const report = auditSignatureReplay(Uint8Array.from([0x00, 0x61, 0x73]));
    expect(report.valid).toBe(false);
    expect(report.findings[0]?.code).toBe('soroban/wasm-invalid-binary');
  });

  it('renders a text report and exposes a class wrapper', () => {
    const report = new SignatureReplayAuditor({ file: 'token.wasm' }).audit(
      contract(['ed25519_verify']),
    );
    const text = renderSignatureReplayReport(report);
    expect(text).toContain('Signature replay audit: token.wasm');
    expect(text).toContain('ed25519_verify');
    expect(text).toContain('nonce NO | domain NO | expiration NO');
  });

  it('knows the crypto verifier set and registers its rules', () => {
    expect(CRYPTO_VERIFIERS.has('ed25519_verify')).toBe(true);
    expect(CRYPTO_VERIFIERS.has('secp256k1_verify')).toBe(true);
    expect(signatureReplayRuleIds).toContain(SIGNATURE_WITHOUT_NONCE_RULE);
    expect(new Set(signatureReplayRuleIds).size).toBe(signatureReplayRuleIds.length);
  });
});
