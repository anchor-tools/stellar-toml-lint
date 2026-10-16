import { describe, expect, it, vi } from 'vitest';
import {
  analyzeImmutability,
  checkImmutabilityClaims,
  FALSE_IMMUTABILITY_CLAIM_RULE,
  immutabilityClaimsOf,
  IMMUTABILITY_UNVERIFIABLE_RULE,
} from '../../src/security/immutability-auditor.js';

const ISSUER = 'GDG3MQ5KRQHKY2AEVD46HMMJS6YQ2SIBYUTNEYLUJ4NQIKRMXFQORS3F';
const HIDDEN_SIGNER = 'GDDOZFWVFZVVRG644A2XKBR5L53OLFIQKACZDSJIOI2HZVQ5H645NJKI';

const claimDoc = {
  NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
  CURRENCIES: [
    {
      code: 'USDX',
      issuer: ISSUER,
      conditions: 'Fixed supply: the token is immutable and cannot be minted further.',
    },
  ],
};

function horizonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('immutability auditor (#390)', () => {
  it('passes a truly locked account: master weight 0, no active signers, unreachable thresholds', async () => {
    const fetchImpl = vi.fn(async () =>
      horizonResponse({
        master_key_weight: 0,
        signers: [{ key: ISSUER, weight: 0, type: 'ed25519_public_key' }],
        thresholds: { low_threshold: 0, med_threshold: 1, high_threshold: 1 },
      }),
    ) as unknown as typeof fetch;

    const diagnostics = await checkImmutabilityClaims(claimDoc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts security/false-immutability-claim (error) when a hidden active signer remains', async () => {
    const fetchImpl = vi.fn(async () =>
      horizonResponse({
        master_key_weight: 0,
        signers: [
          { key: ISSUER, weight: 0, type: 'ed25519_public_key' },
          { key: HIDDEN_SIGNER, weight: 1, type: 'ed25519_public_key' },
        ],
        thresholds: { low_threshold: 0, med_threshold: 1, high_threshold: 1 },
      }),
    ) as unknown as typeof fetch;

    const diagnostics = await checkImmutabilityClaims(claimDoc, fetchImpl);

    const findings = diagnostics.filter((d) => d.rule === FALSE_IMMUTABILITY_CLAIM_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('error');
    expect(findings[0]?.path).toBe('CURRENCIES[0].issuer');
    expect(findings[0]?.message).toContain(HIDDEN_SIGNER);
  });

  it('asserts a false claim when the master weight is non-zero', async () => {
    const fetchImpl = vi.fn(async () =>
      horizonResponse({
        master_key_weight: 1,
        signers: [],
        thresholds: { low_threshold: 0, med_threshold: 1, high_threshold: 1 },
      }),
    ) as unknown as typeof fetch;

    const diagnostics = await checkImmutabilityClaims(claimDoc, fetchImpl);

    const finding = diagnostics.find((d) => d.rule === FALSE_IMMUTABILITY_CLAIM_RULE);
    expect(finding?.message).toContain('master key still carries weight 1');
  });

  it('degrades to security/immutability-unverifiable (warning) when Horizon is unreachable', async () => {
    const fetchImpl = vi.fn(async () => horizonResponse({}, 503)) as unknown as typeof fetch;

    const diagnostics = await checkImmutabilityClaims(claimDoc, fetchImpl);

    const findings = diagnostics.filter((d) => d.rule === IMMUTABILITY_UNVERIFIABLE_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('warning');
  });

  it('does not query Horizon for assets with no immutability claim', async () => {
    const fetchImpl = vi.fn(async () => horizonResponse({})) as unknown as typeof fetch;
    const doc = {
      CURRENCIES: [{ code: 'USDX', issuer: ISSUER, desc: 'A regulated stablecoin' }],
    };

    const diagnostics = await checkImmutabilityClaims(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('respects severity overrides and can silence the false-claim error', async () => {
    const fetchImpl = vi.fn(async () =>
      horizonResponse({
        master_key_weight: 1,
        signers: [],
        thresholds: { low_threshold: 0, med_threshold: 1, high_threshold: 1 },
      }),
    ) as unknown as typeof fetch;

    const diagnostics = await checkImmutabilityClaims(claimDoc, fetchImpl, {
      rules: { [FALSE_IMMUTABILITY_CLAIM_RULE]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });

  it('detects claims in conditions, desc, and name only', () => {
    expect(
      immutabilityClaimsOf({ conditions: 'immutable', desc: 'fixed supply', name: 'plain' }),
    ).toEqual([
      { field: 'conditions', text: 'immutable' },
      { field: 'desc', text: 'fixed supply' },
    ]);
    expect(immutabilityClaimsOf({ desc: 'A bridge asset' })).toEqual([]);
  });

  it('treats zero thresholds as still operable, since operations then need no signatures', () => {
    const verdict = analyzeImmutability({
      accountId: ISSUER,
      masterWeight: 0,
      signers: [{ key: ISSUER, weight: 0 }],
      lowThreshold: 0,
      medThreshold: 0,
      highThreshold: 0,
    });

    expect(verdict.locked).toBe(false);
    expect(verdict.reasons.join(' ')).toContain('require no signatures');
  });
});
