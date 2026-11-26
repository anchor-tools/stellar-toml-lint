import { describe, expect, it } from 'vitest';
import {
  BridgeEmergencyPauseValidator,
  auditEmergencyPause,
  emergencyPauseRuleIds,
} from '../../src/bridges/emergencyPauseValidator.js';

const CONTRACT = 'CADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP5KR';

const GOOD_BRIDGE = {
  NAME: 'main',
  CHAIN: 'soroban',
  CONTRACT,
  METHODS: ['deposit', 'pause', 'unpause'],
  PAUSE_AUTHORITY_TYPE: 'multisig',
  PAUSE_AUTHORITY: 'council',
  PAUSE_THRESHOLD: 3,
  PAUSE_SIGNERS: 5,
  UNPAUSE_AUTHORITY: 'governance',
  UNPAUSE_TIMELOCK_SECONDS: 86400,
};
const GOOD = {
  SECURITY_CONTACT: 'security@example.com',
  SECURITY_CONTACT_HOURS: '24/7',
  BRIDGES: [GOOD_BRIDGE],
};

const rules = (doc: Record<string, unknown>): string[] =>
  auditEmergencyPause(doc).diagnostics.map((d) => d.rule);
const withBridge = (patch: Record<string, unknown>): Record<string, unknown> => ({
  ...GOOD,
  BRIDGES: [{ ...GOOD_BRIDGE, ...patch }],
});

describe('BridgeEmergencyPauseValidator', () => {
  it('registers rule ids', () => {
    expect(emergencyPauseRuleIds).toContain('bridgepause/missing-pause-method');
  });

  it('is silent when no bridges are declared', () => {
    expect(auditEmergencyPause({}).diagnostics).toEqual([]);
  });

  it('passes a pausable, council-controlled, timelocked bridge', () => {
    const r = auditEmergencyPause(GOOD);
    expect(r.diagnostics).toEqual([]);
    expect(r.bridges.main).toEqual({ pausable: true, restricted: true });
  });

  it('flags a non-pausable bridge', () => {
    const r = auditEmergencyPause(withBridge({ METHODS: ['deposit', 'withdraw'] }));
    expect(r.diagnostics.map((d) => d.rule)).toContain('bridgepause/missing-pause-method');
    expect(r.bridges.main?.pausable).toBe(false);
  });

  it('accepts emergency_stop and warns when unpause is missing', () => {
    expect(rules(withBridge({ METHODS: ['emergency_stop'] }))).toEqual([
      'bridgepause/missing-unpause-method',
    ]);
  });

  it('accepts an automated circuit breaker authority', () => {
    expect(rules(withBridge({ PAUSE_AUTHORITY_TYPE: 'circuit_breaker' }))).toEqual([]);
  });

  it('rejects single keys, 1-of-n multisigs and impossible thresholds', () => {
    for (const patch of [
      { PAUSE_AUTHORITY_TYPE: 'single_key' },
      { PAUSE_THRESHOLD: 1 },
      { PAUSE_THRESHOLD: 9 },
      { PAUSE_SIGNERS: 'five' },
      { PAUSE_AUTHORITY_TYPE: undefined },
    ]) {
      expect(rules(withBridge(patch))).toEqual(['bridgepause/unrestricted-pause-authority']);
    }
  });

  it('warns when one authority both pauses and unpauses', () => {
    expect(rules(withBridge({ UNPAUSE_AUTHORITY: 'council' }))).toEqual([
      'bridgepause/shared-pause-unpause-authority',
    ]);
  });

  it('recommends a timelock for unpausing', () => {
    expect(rules(withBridge({ UNPAUSE_TIMELOCK_SECONDS: 0 }))).toEqual([
      'bridgepause/missing-unpause-timelock',
    ]);
    expect(rules(withBridge({ UNPAUSE_TIMELOCK_SECONDS: undefined }))).toEqual([
      'bridgepause/missing-unpause-timelock',
    ]);
  });

  it('validates the contract address per chain', () => {
    expect(rules(withBridge({ CONTRACT: 'nope' }))).toEqual(['bridgepause/invalid-bridge']);
    expect(rules(withBridge({ CHAIN: 'cosmos' }))).toEqual(['bridgepause/invalid-bridge']);
    expect(rules(withBridge({ CHAIN: 'evm', CONTRACT: `0x${'a'.repeat(40)}` }))).toEqual([]);
    expect(rules(withBridge({ CHAIN: 'evm', CONTRACT: '0x123' }))).toEqual([
      'bridgepause/invalid-bridge',
    ]);
    expect(
      rules(withBridge({ CHAIN: 'solana', CONTRACT: '11111111111111111111111111111111' })),
    ).toEqual([]);
    expect(rules(withBridge({ CHAIN: 'solana', CONTRACT: 12 }))).toEqual([
      'bridgepause/invalid-bridge',
    ]);
  });

  it('requires a security contact, from either field or DOCUMENTATION', () => {
    const { SECURITY_CONTACT: _s, SECURITY_CONTACT_HOURS: _h, ...bare } = GOOD;
    expect(rules(bare)).toEqual(['bridgepause/missing-security-contact']);
    expect(rules({ ...bare, SECURITY_CONTACT: 'not an email' })).toEqual([
      'bridgepause/missing-security-contact',
    ]);
    expect(rules({ ...bare, ORG_OFFICIAL_EMAIL: 'ops@example.com' })).toEqual([
      'bridgepause/contact-not-24x7',
    ]);
    expect(
      rules({
        ...bare,
        DOCUMENTATION: { ORG_OFFICIAL_EMAIL: 'ops@example.com', SECURITY_CONTACT_HOURS: '24x7' },
      }),
    ).toEqual([]);
    expect(rules({ ...GOOD, SECURITY_CONTACT: 'https://example.com/security' })).toEqual([]);
  });

  it('skips malformed bridge entries and honours overrides', () => {
    expect(rules({ ...GOOD, BRIDGES: ['x', null, 5] })).toEqual([]);
    const r = new BridgeEmergencyPauseValidator({
      rules: { 'bridgepause/missing-unpause-timelock': 'off' },
    }).validate(withBridge({ UNPAUSE_TIMELOCK_SECONDS: 0 }));
    expect(r.diagnostics).toEqual([]);
    expect(
      auditEmergencyPause({ ...GOOD, BRIDGES: [{ ...GOOD_BRIDGE, NAME: undefined }] }).bridges[
        'bridge #1'
      ],
    ).toBeDefined();
  });
});
