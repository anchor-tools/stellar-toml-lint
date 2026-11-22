import { describe, expect, it } from 'vitest';
import { Keypair } from '@stellar/stellar-base';
import {
  DEFAULT_ROTATION_GRACE_PERIOD_MS,
  KEY_ROTATION_CROSS_SIGNATURE_INVALID,
  KEY_ROTATION_CROSS_SIGNATURE_MISSING,
  KEY_ROTATION_KEY_INVALID,
  KEY_ROTATION_MARKERS_INCOMPLETE,
  KEY_ROTATION_QUORUM_NOT_ADOPTED,
  KEY_ROTATION_RETIRED_KEY_ADVERTISED,
  KEY_ROTATION_RETIRED_KEY_TRUSTED,
  KEY_ROTATION_SAME_KEY,
  KEY_ROTATION_TRANSITION_ACTIVE,
  KEY_ROTATION_TRANSITION_DATE_INVALID,
  ValidatorKeyRotationVerifier,
  detectRotationMarkers,
  hasRotationMarkers,
  keyRotationPayload,
  renderKeyRotationReport,
  signKeyRotationPayload,
  validatorKeyRotationRuleIds,
  validatorKeyRotationRules,
  verifyCrossSignatures,
} from '../../src/overlay/keyRotationVerifier.js';

const DOMAIN = 'anchor.example.com';
const PREVIOUS = Keypair.random();
const REPLACEMENT = Keypair.random();
const TRANSITION = '2026-01-15T00:00:00Z';
const AFTER_TRANSITION = new Date('2026-01-20T00:00:00Z');
const AFTER_GRACE = new Date('2026-03-01T00:00:00Z');

function markers(previous = PREVIOUS.publicKey(), replacement = REPLACEMENT.publicKey()) {
  return {
    previousPublicKey: previous,
    replacementPublicKey: replacement,
    transitionDate: TRANSITION,
  };
}

function announcement(rotation = markers()): Record<string, unknown> {
  return {
    PREVIOUS_PUBLIC_KEY: rotation.previousPublicKey,
    REPLACEMENT_PUBLIC_KEY: rotation.replacementPublicKey,
    TRANSITION_DATE: rotation.transitionDate,
  };
}

function attestation(signed = markers(), domain: string | undefined = DOMAIN) {
  return {
    previousKeySignature: signKeyRotationPayload(PREVIOUS, signed, domain),
    replacementKeySignature: signKeyRotationPayload(REPLACEMENT, signed, domain),
  };
}

describe('ValidatorKeyRotationVerifier', () => {
  it('reports nothing when no rotation markers were announced', () => {
    const verifier = new ValidatorKeyRotationVerifier({ domain: DOMAIN });
    const report = verifier.audit({ VALIDATORS: [{ PUBLIC_KEY: PREVIOUS.publicKey() }] });

    expect(report.detected).toBe(false);
    expect(report.phase).toBe('none');
    expect(report.ok).toBe(true);
    expect(report.diagnostics).toEqual([]);
    expect(report.checklist).toEqual([]);
    expect(report.crossSignatures.verified).toBe(false);
    expect(renderKeyRotationReport(report)).toContain('No rotation markers found');
  });

  it('detects all three markers and ignores non-string values', () => {
    const detected = detectRotationMarkers({
      PREVIOUS_PUBLIC_KEY: ` ${PREVIOUS.publicKey()} `,
      REPLACEMENT_PUBLIC_KEY: REPLACEMENT.publicKey(),
      TRANSITION_DATE: TRANSITION,
    });
    expect(detected).toEqual({
      previousPublicKey: PREVIOUS.publicKey(),
      replacementPublicKey: REPLACEMENT.publicKey(),
      transitionDate: TRANSITION,
    });
    expect(hasRotationMarkers(detected)).toBe(true);
    expect(hasRotationMarkers(detectRotationMarkers({ PREVIOUS_PUBLIC_KEY: 42 }))).toBe(false);
    expect(detectRotationMarkers({ TRANSITION_DATE: '   ' })).toEqual({});
  });

  it('accepts a smooth rotation that is cross-signed and adopted by every peer', () => {
    const verifier = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(),
      declaredValidatorKeys: [REPLACEMENT.publicKey()],
      peers: [
        { name: 'peer-a', validatorKeys: [REPLACEMENT.publicKey()] },
        { name: 'peer-b', validatorKeys: [REPLACEMENT.publicKey()] },
        { name: 'anchor-x', kind: 'anchor', validatorKeys: [REPLACEMENT.publicKey()] },
      ],
      now: AFTER_GRACE,
    });

    const report = verifier.audit(announcement());
    expect(report.ok).toBe(true);
    expect(report.phase).toBe('complete');
    expect(report.detected).toBe(true);
    expect(report.crossSignatures.verified).toBe(true);
    expect(report.crossSignatures.previousKeyValid).toBe(true);
    expect(report.crossSignatures.replacementKeyValid).toBe(true);
    expect(report.quorum.adoptedBy).toEqual(['peer-a', 'peer-b', 'anchor-x']);
    expect(report.quorum.missing).toEqual([]);
    expect(report.checks.some((check) => check.severity === 'error')).toBe(false);
    expect(report.checklist.length).toBeGreaterThan(0);

    const rendered = renderKeyRotationReport(report);
    expect(rendered).toContain('cross-signatures: verified (both keys)');
    expect(rendered).toContain('quorum adoption: 3/3');
    expect(rendered).toContain('operator checklist:');
    expect(rendered).toContain('Result: rotation is coordinated');
  });

  it('reports incomplete markers when only the retiring key is announced', () => {
    const report = new ValidatorKeyRotationVerifier({ domain: DOMAIN }).audit({
      PREVIOUS_PUBLIC_KEY: PREVIOUS.publicKey(),
    });

    expect(report.detected).toBe(true);
    expect(report.phase).toBe('none');
    expect(report.ok).toBe(false);
    expect(report.checks.map((check) => check.code)).toContain(KEY_ROTATION_MARKERS_INCOMPLETE);
    expect(report.checklist).toEqual([]);
  });

  it('rejects invalid account ids for either marker', () => {
    const report = new ValidatorKeyRotationVerifier().audit({
      PREVIOUS_PUBLIC_KEY: 'not-a-key',
      REPLACEMENT_PUBLIC_KEY: 'S-not-a-key',
      TRANSITION_DATE: TRANSITION,
    });
    const invalid = report.checks.filter((check) => check.code === KEY_ROTATION_KEY_INVALID);
    expect(invalid).toHaveLength(2);
    expect(report.diagnostics).toHaveLength(report.checks.length);
    expect(report.diagnostics.every((diagnostic) => diagnostic.category === 'network')).toBe(true);
  });

  it('rejects a rotation that reuses the compromised key', () => {
    const key = PREVIOUS.publicKey();
    const report = new ValidatorKeyRotationVerifier().audit({
      PREVIOUS_PUBLIC_KEY: key,
      REPLACEMENT_PUBLIC_KEY: key,
      TRANSITION_DATE: TRANSITION,
    });
    expect(report.checks.map((check) => check.code)).toContain(KEY_ROTATION_SAME_KEY);
    expect(report.ok).toBe(false);
  });

  it('rejects an unparseable transition date and leaves the phase undefined', () => {
    const rotation = markers();
    rotation.transitionDate = 'next tuesday';
    const report = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(rotation),
    }).audit(announcement(rotation));

    expect(report.phase).toBe('none');
    expect(report.checks.map((check) => check.code)).toContain(
      KEY_ROTATION_TRANSITION_DATE_INVALID,
    );
  });

  // --- Cross-signature verification: every branch is exercised below. -------

  it('fails closed when no attestation is supplied', () => {
    const result = verifyCrossSignatures(markers(), undefined, DOMAIN);
    expect(result.verified).toBe(false);
    expect(result.previousKeyValid).toBe(false);
    expect(result.replacementKeyValid).toBe(false);
    expect(result.errors).toEqual([
      'the retiring key did not sign the rotation announcement',
      'the replacement key did not sign the rotation announcement',
    ]);
  });

  it('fails when only the retiring key signed', () => {
    const rotation = markers();
    const result = verifyCrossSignatures(
      rotation,
      { previousKeySignature: signKeyRotationPayload(PREVIOUS, rotation, DOMAIN) },
      DOMAIN,
    );
    expect(result.previousKeyValid).toBe(true);
    expect(result.replacementKeyValid).toBe(false);
    expect(result.verified).toBe(false);
    expect(result.errors).toContain('the replacement key did not sign the rotation announcement');
  });

  it('fails when only the replacement key signed', () => {
    const rotation = markers();
    const result = verifyCrossSignatures(
      rotation,
      { replacementKeySignature: signKeyRotationPayload(REPLACEMENT, rotation, DOMAIN) },
      DOMAIN,
    );
    expect(result.previousKeyValid).toBe(false);
    expect(result.replacementKeyValid).toBe(true);
    expect(result.verified).toBe(false);
    expect(result.errors).toContain('the retiring key did not sign the rotation announcement');
  });

  it('fails when the signatures were produced by the wrong keys', () => {
    const rotation = markers();
    const stranger = Keypair.random();
    const result = verifyCrossSignatures(
      rotation,
      {
        previousKeySignature: signKeyRotationPayload(stranger, rotation, DOMAIN),
        replacementKeySignature: signKeyRotationPayload(stranger, rotation, DOMAIN),
      },
      DOMAIN,
    );
    expect(result.verified).toBe(false);
    expect(result.errors).toContain(
      'the retiring key signature does not verify against PREVIOUS_PUBLIC_KEY',
    );
    expect(result.errors).toContain(
      'the replacement key signature does not verify against REPLACEMENT_PUBLIC_KEY',
    );
  });

  it('fails on signatures that are neither base64 nor hex', () => {
    const rotation = markers();
    const result = verifyCrossSignatures(
      rotation,
      {
        previousKeySignature: '!!! not a signature !!!',
        replacementKeySignature: '   ',
      },
      DOMAIN,
    );
    expect(result.previousKeyValid).toBe(false);
    expect(result.replacementKeyValid).toBe(false);
    expect(result.verified).toBe(false);
  });

  it('accepts hex-encoded signatures and binds them to the audited domain', () => {
    const rotation = markers();
    const hex = {
      previousKeySignature: Buffer.from(
        PREVIOUS.sign(Buffer.from(keyRotationPayload(rotation, DOMAIN))),
      ).toString('hex'),
      replacementKeySignature: Buffer.from(
        REPLACEMENT.sign(Buffer.from(keyRotationPayload(rotation, DOMAIN))),
      ).toString('hex'),
    };

    expect(verifyCrossSignatures(rotation, hex, DOMAIN).verified).toBe(true);
    // The same signatures must not verify for another host.
    expect(verifyCrossSignatures(rotation, hex, 'other.example.com').verified).toBe(false);
    // Without a domain the payload changes, so the bound signatures fail.
    expect(verifyCrossSignatures(rotation, hex).verified).toBe(false);
  });

  it('fails safely when a signature cannot be decoded against a malformed key', () => {
    const rotation = markers('not-a-key', REPLACEMENT.publicKey());
    const result = verifyCrossSignatures(
      rotation,
      {
        previousKeySignature: Buffer.alloc(64, 7).toString('base64'),
        replacementKeySignature: signKeyRotationPayload(REPLACEMENT, rotation, DOMAIN),
      },
      DOMAIN,
    );
    expect(result.previousKeyValid).toBe(false);
    expect(result.replacementKeyValid).toBe(true);
    expect(result.errors).toContain(
      'the retiring key signature does not verify against PREVIOUS_PUBLIC_KEY',
    );
  });

  it('skips verification for a marker that is not announced', () => {
    const previousMarkers = {
      previousPublicKey: PREVIOUS.publicKey(),
      transitionDate: TRANSITION,
    };
    const previousOnly = verifyCrossSignatures(
      previousMarkers,
      {
        previousKeySignature: signKeyRotationPayload(PREVIOUS, previousMarkers, DOMAIN),
        replacementKeySignature: Buffer.alloc(64, 2).toString('base64'),
      },
      DOMAIN,
    );
    expect(previousOnly.previousKeyValid).toBe(true);
    expect(previousOnly.replacementKeyValid).toBe(false);
    expect(previousOnly.verified).toBe(false);
    expect(previousOnly.errors).toEqual([]);

    const replacementMarkers = {
      replacementPublicKey: REPLACEMENT.publicKey(),
      transitionDate: TRANSITION,
    };
    const replacementOnly = verifyCrossSignatures(
      replacementMarkers,
      {
        previousKeySignature: Buffer.alloc(64, 1).toString('base64'),
        replacementKeySignature: signKeyRotationPayload(REPLACEMENT, replacementMarkers, DOMAIN),
      },
      DOMAIN,
    );
    expect(replacementOnly.previousKeyValid).toBe(false);
    expect(replacementOnly.replacementKeyValid).toBe(true);
    expect(replacementOnly.errors).toEqual([]);
  });

  it('does not report signature errors for markers that are absent', () => {
    const result = verifyCrossSignatures(
      { transitionDate: TRANSITION },
      {
        previousKeySignature: signKeyRotationPayload(PREVIOUS, {}, DOMAIN),
        replacementKeySignature: signKeyRotationPayload(REPLACEMENT, {}, DOMAIN),
      },
      DOMAIN,
    );
    expect(result.verified).toBe(false);
    expect(result.errors).toEqual([]);
  });

  it('keeps a partially applied announcement behind a missing cross-signature error', () => {
    const report = new ValidatorKeyRotationVerifier({ domain: DOMAIN }).audit(announcement());
    expect(report.crossSignatures.verified).toBe(false);
    expect(report.checks.map((check) => check.code)).toContain(
      KEY_ROTATION_CROSS_SIGNATURE_MISSING,
    );
    expect(report.ok).toBe(false);
    expect(renderKeyRotationReport(report)).toContain('cross-signatures: NOT VERIFIED');
  });

  it('reports which signature failed when verification runs and fails', () => {
    const rotation = markers();
    const report = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: {
        previousKeySignature: signKeyRotationPayload(PREVIOUS, rotation, DOMAIN),
        replacementKeySignature: signKeyRotationPayload(Keypair.random(), rotation, DOMAIN),
      },
    }).audit(announcement(rotation));

    expect(report.checks.map((check) => check.code)).toContain(
      KEY_ROTATION_CROSS_SIGNATURE_INVALID,
    );
    expect(renderKeyRotationReport(report)).toContain(
      'does not verify against REPLACEMENT_PUBLIC_KEY',
    );
  });

  // --- Quorum coordination and transition windows. --------------------------

  it('flags peers and downstream anchors that have not adopted the replacement key', () => {
    const report = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(),
      peers: [
        { name: 'peer-a', validatorKeys: [PREVIOUS.publicKey(), REPLACEMENT.publicKey()] },
        { name: 'peer-b', validatorKeys: [PREVIOUS.publicKey()] },
        { name: 'anchor-x', kind: 'anchor', validatorKeys: [] },
      ],
      now: AFTER_TRANSITION,
    }).audit(announcement());

    expect(report.phase).toBe('in-progress');
    expect(report.quorum.adoptedBy).toEqual(['peer-a']);
    expect(report.quorum.missing).toEqual(['peer-b', 'anchor-x']);
    const quorumFindings = report.checks.filter(
      (check) => check.code === KEY_ROTATION_QUORUM_NOT_ADOPTED,
    );
    expect(quorumFindings).toHaveLength(2);
    expect(quorumFindings.map((check) => check.message).join(' ')).toContain(
      'Downstream anchor "anchor-x"',
    );
    expect(report.ok).toBe(false);
    expect(renderKeyRotationReport(report)).toContain('missing peer peer-b');
    expect(renderKeyRotationReport(report)).toContain('still trusts retired key');
  });

  it('treats connection keywords as peers in the default kind', () => {
    const report = new ValidatorKeyRotationVerifier({
      peers: [{ name: 'peer-a', validatorKeys: [] }],
      now: AFTER_TRANSITION,
    }).audit(announcement());
    expect(report.quorum.peers[0]?.kind).toBe('peer');
  });

  it('emits the scheduled checklist before the transition date', () => {
    const report = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(),
      declaredValidatorKeys: [PREVIOUS.publicKey(), REPLACEMENT.publicKey()],
      peers: [{ name: 'peer-a', validatorKeys: [PREVIOUS.publicKey(), REPLACEMENT.publicKey()] }],
      now: new Date('2026-01-01T00:00:00Z'),
    }).audit(announcement());

    expect(report.phase).toBe('scheduled');
    expect(report.checks.map((check) => check.code)).toContain(KEY_ROTATION_TRANSITION_ACTIVE);
    expect(report.checklist[0]).toContain('Publish PREVIOUS_PUBLIC_KEY');
    expect(renderKeyRotationReport(report)).toContain('window:     scheduled');
  });

  it('escalates an overdue window when peers still trust the retired key', () => {
    const report = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(),
      declaredValidatorKeys: [PREVIOUS.publicKey(), REPLACEMENT.publicKey()],
      peers: [{ name: 'peer-a', validatorKeys: [PREVIOUS.publicKey(), REPLACEMENT.publicKey()] }],
      now: AFTER_GRACE,
    }).audit(announcement());

    expect(report.phase).toBe('overdue');
    const codes = report.checks.map((check) => check.code);
    expect(codes).toContain(KEY_ROTATION_RETIRED_KEY_TRUSTED);
    expect(codes).toContain(KEY_ROTATION_RETIRED_KEY_ADVERTISED);
    expect(report.checklist.join(' ')).toContain('Contact every peer still missing');
    expect(renderKeyRotationReport(report)).toContain('do NOT sign with the replacement key');
  });

  it('does not advertise the replacement key in [[VALIDATORS]] yet', () => {
    const report = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(),
      declaredValidatorKeys: [PREVIOUS.publicKey()],
      peers: [{ name: 'peer-a', validatorKeys: [REPLACEMENT.publicKey()] }],
      now: AFTER_GRACE,
    }).audit(announcement());
    expect(report.checks.map((check) => check.code)).toContain(KEY_ROTATION_RETIRED_KEY_ADVERTISED);
  });

  it('honours rule overrides without changing the underlying verification', () => {
    const suppressed = new ValidatorKeyRotationVerifier({
      rules: { [KEY_ROTATION_MARKERS_INCOMPLETE]: 'off' },
    }).audit({ PREVIOUS_PUBLIC_KEY: PREVIOUS.publicKey() });
    expect(suppressed.checks.map((check) => check.code)).not.toContain(
      KEY_ROTATION_MARKERS_INCOMPLETE,
    );

    const escalated = new ValidatorKeyRotationVerifier({
      domain: DOMAIN,
      attestation: attestation(),
      declaredValidatorKeys: [PREVIOUS.publicKey()],
      rules: { [KEY_ROTATION_TRANSITION_ACTIVE]: 'warning' },
      now: AFTER_TRANSITION,
    }).audit(announcement());
    const active = escalated.checks.find((check) => check.code === KEY_ROTATION_TRANSITION_ACTIVE);
    expect(active?.severity).toBe('warning');

    const raised = new ValidatorKeyRotationVerifier({
      rules: { [KEY_ROTATION_TRANSITION_ACTIVE]: 'error' },
      domain: DOMAIN,
      attestation: attestation(),
      declaredValidatorKeys: [PREVIOUS.publicKey()],
      now: AFTER_TRANSITION,
    }).audit(announcement());
    expect(
      raised.checks.find((check) => check.code === KEY_ROTATION_TRANSITION_ACTIVE)?.severity,
    ).toBe('error');
    expect(raised.ok).toBe(false);

    const informational = new ValidatorKeyRotationVerifier({
      rules: { [KEY_ROTATION_QUORUM_NOT_ADOPTED]: 'info' },
      peers: [{ name: 'peer-a', validatorKeys: [] }],
      now: AFTER_TRANSITION,
    }).audit(announcement());
    expect(
      informational.checks.find((check) => check.code === KEY_ROTATION_QUORUM_NOT_ADOPTED)
        ?.severity,
    ).toBe('info');
  });

  it('exposes a stable rule registry', () => {
    expect(validatorKeyRotationRules).toHaveLength(10);
    expect(validatorKeyRotationRuleIds).toContain(KEY_ROTATION_CROSS_SIGNATURE_INVALID);
    expect(validatorKeyRotationRuleIds).toContain(KEY_ROTATION_RETIRED_KEY_TRUSTED);
    expect(DEFAULT_ROTATION_GRACE_PERIOD_MS).toBe(14 * 24 * 60 * 60 * 1000);
  });

  it('renders a report for a fully announced but unverified rotation', () => {
    const report = new ValidatorKeyRotationVerifier({ domain: DOMAIN }).audit(announcement());
    const rendered = renderKeyRotationReport(report);
    expect(rendered).toContain(`previous:  ${PREVIOUS.publicKey()}`);
    expect(rendered).toContain(`replacement: ${REPLACEMENT.publicKey()}`);
    expect(rendered).toContain(`transition: ${TRANSITION}`);
    expect(rendered).toContain('payload: stellar-toml-lint/key-rotation/v1');
  });
});
