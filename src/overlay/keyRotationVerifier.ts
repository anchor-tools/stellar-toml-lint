/**
 * Validator key rotation and revocation sequence verifier.
 *
 * Rotating a validator signing key is a network-wide operation, not a one-line
 * edit to `stellar.toml`. The file can only announce intent: the retiring key
 * (`PREVIOUS_PUBLIC_KEY`), the key that will replace it
 * (`REPLACEMENT_PUBLIC_KEY`) and the ledger-independent transition moment
 * (`TRANSITION_DATE`). Adopting the replacement is a separate act performed by
 * every peer and downstream anchor that lists the validator in a quorum slice.
 *
 * A rotation that is only announced is a consensus-stall risk: as soon as the
 * node signs with the replacement key, peers still configured with the retired
 * key stop accepting its SCP envelopes. This verifier therefore performs three
 * checks that must agree before a rotation can be called coordinated:
 *
 * 1. The three markers are present, well formed and refer to different keys.
 * 2. Both keys cross-sign the canonical rotation announcement, proving the
 *    replacement was authorised by the retiring key and not injected by a third
 *    party that can edit the file.
 * 3. Every known peer and downstream anchor quorum slice lists the replacement
 *    key, and the retiring key has been dropped once the transition is over.
 *
 * The audit is deterministic and offline: operators supply the attestation and
 * the quorum slices of their peers, and the verifier renders an ordered
 * checklist for the window between announcement and revocation.
 */

import { Keypair, StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

/** One of the three rotation markers is absent. */
export const KEY_ROTATION_MARKERS_INCOMPLETE = 'overlay/key-rotation-markers-incomplete';
/** A marker is not a StrKey-encoded Ed25519 account id. */
export const KEY_ROTATION_KEY_INVALID = 'overlay/key-rotation-key-invalid';
/** The retiring and replacement keys are the same key. */
export const KEY_ROTATION_SAME_KEY = 'overlay/key-rotation-same-key';
/** `TRANSITION_DATE` is not an ISO-8601 timestamp. */
export const KEY_ROTATION_TRANSITION_DATE_INVALID = 'overlay/key-rotation-transition-date-invalid';
/** One or both cross-signatures are missing. */
export const KEY_ROTATION_CROSS_SIGNATURE_MISSING = 'overlay/key-rotation-cross-signature-missing';
/** A cross-signature does not verify against the key that must have produced it. */
export const KEY_ROTATION_CROSS_SIGNATURE_INVALID = 'overlay/key-rotation-cross-signature-invalid';
/** A peer or downstream anchor quorum slice still lacks the replacement key. */
export const KEY_ROTATION_QUORUM_NOT_ADOPTED = 'overlay/key-rotation-quorum-not-adopted';
/** A peer still trusts the retiring key after the transition window closed. */
export const KEY_ROTATION_RETIRED_KEY_TRUSTED = 'overlay/key-rotation-retired-key-trusted';
/** The advertised `[[VALIDATORS]]` entry still names the retiring key. */
export const KEY_ROTATION_RETIRED_KEY_ADVERTISED = 'overlay/key-rotation-retired-key-advertised';
/** An ongoing transition window still needs operator action. */
export const KEY_ROTATION_TRANSITION_ACTIVE = 'overlay/key-rotation-transition-active';

/** Default grace period after `TRANSITION_DATE` before the rotation is overdue. */
export const DEFAULT_ROTATION_GRACE_PERIOD_MS = 14 * 24 * 60 * 60 * 1000;

const PAYLOAD_PREFIX = 'stellar-toml-lint/key-rotation/v1';

/** Rotation markers read from the top level of `stellar.toml`. */
export interface KeyRotationMarkers {
  previousPublicKey?: string;
  replacementPublicKey?: string;
  /** Raw `TRANSITION_DATE` value, so the caller can see what was announced. */
  transitionDate?: string;
}

/**
 * Cross-signature attestation for a rotation announcement.
 *
 * Both values are signatures over {@link keyRotationPayload}. The retiring key
 * signs to authorise the successor; the successor signs to prove possession of
 * the private key before peers are asked to trust it.
 */
export interface KeyRotationAttestation {
  /** Base64 (or hex) Ed25519 signature produced by `previousPublicKey`. */
  previousKeySignature?: string;
  /** Base64 (or hex) Ed25519 signature produced by `replacementPublicKey`. */
  replacementKeySignature?: string;
}

/** Quorum slice of a peer or downstream anchor that consumes the validator. */
export interface QuorumPeerConfig {
  /** Human-readable peer name, used in findings. */
  name: string;
  /** Validator public keys the peer currently trusts. */
  validatorKeys: readonly string[];
  /** Distinguishes another validator from a downstream anchor. */
  kind?: 'peer' | 'anchor';
}

export interface KeyRotationVerifierOptions {
  rules?: RuleOverrides;
  /** Domain the announcement is published for; binds signatures to the host. */
  domain?: string;
  /** Attestation signatures supplied by the node operator. */
  attestation?: KeyRotationAttestation;
  /** Known peer and downstream anchor quorum slices. */
  peers?: readonly QuorumPeerConfig[];
  /** `[[VALIDATORS]].PUBLIC_KEY` values currently advertised by the file. */
  declaredValidatorKeys?: readonly string[];
  /** Overrides the clock, for deterministic transition-window tests. */
  now?: Date;
  /** How long after `TRANSITION_DATE` the rotation is still tolerated. */
  gracePeriodMs?: number;
}

export interface CrossSignatureVerification {
  /** Canonical UTF-8 payload both keys must sign. */
  payload: string;
  previousKeyValid: boolean;
  replacementKeyValid: boolean;
  /** True only when both signatures verify against the expected keys. */
  verified: boolean;
  errors: string[];
}

export interface QuorumRecognition {
  name: string;
  kind: 'peer' | 'anchor';
  recognizesReplacement: boolean;
  stillTrustsRetired: boolean;
}

export interface KeyRotationCheck {
  code: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  suggestion?: string;
}

export type RotationPhase = 'none' | 'scheduled' | 'in-progress' | 'overdue' | 'complete';

export interface KeyRotationReport {
  ok: boolean;
  domain?: string;
  detected: boolean;
  markers: KeyRotationMarkers;
  phase: RotationPhase;
  transitionDate?: string;
  crossSignatures: CrossSignatureVerification;
  quorum: {
    peers: QuorumRecognition[];
    adoptedBy: string[];
    missing: string[];
  };
  checks: KeyRotationCheck[];
  checklist: string[];
  diagnostics: Diagnostic[];
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning' | 'info',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | 'info' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  if (override === 'error' || override === 'warning') return override;
  if (override === 'info') return 'info';
  return fallback;
}

function trimmed(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const text = value.trim();
  return text.length === 0 ? undefined : text;
}

/**
 * Reads the three rotation markers from the top level of a parsed document.
 * Values that are not strings are ignored so the caller can report the marker
 * as missing rather than as an unrelated schema violation.
 */
export function detectRotationMarkers(doc: Record<string, unknown>): KeyRotationMarkers {
  const markers: KeyRotationMarkers = {};
  const previous = trimmed(doc.PREVIOUS_PUBLIC_KEY);
  const replacement = trimmed(doc.REPLACEMENT_PUBLIC_KEY);
  const transition = trimmed(doc.TRANSITION_DATE);
  if (previous !== undefined) markers.previousPublicKey = previous;
  if (replacement !== undefined) markers.replacementPublicKey = replacement;
  if (transition !== undefined) markers.transitionDate = transition;
  return markers;
}

/** True when at least one rotation marker is present. */
export function hasRotationMarkers(markers: KeyRotationMarkers): boolean {
  return (
    markers.previousPublicKey !== undefined ||
    markers.replacementPublicKey !== undefined ||
    markers.transitionDate !== undefined
  );
}

/**
 * Canonical bytes both keys sign. The domain is part of the payload so a
 * signature harvested from one anchor's stellar.toml cannot be replayed on
 * another host.
 */
export function keyRotationPayload(markers: KeyRotationMarkers, domain?: string): string {
  return [
    PAYLOAD_PREFIX,
    domain ?? '',
    markers.previousPublicKey ?? '',
    markers.replacementPublicKey ?? '',
    markers.transitionDate ?? '',
  ].join('|');
}

/** Signs the rotation payload with a validator keypair. */
export function signKeyRotationPayload(
  keypair: Keypair,
  markers: KeyRotationMarkers,
  domain?: string,
): string {
  return keypair.sign(Buffer.from(keyRotationPayload(markers, domain), 'utf8')).toString('base64');
}

function decodeSignature(signature: string): Buffer | undefined {
  const value = signature.trim();
  if (value.length === 0) return undefined;
  const base64 = Buffer.from(value, 'base64');
  if (base64.length === 64) return base64;
  if (/^[0-9a-f]{128}$/i.test(value)) return Buffer.from(value, 'hex');
  return undefined;
}

function verifiesWith(
  publicKey: string | undefined,
  signature: string | undefined,
  payload: string,
): boolean {
  if (publicKey === undefined || signature === undefined) return false;
  const bytes = decodeSignature(signature);
  if (bytes === undefined) return false;
  try {
    return Keypair.fromPublicKey(publicKey).verify(Buffer.from(payload, 'utf8'), bytes);
  } catch {
    return false;
  }
}

/**
 * Verifies the bidirectional cross-signature between the retiring key and its
 * replacement. Both signatures are mandatory: a one-sided signature proves only
 * that one of the two parties participated, which is exactly the silent,
 * uncoordinated rotation this verifier exists to reject.
 */
export function verifyCrossSignatures(
  markers: KeyRotationMarkers,
  attestation: KeyRotationAttestation | undefined,
  domain?: string,
): CrossSignatureVerification {
  const payload = keyRotationPayload(markers, domain);
  const previous = markers.previousPublicKey;
  const replacement = markers.replacementPublicKey;
  const errors: string[] = [];

  if (attestation?.previousKeySignature === undefined) {
    errors.push('the retiring key did not sign the rotation announcement');
  }
  if (attestation?.replacementKeySignature === undefined) {
    errors.push('the replacement key did not sign the rotation announcement');
  }

  const previousKeyValid = verifiesWith(previous, attestation?.previousKeySignature, payload);
  const replacementKeyValid = verifiesWith(
    replacement,
    attestation?.replacementKeySignature,
    payload,
  );

  if (
    previous !== undefined &&
    attestation?.previousKeySignature !== undefined &&
    !previousKeyValid
  ) {
    errors.push('the retiring key signature does not verify against PREVIOUS_PUBLIC_KEY');
  }
  if (
    replacement !== undefined &&
    attestation?.replacementKeySignature !== undefined &&
    !replacementKeyValid
  ) {
    errors.push('the replacement key signature does not verify against REPLACEMENT_PUBLIC_KEY');
  }

  return {
    payload,
    previousKeyValid,
    replacementKeyValid,
    verified: previousKeyValid && replacementKeyValid,
    errors,
  };
}

function isAccountId(value: string): boolean {
  try {
    StrKey.decodeEd25519PublicKey(value);
    return true;
  } catch {
    return false;
  }
}

function parseTransitionDate(value: string | undefined): Date | undefined {
  if (value === undefined) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

const CHECKLIST_SCHEDULED: readonly string[] = [
  'Publish PREVIOUS_PUBLIC_KEY, REPLACEMENT_PUBLIC_KEY and TRANSITION_DATE together, with both cross-signatures, before touching the quorum configuration.',
  'Distribute the cross-signed announcement to every validator peer and downstream anchor that lists this node in a quorum slice.',
  'Confirm each peer accepts the replacement key in its quorum slice while still trusting the retiring key, so no threshold is lost during the switch.',
  'Restart validators with the replacement seed only after the transition window opens, and announce the exact ledger of the switch on all operator channels.',
];

const CHECKLIST_IN_PROGRESS: readonly string[] = [
  'Watch peer quorum slices and SCP envelope acceptance for the first hour of the window; a peer that has not adopted the replacement key will stall consensus.',
  'Keep the retiring node reachable and signing until every configured peer reports the replacement key in its quorum slice.',
  'Record the first ledger signed with the replacement key and publish it with the rotation announcement.',
];

const CHECKLIST_OVERDUE: readonly string[] = [
  'Contact every peer still missing the replacement key and escalate to that operator before the next consensus upgrade.',
  'Re-verify the cross-signature before extending the transition: an expired window is an operational incident, not a reason to publish an unsigned key.',
  'Remove the retiring key from all quorum slices, then revoke it and retire the corresponding secret material.',
];

const CHECKLIST_COMPLETE: readonly string[] = [
  'Remove PREVIOUS_PUBLIC_KEY, REPLACEMENT_PUBLIC_KEY and TRANSITION_DATE once every peer reports the replacement key, and record the completed rotation in the operator log.',
  'Revoke the retiring key and confirm the old seed is destroyed wherever it was stored.',
];

/**
 * Audits a parsed `stellar.toml` for a coordinated validator key rotation.
 *
 * A file with no rotation markers is valid and produces no findings: the
 * verifier only takes responsibility once an operator has announced a rotation.
 */
export class ValidatorKeyRotationVerifier {
  readonly options: KeyRotationVerifierOptions;

  constructor(options: KeyRotationVerifierOptions = {}) {
    this.options = options;
  }

  detect(doc: Record<string, unknown>): KeyRotationMarkers {
    return detectRotationMarkers(doc);
  }

  /** Classifies the rotation window against the configured clock. */
  phase(
    markers: KeyRotationMarkers,
    now: Date,
    gracePeriodMs: number,
    retiredKeyStillTrusted: boolean,
  ): RotationPhase {
    if (!hasRotationMarkers(markers)) return 'none';
    const transition = parseTransitionDate(markers.transitionDate);
    if (transition === undefined) return 'none';
    if (now.getTime() < transition.getTime()) return 'scheduled';
    if (!retiredKeyStillTrusted) return 'complete';
    return now.getTime() >= transition.getTime() + gracePeriodMs ? 'overdue' : 'in-progress';
  }

  private check(
    code: string,
    fallback: 'error' | 'warning' | 'info',
    message: string,
    suggestion?: string,
  ): KeyRotationCheck | undefined {
    const severity = severityFor(code, fallback, this.options.rules);
    if (severity === undefined) return undefined;
    const check: KeyRotationCheck = { code, severity, message };
    if (suggestion !== undefined) check.suggestion = suggestion;
    return check;
  }

  audit(doc: Record<string, unknown>): KeyRotationReport {
    const markers = this.detect(doc);
    const domain = this.options.domain;
    const now = this.options.now ?? new Date();
    const gracePeriodMs = this.options.gracePeriodMs ?? DEFAULT_ROTATION_GRACE_PERIOD_MS;
    const declared = this.options.declaredValidatorKeys ?? [];
    const checks: KeyRotationCheck[] = [];
    const add = (check: KeyRotationCheck | undefined): void => {
      if (check !== undefined) checks.push(check);
    };

    const crossSignatures = verifyCrossSignatures(markers, this.options.attestation, domain);
    const detected = hasRotationMarkers(markers);
    const previous = markers.previousPublicKey;
    const replacement = markers.replacementPublicKey;

    if (!detected) {
      return {
        ok: true,
        ...(domain === undefined ? {} : { domain }),
        detected: false,
        markers,
        phase: 'none',
        crossSignatures,
        quorum: { peers: [], adoptedBy: [], missing: [] },
        checks,
        checklist: [],
        diagnostics: [],
      };
    }

    if (
      previous === undefined ||
      replacement === undefined ||
      markers.transitionDate === undefined
    ) {
      add(
        this.check(
          KEY_ROTATION_MARKERS_INCOMPLETE,
          'error',
          'A key rotation is announced but PREVIOUS_PUBLIC_KEY, REPLACEMENT_PUBLIC_KEY and TRANSITION_DATE are not all present',
          'Publish all three markers in the same revision so peers can plan the switch; a partially announced rotation cannot be coordinated.',
        ),
      );
    }

    for (const [field, key] of [
      ['PREVIOUS_PUBLIC_KEY', previous],
      ['REPLACEMENT_PUBLIC_KEY', replacement],
    ] as const) {
      if (key !== undefined && !isAccountId(key)) {
        add(
          this.check(
            KEY_ROTATION_KEY_INVALID,
            'error',
            `${field} is not a valid Ed25519 account id`,
            `Publish the StrKey form of the key (G...) for ${field}.`,
          ),
        );
      }
    }

    if (previous !== undefined && replacement !== undefined && previous === replacement) {
      add(
        this.check(
          KEY_ROTATION_SAME_KEY,
          'error',
          'PREVIOUS_PUBLIC_KEY and REPLACEMENT_PUBLIC_KEY are the same key',
          'Announce a genuinely new validator key; reusing the compromised key defeats the rotation.',
        ),
      );
    }

    const transition = parseTransitionDate(markers.transitionDate);
    if (markers.transitionDate !== undefined && transition === undefined) {
      add(
        this.check(
          KEY_ROTATION_TRANSITION_DATE_INVALID,
          'error',
          `TRANSITION_DATE "${markers.transitionDate}" is not an ISO-8601 timestamp`,
          'Use an unambiguous UTC timestamp such as 2026-01-31T00:00:00Z so every operator agrees on the window.',
        ),
      );
    }

    if (previous !== undefined && replacement !== undefined) {
      const attestation = this.options.attestation;
      if (
        attestation?.previousKeySignature === undefined ||
        attestation?.replacementKeySignature === undefined
      ) {
        add(
          this.check(
            KEY_ROTATION_CROSS_SIGNATURE_MISSING,
            'error',
            'The rotation announcement is not cross-signed by both the retiring and the replacement key',
            'Have both keys sign the canonical rotation payload and publish both signatures with the markers.',
          ),
        );
      } else if (!crossSignatures.verified) {
        add(
          this.check(
            KEY_ROTATION_CROSS_SIGNATURE_INVALID,
            'error',
            `Cross-signature verification failed: ${crossSignatures.errors.join('; ')}`,
            'Re-sign the canonical payload with each private key; do not publish the replacement key until both signatures verify.',
          ),
        );
      }
    }

    if (replacement !== undefined && declared.length > 0 && !declared.includes(replacement)) {
      add(
        this.check(
          KEY_ROTATION_RETIRED_KEY_ADVERTISED,
          'error',
          '[[VALIDATORS]].PUBLIC_KEY does not advertise REPLACEMENT_PUBLIC_KEY',
          'Add the replacement key to [[VALIDATORS]] so peers discover the new identity before the switch.',
        ),
      );
    }

    const peers = this.options.peers ?? [];
    const quorumPeers: QuorumRecognition[] = peers.map((peer) => ({
      name: peer.name,
      kind: peer.kind ?? 'peer',
      recognizesReplacement: replacement !== undefined && peer.validatorKeys.includes(replacement),
      stillTrustsRetired: previous !== undefined && peer.validatorKeys.includes(previous),
    }));
    const adoptedBy = quorumPeers
      .filter((peer) => peer.recognizesReplacement)
      .map((peer) => peer.name);
    const missing = quorumPeers
      .filter((peer) => !peer.recognizesReplacement)
      .map((peer) => peer.name);

    for (const peer of quorumPeers) {
      if (replacement !== undefined && !peer.recognizesReplacement) {
        add(
          this.check(
            KEY_ROTATION_QUORUM_NOT_ADOPTED,
            'error',
            `${peer.kind === 'anchor' ? 'Downstream anchor' : 'Peer'} "${peer.name}" does not list REPLACEMENT_PUBLIC_KEY in its quorum slice`,
            `Ask ${peer.name} to add the replacement key to its quorum slice before the transition opens.`,
          ),
        );
      }
    }

    const retiredKeyStillTrusted =
      (previous !== undefined && declared.includes(previous)) ||
      quorumPeers.some((peer) => peer.stillTrustsRetired);
    const phase = this.phase(markers, now, gracePeriodMs, retiredKeyStillTrusted);

    if (phase === 'overdue') {
      for (const peer of quorumPeers) {
        if (peer.stillTrustsRetired) {
          add(
            this.check(
              KEY_ROTATION_RETIRED_KEY_TRUSTED,
              'warning',
              `${peer.name} still trusts the retiring validator key after the transition window closed`,
              'Have the peer remove PREVIOUS_PUBLIC_KEY from its quorum slice and confirm the replacement key meets the threshold.',
            ),
          );
        }
      }
      if (previous !== undefined && declared.includes(previous)) {
        add(
          this.check(
            KEY_ROTATION_RETIRED_KEY_ADVERTISED,
            'error',
            'The retiring key is still advertised in [[VALIDATORS]].PUBLIC_KEY after the transition window closed',
            'Replace the retired [[VALIDATORS]] entry with REPLACEMENT_PUBLIC_KEY and remove the stale announcement.',
          ),
        );
      }
    }

    if (phase === 'scheduled' || phase === 'in-progress' || phase === 'overdue') {
      add(
        this.check(
          KEY_ROTATION_TRANSITION_ACTIVE,
          'info',
          `Validator key transition is ${phase}; the replacement key must be adopted by all peers before signing with it`,
        ),
      );
    }

    const checklist =
      phase === 'scheduled'
        ? [...CHECKLIST_SCHEDULED]
        : phase === 'in-progress'
          ? [...CHECKLIST_IN_PROGRESS]
          : phase === 'overdue'
            ? [...CHECKLIST_OVERDUE]
            : phase === 'complete'
              ? [...CHECKLIST_COMPLETE]
              : [];

    const diagnostics: Diagnostic[] = checks.map((check) => ({
      rule: check.code,
      severity: check.severity,
      category: 'network',
      message: check.message,
      ...(check.suggestion === undefined ? {} : { suggestion: check.suggestion }),
    }));

    return {
      ok: !checks.some((check) => check.severity === 'error'),
      ...(domain === undefined ? {} : { domain }),
      detected: true,
      markers,
      phase,
      ...(markers.transitionDate === undefined ? {} : { transitionDate: markers.transitionDate }),
      crossSignatures,
      quorum: { peers: quorumPeers, adoptedBy, missing },
      checks,
      checklist,
      diagnostics,
    };
  }
}

/** Human-readable terminal report for `audit-validator-rotation`. */
export function renderKeyRotationReport(report: KeyRotationReport): string {
  const lines: string[] = [];
  const host = report.domain === undefined ? 'stellar.toml' : report.domain;
  lines.push(`Validator key rotation: ${host}`);
  if (!report.detected) {
    lines.push('  No rotation markers found; nothing to verify.');
    return `${lines.join('\n')}\n`;
  }

  lines.push(
    `  previous:  ${report.markers.previousPublicKey ?? '(missing)'}`,
    `  replacement: ${report.markers.replacementPublicKey ?? '(missing)'}`,
    `  transition: ${report.markers.transitionDate ?? '(missing)'}`,
    `  window:     ${report.phase}`,
    `  cross-signatures: ${report.crossSignatures.verified ? 'verified (both keys)' : 'NOT VERIFIED'}`,
  );
  if (!report.crossSignatures.verified) {
    for (const error of report.crossSignatures.errors) lines.push(`    - ${error}`);
    lines.push(`    payload: ${report.crossSignatures.payload}`);
  }

  if (report.quorum.peers.length > 0) {
    lines.push(
      `  quorum adoption: ${report.quorum.adoptedBy.length}/${report.quorum.peers.length}`,
    );
    for (const peer of report.quorum.peers) {
      lines.push(
        `    ${peer.recognizesReplacement ? 'ok     ' : 'missing'} ${peer.kind} ${peer.name}` +
          (peer.stillTrustsRetired ? '  (still trusts retired key)' : ''),
      );
    }
  }

  if (report.checks.length > 0) {
    lines.push('  findings:');
    for (const check of report.checks) {
      lines.push(`    ${check.severity}  ${check.code}  ${check.message}`);
      if (check.suggestion !== undefined) lines.push(`      fix: ${check.suggestion}`);
    }
  } else {
    lines.push('  No findings: the announcement, attestation and quorum slices agree.');
  }

  if (report.checklist.length > 0) {
    lines.push('  operator checklist:');
    report.checklist.forEach((step, index) => lines.push(`    ${index + 1}. ${step}`));
  }

  lines.push(
    report.ok
      ? '  Result: rotation is coordinated for the current window.'
      : '  Result: do NOT sign with the replacement key until every error above is resolved.',
  );
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const validatorKeyRotationRules: Rule[] = [
  {
    id: KEY_ROTATION_MARKERS_INCOMPLETE,
    category: 'network',
    severity: 'error',
    description:
      'Validator key rotation must announce previous key, replacement key and transition date together',
    run() {},
  },
  {
    id: KEY_ROTATION_KEY_INVALID,
    category: 'network',
    severity: 'error',
    description: 'Validator key rotation markers must be StrKey-encoded Ed25519 account ids',
    run() {},
  },
  {
    id: KEY_ROTATION_SAME_KEY,
    category: 'network',
    severity: 'error',
    description: 'A validator key rotation must replace the retired key with a different key',
    run() {},
  },
  {
    id: KEY_ROTATION_TRANSITION_DATE_INVALID,
    category: 'network',
    severity: 'error',
    description: 'TRANSITION_DATE must be an ISO-8601 timestamp',
    run() {},
  },
  {
    id: KEY_ROTATION_CROSS_SIGNATURE_MISSING,
    category: 'network',
    severity: 'error',
    description:
      'A validator key rotation must be cross-signed by the retiring and replacement keys',
    run() {},
  },
  {
    id: KEY_ROTATION_CROSS_SIGNATURE_INVALID,
    category: 'network',
    severity: 'error',
    description: 'Validator key rotation cross-signatures must verify against the advertised keys',
    run() {},
  },
  {
    id: KEY_ROTATION_QUORUM_NOT_ADOPTED,
    category: 'network',
    severity: 'error',
    description: 'Peer and downstream anchor quorum slices must list the replacement validator key',
    run() {},
  },
  {
    id: KEY_ROTATION_RETIRED_KEY_TRUSTED,
    category: 'network',
    severity: 'warning',
    description: 'Peers should drop the retiring validator key once the transition window closes',
    run() {},
  },
  {
    id: KEY_ROTATION_RETIRED_KEY_ADVERTISED,
    category: 'network',
    severity: 'error',
    description: 'The retiring validator key must not remain advertised after a completed rotation',
    run() {},
  },
  {
    id: KEY_ROTATION_TRANSITION_ACTIVE,
    category: 'network',
    severity: 'info',
    description: 'An open validator key transition window requires operator coordination',
    run() {},
  },
];

export const validatorKeyRotationRuleIds: readonly string[] = validatorKeyRotationRules.map(
  (rule) => rule.id,
);
