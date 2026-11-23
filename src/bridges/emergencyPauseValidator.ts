/**
 * Cross-chain bridge emergency pause validator.
 *
 * Runs under opt-in `--audit-emergency-pause`; fully offline.
 *
 * Bridges are declared as `[[BRIDGES]]` tables:
 *
 *   NAME, CHAIN ("soroban" | "evm" | "solana"), CONTRACT
 *   METHODS                      exported interface, e.g. ["pause", "unpause"]
 *   PAUSE_AUTHORITY_TYPE         "multisig" | "circuit_breaker" | "single_key"
 *   PAUSE_AUTHORITY, PAUSE_THRESHOLD, PAUSE_SIGNERS
 *   UNPAUSE_AUTHORITY, UNPAUSE_TIMELOCK_SECONDS
 *
 * A bridge that cannot be frozen during an exploit cannot protect its funds,
 * and a pause key held by one person is itself an attack surface. Pause and
 * unpause authority should be separate (least privilege), and unpausing
 * should sit behind a timelock.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isEmail } from '../predicates.js';
import { createReporter, isRecord } from '../protocols/verifierSupport.js';
import { bridgesOf, isValidBridgeContract } from './bridgeSupport.js';

const INVALID_RULE = 'bridgepause/invalid-bridge';
const NO_PAUSE_RULE = 'bridgepause/missing-pause-method';
const NO_UNPAUSE_RULE = 'bridgepause/missing-unpause-method';
const AUTHORITY_RULE = 'bridgepause/unrestricted-pause-authority';
const SHARED_RULE = 'bridgepause/shared-pause-unpause-authority';
const TIMELOCK_RULE = 'bridgepause/missing-unpause-timelock';
const CONTACT_RULE = 'bridgepause/missing-security-contact';
const HOURS_RULE = 'bridgepause/contact-not-24x7';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';

export const PAUSE_METHODS: readonly string[] = [
  'pause',
  'emergency_stop',
  'emergencyStop',
  'pause_all',
  'set_paused',
];
export const UNPAUSE_METHODS: readonly string[] = ['unpause', 'resume', 'emergency_resume'];
const AUTOMATED = ['circuit_breaker', 'circuit_breaker_bot'];
const MIN_TIMELOCK_SECONDS = 3600;

export interface EmergencyPauseOptions {
  rules?: RuleOverrides;
}

export interface EmergencyPauseResult {
  diagnostics: Diagnostic[];
  /** Bridge name -> pause readiness. */
  bridges: Record<string, { pausable: boolean; restricted: boolean }>;
}

export class BridgeEmergencyPauseValidator {
  constructor(private readonly options: EmergencyPauseOptions = {}) {}

  validate(doc: Record<string, unknown>): EmergencyPauseResult {
    const diagnostics: Diagnostic[] = [];
    const bridges: EmergencyPauseResult['bridges'] = {};
    const push = createReporter(diagnostics, this.options.rules, SPEC, 'policy');
    const list = bridgesOf(doc);
    if (list.length === 0) return { diagnostics, bridges };

    for (const bridge of list) {
      const at = `BRIDGES[${bridge.index}]`;
      const name = bridge.name;
      if (!bridge.chain || !isValidBridgeContract(bridge.chain, bridge.contract)) {
        push(
          INVALID_RULE,
          'error',
          `${name}: CHAIN must be soroban, evm or solana and CONTRACT a valid address for it`,
          `${at}.CONTRACT`,
          'Declare the chain and the deployed bridge contract address.',
        );
      }
      const methods = Array.isArray(bridge.raw.METHODS)
        ? bridge.raw.METHODS.filter((m): m is string => typeof m === 'string')
        : [];
      const pausable = methods.some((m) => PAUSE_METHODS.includes(m));
      if (!pausable) {
        push(
          NO_PAUSE_RULE,
          'error',
          `${name}: no emergency pause method exported (expected one of ${PAUSE_METHODS.join(', ')})`,
          `${at}.METHODS`,
          'Export pause()/emergency_stop() so funds can be frozen during an exploit.',
        );
      } else if (!methods.some((m) => UNPAUSE_METHODS.includes(m))) {
        push(
          NO_UNPAUSE_RULE,
          'warning',
          `${name}: pause is exported but there is no unpause method`,
          `${at}.METHODS`,
          'Export unpause() so a false alarm does not freeze the bridge forever.',
        );
      }

      const type =
        typeof bridge.raw.PAUSE_AUTHORITY_TYPE === 'string' ? bridge.raw.PAUSE_AUTHORITY_TYPE : '';
      const threshold = bridge.raw.PAUSE_THRESHOLD;
      const signers = bridge.raw.PAUSE_SIGNERS;
      const multisigOk =
        type === 'multisig' &&
        Number.isInteger(threshold) &&
        Number.isInteger(signers) &&
        (threshold as number) >= 2 &&
        (threshold as number) <= (signers as number);
      const restricted = multisigOk || AUTOMATED.includes(type);
      if (!restricted) {
        push(
          AUTHORITY_RULE,
          'error',
          `${name}: pause authority must be a security council multisig (threshold >= 2) or a circuit breaker bot`,
          `${at}.PAUSE_AUTHORITY_TYPE`,
          'Set PAUSE_AUTHORITY_TYPE = "multisig" with PAUSE_THRESHOLD >= 2 and PAUSE_SIGNERS, or "circuit_breaker".',
        );
      }
      const pauseAuth = bridge.raw.PAUSE_AUTHORITY;
      const unpauseAuth = bridge.raw.UNPAUSE_AUTHORITY;
      if (typeof pauseAuth === 'string' && pauseAuth !== '' && pauseAuth === unpauseAuth) {
        push(
          SHARED_RULE,
          'warning',
          `${name}: the same authority can both pause and unpause`,
          `${at}.UNPAUSE_AUTHORITY`,
          'Separate duties: let a fast guardian pause, and a slower governance body unpause.',
        );
      }
      const lock = bridge.raw.UNPAUSE_TIMELOCK_SECONDS;
      if (
        pausable &&
        !(typeof lock === 'number' && Number.isInteger(lock) && lock >= MIN_TIMELOCK_SECONDS)
      ) {
        push(
          TIMELOCK_RULE,
          'warning',
          `${name}: unpausing is not behind a timelock of at least ${MIN_TIMELOCK_SECONDS} seconds`,
          `${at}.UNPAUSE_TIMELOCK_SECONDS`,
          'Timelock unpausing so a compromised key cannot instantly reopen a bridge under attack.',
        );
      }
      bridges[name] = { pausable, restricted };
    }

    const docs = isRecord(doc.DOCUMENTATION) ? doc.DOCUMENTATION : {};
    const contact =
      doc.SECURITY_CONTACT ??
      docs.SECURITY_CONTACT ??
      doc.ORG_OFFICIAL_EMAIL ??
      docs.ORG_OFFICIAL_EMAIL;
    const contactOk =
      typeof contact === 'string' && (isEmail(contact) || /^https:\/\//.test(contact));
    if (!contactOk) {
      push(
        CONTACT_RULE,
        'error',
        'No valid SECURITY_CONTACT or ORG_OFFICIAL_EMAIL for bridge incidents',
        'SECURITY_CONTACT',
        'Publish a monitored security contact so exploits can be reported immediately.',
      );
    } else {
      const hours = doc.SECURITY_CONTACT_HOURS ?? docs.SECURITY_CONTACT_HOURS;
      if (typeof hours !== 'string' || !/^24\s*[/x]\s*7$/i.test(hours.trim())) {
        push(
          HOURS_RULE,
          'warning',
          'The security contact is not declared as staffed 24/7',
          'SECURITY_CONTACT_HOURS',
          'Set SECURITY_CONTACT_HOURS = "24/7" once the contact is monitored around the clock.',
        );
      }
    }
    return { diagnostics, bridges };
  }
}

export function auditEmergencyPause(
  doc: Record<string, unknown>,
  options: EmergencyPauseOptions = {},
): EmergencyPauseResult {
  return new BridgeEmergencyPauseValidator(options).validate(doc);
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'policy',
  severity: 'warning',
  description,
  run() {},
});

export const emergencyPauseRules: Rule[] = [
  def(INVALID_RULE, 'Bridges must declare a known chain and a valid contract address'),
  def(NO_PAUSE_RULE, 'Bridge contracts must export an emergency pause method'),
  def(NO_UNPAUSE_RULE, 'Bridge contracts should export an unpause method'),
  def(AUTHORITY_RULE, 'Pause authority must be a multisig council or circuit breaker bot'),
  def(SHARED_RULE, 'Pause and unpause authority should be separate'),
  def(TIMELOCK_RULE, 'Unpausing should be protected by a timelock'),
  def(CONTACT_RULE, 'Anchors with bridges must publish a security contact'),
  def(HOURS_RULE, 'The bridge security contact should be staffed 24/7'),
];

export const emergencyPauseRuleIds: readonly string[] = emergencyPauseRules.map((r) => r.id);
