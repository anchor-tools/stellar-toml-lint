/**
 * Static replay-resistance audit for Soroban contracts that verify signatures.
 *
 * A contract that calls `ed25519_verify` or `secp256k1_verify` without binding
 * the signed message to a consumed nonce, the Stellar network and the contract's
 * own address, and an expiration ledger, accepts the same signature twice. The
 * auditor parses the WASM import/name/code sections and inspects every function
 * that reaches a crypto verification host function for those four signals.
 *
 * This is a static heuristic: it proves the presence of the checks in the
 * compiled code, not that they are correct. The report says which signals were
 * found so a reviewer can confirm the wiring.
 */

import type { Rule } from '../types.js';
import {
  WasmModuleError,
  importedFunction,
  parseWasmModule,
  type WasmModule,
} from './wasmModule.js';

export const SIGNATURE_WITHOUT_NONCE_RULE = 'soroban/signature-verification-without-nonce';
export const SIGNATURE_WITHOUT_DOMAIN_RULE =
  'soroban/signature-verification-without-domain-separation';
export const SIGNATURE_WITHOUT_EXPIRATION_RULE =
  'soroban/signature-verification-without-expiration';

export type SignatureReplayCode =
  | 'soroban/wasm-invalid-binary'
  | typeof SIGNATURE_WITHOUT_NONCE_RULE
  | typeof SIGNATURE_WITHOUT_DOMAIN_RULE
  | typeof SIGNATURE_WITHOUT_EXPIRATION_RULE;

export interface SignatureReplayFinding {
  code: SignatureReplayCode;
  severity: 'error' | 'warning';
  message: string;
  suggestion: string;
  function?: string;
  offset?: number;
}

/** The checks found around one signature-verification routine. */
export interface SignatureVerificationRoutine {
  function: string;
  index: number;
  offset: number;
  /** Host crypto functions the routine calls. */
  verifiers: string[];
  /** True when a nonce is read from and written back to contract state. */
  consumesNonce: boolean;
  /** True when the message is separated by both network and contract domain. */
  domainSeparated: boolean;
  /** True when a ledger sequence/expiration is consulted. */
  checksExpiration: boolean;
  notes: string[];
}

export interface SignatureReplayReport {
  file?: string;
  valid: boolean;
  sizeBytes: number;
  error?: string;
  /** Crypto verification host functions the module imports. */
  cryptoImports: string[];
  routines: SignatureVerificationRoutine[];
  findings: SignatureReplayFinding[];
}

export interface SignatureReplayOptions {
  file?: string;
}

/** Host functions that verify a signature. */
export const CRYPTO_VERIFIERS = new Set([
  'ed25519_verify',
  'ed25519_recover',
  'secp256k1_verify',
  'secp256k1_recover',
]);

const NONCE_READS = new Set([
  'get_contract_data',
  'has_contract_data',
  'get_contract_data_for_contract',
  'get_ledger_entry',
  'has_ledger_entry',
]);

const NONCE_WRITES = new Set([
  'put_contract_data',
  'put_contract_data_for_contract',
  'put_ledger_entry',
  'del_contract_data',
]);

const NETWORK_SIGNALS = new Set([
  'get_network_id',
  'get_ledger_network_id',
  'get_stellar_network_id',
  'network_id',
]);

const CONTRACT_SIGNALS = new Set([
  'get_current_contract_address',
  'get_current_contract_id',
  'get_contract_id',
  'get_contract_address',
]);

const EXPIRATION_SIGNALS = new Set([
  'get_ledger_sequence',
  'get_ledger_timestamp',
  'get_ledger_version',
]);

const NONCE_STRINGS = ['nonce', 'replay', 'counter', 'sequence number'];
const NETWORK_STRINGS = ['network', 'passphrase', 'network id', 'networkid'];
const CONTRACT_STRINGS = ['contract address', 'contract id', 'contractid', 'this contract'];
const EXPIRATION_STRINGS = ['expiration', 'expires', 'expiry', 'deadline', 'valid until'];

/** Audits a module for signature replay hazards. */
export function auditSignatureReplay(
  bytes: Uint8Array,
  options: SignatureReplayOptions = {},
): SignatureReplayReport {
  const base = { ...(options.file !== undefined ? { file: options.file } : {}) };
  let module: WasmModule;
  try {
    module = parseWasmModule(bytes);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ...base,
      valid: false,
      sizeBytes: bytes.byteLength,
      error: message,
      cryptoImports: [],
      routines: [],
      findings: [
        {
          code: 'soroban/wasm-invalid-binary',
          severity: 'error',
          message: `The contract binary cannot be parsed: ${message}`,
          suggestion:
            'Rebuild the contract with a current Soroban SDK and audit the deployed bytes.',
          ...(error instanceof WasmModuleError ? { offset: error.offset } : {}),
        },
      ],
    };
  }

  const cryptoImports = module.imports
    .filter((entry) => entry.kind === 'function' && CRYPTO_VERIFIERS.has(entry.field))
    .map((entry) => entry.field);
  const strings = module.strings.map((text) => text.toLowerCase());
  const reports: SignatureVerificationRoutine[] = [];

  for (const fn of module.functions) {
    const callNames = fn.calls
      .map((call) => importedFunction(module, call.target)?.field)
      .filter((name): name is string => name !== undefined);
    const verifiers = callNames.filter((name) => CRYPTO_VERIFIERS.has(name));
    if (verifiers.length === 0) continue;

    const notes: string[] = [];
    const readsNonce = callNames.some((name) => NONCE_READS.has(name));
    const writesNonce = callNames.some((name) => NONCE_WRITES.has(name));
    const nonceString = hasString(strings, NONCE_STRINGS);
    const consumesNonce = readsNonce && writesNonce;
    if (readsNonce && !writesNonce) {
      notes.push('reads contract state but never writes the nonce back');
    } else if (writesNonce && !readsNonce) {
      notes.push('writes contract state but never checks the stored nonce first');
    } else if (!consumesNonce) {
      notes.push(
        nonceString ? 'mentions a nonce but never reads/writes state' : 'no nonce state access',
      );
    } else {
      notes.push('nonce read and consumed in contract state');
    }

    const networkSignal =
      callNames.some((name) => NETWORK_SIGNALS.has(name)) || hasString(strings, NETWORK_STRINGS);
    const contractSignal =
      callNames.some((name) => CONTRACT_SIGNALS.has(name)) || hasString(strings, CONTRACT_STRINGS);
    const domainSeparated = networkSignal && contractSignal;
    if (!networkSignal) notes.push('no Stellar network identifier in the signed message');
    if (!contractSignal) notes.push('no contract-address identifier in the signed message');

    const checksExpiration =
      callNames.some((name) => EXPIRATION_SIGNALS.has(name)) ||
      hasString(strings, EXPIRATION_STRINGS);
    if (!checksExpiration) notes.push('no ledger sequence or expiration bound');

    const firstCryptoCall = fn.calls.find((call) => {
      const name = importedFunction(module, call.target)?.field;
      return name !== undefined && CRYPTO_VERIFIERS.has(name);
    });

    reports.push({
      function: fn.name,
      index: fn.index,
      offset: firstCryptoCall?.offset ?? 0,
      verifiers,
      consumesNonce,
      domainSeparated,
      checksExpiration,
      notes,
    });
  }

  const findings: SignatureReplayFinding[] = [];
  for (const routine of reports) {
    const where = `[${routine.function} @ ${routine.offset}]`;
    if (!routine.consumesNonce) {
      findings.push({
        code: SIGNATURE_WITHOUT_NONCE_RULE,
        severity: 'error',
        message: `${routine.function} verifies a signature via ${routine.verifiers.join(', ')} but does not consume a nonce from contract state, so the same signature can be replayed ${where}`,
        suggestion:
          'Store a per-signer nonce in contract data, require it in the signed payload, and delete or increment it before external effects.',
        function: routine.function,
        offset: routine.offset,
      });
    }
    if (!routine.domainSeparated) {
      findings.push({
        code: SIGNATURE_WITHOUT_DOMAIN_RULE,
        severity: 'error',
        message: `${routine.function} verifies a signature without binding it to both the Stellar network and this contract's address, so it can be replayed on another network or contract ${where}`,
        suggestion:
          'Hash the network id and the current contract address into the signed message before verifying it.',
        function: routine.function,
        offset: routine.offset,
      });
    }
    if (!routine.checksExpiration) {
      findings.push({
        code: SIGNATURE_WITHOUT_EXPIRATION_RULE,
        severity: 'warning',
        message: `${routine.function} verifies a signature with no ledger-sequence or expiration check, so a leaked signature stays valid indefinitely ${where}`,
        suggestion:
          'Include an expiration ledger in the signed payload and reject it when the current ledger sequence is past it.',
        function: routine.function,
        offset: routine.offset,
      });
    }
  }

  return {
    ...base,
    valid: true,
    sizeBytes: bytes.byteLength,
    cryptoImports: [...new Set(cryptoImports)],
    routines: reports,
    findings,
  };
}

/** Renders a signature audit as a human-readable report. */
export function renderSignatureReplayReport(report: SignatureReplayReport): string {
  const lines: string[] = [];
  const label = report.file === undefined ? 'contract' : report.file;
  lines.push(`Signature replay audit: ${label}`);
  lines.push(`  Binary: ${report.valid ? 'valid' : 'INVALID'} (${report.sizeBytes} bytes)`);
  if (report.error !== undefined) lines.push(`  Error: ${report.error}`);
  if (report.valid) {
    if (report.cryptoImports.length === 0) {
      lines.push('  Crypto verification imports: none');
    } else {
      lines.push(`  Crypto verification imports: ${report.cryptoImports.join(', ')}`);
      lines.push(`  Verification routines: ${report.routines.length}`);
      for (const routine of report.routines) {
        lines.push(
          `    ${routine.function} @ ${routine.offset}: ` +
            `${routine.verifiers.join(', ')} | nonce ${yesNo(routine.consumesNonce)} | ` +
            `domain ${yesNo(routine.domainSeparated)} | expiration ${yesNo(routine.checksExpiration)}`,
        );
        for (const note of routine.notes) lines.push(`      - ${note}`);
      }
    }
  }

  if (report.findings.length === 0) {
    lines.push('  No signature replay hazards found.');
    return `${lines.join('\n')}\n`;
  }

  lines.push(`  Findings (${report.findings.length}):`);
  for (const finding of report.findings) {
    const where =
      finding.function !== undefined
        ? ` [${finding.function}${finding.offset !== undefined ? ` @ ${finding.offset}` : ''}]`
        : '';
    lines.push(`    ${finding.severity.toUpperCase()} ${finding.code}${where}`);
    lines.push(`      ${finding.message}`);
    lines.push(`      Fix: ${finding.suggestion}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Rule ids the signature auditor can emit. */
export const signatureReplayRuleIds = [
  'soroban/wasm-invalid-binary',
  SIGNATURE_WITHOUT_NONCE_RULE,
  SIGNATURE_WITHOUT_DOMAIN_RULE,
  SIGNATURE_WITHOUT_EXPIRATION_RULE,
] as const;

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const signatureReplayRules: Rule[] = [
  {
    id: SIGNATURE_WITHOUT_NONCE_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract verifies a signature without consuming a nonce, allowing signature replay',
    run() {},
  },
  {
    id: SIGNATURE_WITHOUT_DOMAIN_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract verifies a signature without network and contract-address domain separation',
    run() {},
  },
  {
    id: SIGNATURE_WITHOUT_EXPIRATION_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract verifies a signature without an expiration ledger bound',
    run() {},
  },
];

/** Object wrapper around `auditSignatureReplay`. */
export class SignatureReplayAuditor {
  constructor(private readonly options: SignatureReplayOptions = {}) {}

  audit(bytes: Uint8Array): SignatureReplayReport {
    return auditSignatureReplay(bytes, this.options);
  }
}

function hasString(strings: string[], needles: string[]): boolean {
  return strings.some((text) => needles.some((needle) => text.includes(needle)));
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'NO';
}
