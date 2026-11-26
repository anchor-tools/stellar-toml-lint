/**
 * Soroban contract WASM binary size and optimization verifier.
 *
 * The Stellar network caps uncompressed WASM bytecode and limits total
 * transaction size. Binaries that contain debug symbols, unused export stubs,
 * or other development artefacts that survive a production build inflate
 * deployment fees and can push the envelope above the network's hard limits.
 *
 * This module reads WASM section headers without executing any code — the same
 * approach as the budget estimator — and reports:
 *
 * - Total uncompressed and gzip-estimated binary sizes vs. network thresholds.
 * - Custom sections whose names indicate leftover debug info (`name`,
 *   `sourceMappingURL`, `producers`).
 * - Exported function names that are not part of the SEP-41 token interface,
 *   which may indicate dead code or unreachable entry points.
 */

import * as zlib from 'node:zlib';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

export const BINARY_TOO_LARGE_RULE = 'soroban/wasm-binary-too-large';
export const DEBUG_SECTION_PRESENT_RULE = 'soroban/wasm-debug-section-present';
export const DEAD_EXPORT_PRESENT_RULE = 'soroban/wasm-dead-export-present';

/**
 * Stellar network hard limit for an uncompressed WASM contract binary.
 * Corresponds to the `MaxContractSizeBytes` network config parameter.
 */
export const STELLAR_MAX_WASM_BYTES = 65_536;

/**
 * Practical warning threshold (80 % of the hard limit). Binaries approaching
 * the ceiling leave no headroom for future feature additions.
 */
export const WASM_SIZE_WARNING_THRESHOLD = Math.floor(STELLAR_MAX_WASM_BYTES * 0.8);

/** Custom section names that contain debug-only metadata. */
export const DEBUG_SECTION_NAMES = new Set(['name', 'sourceMappingURL', 'producers']);

/**
 * The standard SEP-41 token interface that every production token is expected
 * to export. Any other exported function is considered potentially dead code.
 */
export const SEP41_EXPORTS = new Set([
  'allowance',
  'approve',
  'balance',
  'burn',
  'burn_from',
  'decimals',
  'initialize',
  'name',
  'symbol',
  'total_supply',
  'transfer',
  'transfer_from',
  // Soroban host ABI entry points
  '__data_end',
  '__heap_base',
  'memory',
]);

export interface WasmSizeInfo {
  uncompressedBytes: number;
  estimatedGzipBytes: number;
}

export interface WasmOptimizationReport {
  size: WasmSizeInfo;
  debugSections: string[];
  nonStandardExports: string[];
}

export interface WasmOptimizationOptions {
  rules?: RuleOverrides;
  /** Override the uncompressed size limit (bytes). Defaults to `STELLAR_MAX_WASM_BYTES`. */
  maxUncompressedBytes?: number;
  /** Additional export names to treat as standard (not flagged as dead code). */
  allowedExports?: ReadonlySet<string>;
}

// ---------------------------------------------------------------------------
// Minimal WASM section reader (custom section id = 0)
// ---------------------------------------------------------------------------

class Reader {
  pos: number;
  constructor(
    private readonly bytes: Buffer,
    start = 0,
    private readonly end = bytes.length,
  ) {
    this.pos = start;
  }

  get done(): boolean {
    return this.pos >= this.end;
  }

  byte(): number {
    if (this.pos >= this.end) throw new Error('unexpected end of WASM');
    return this.bytes[this.pos++] as number;
  }

  skip(count: number): void {
    if (count < 0 || this.pos + count > this.end) throw new Error('unexpected end of WASM');
    this.pos += count;
  }

  u32(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = this.byte();
      value |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return value >>> 0;
      shift += 7;
      if (shift > 28) throw new Error('LEB128 overflow');
    }
  }

  utf8(length: number): string {
    const start = this.pos;
    this.skip(length);
    return this.bytes.toString('utf8', start, start + length);
  }
}

const WASM_MAGIC = 0x6d736100; // "\0asm" in little-endian

function assertWasm(bytes: Buffer): void {
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== WASM_MAGIC) {
    throw new Error('not a WASM module');
  }
}

/** Collects custom-section names and exported function names from raw bytes. */
function scanSections(bytes: Buffer): { customNames: string[]; exportNames: string[] } {
  assertWasm(bytes);
  const reader = new Reader(bytes, 8);
  const customNames: string[] = [];
  const exportNames: string[] = [];

  while (!reader.done) {
    const id = reader.byte();
    const size = reader.u32();
    const sectionStart = reader.pos;

    if (id === 0) {
      // Custom section: name string immediately follows the size.
      const nameLen = reader.u32();
      const sectionName = reader.utf8(nameLen);
      customNames.push(sectionName);
    } else if (id === 7) {
      // Export section: count followed by (name, kind, index) triples.
      const count = reader.u32();
      for (let i = 0; i < count; i++) {
        const nameLen = reader.u32();
        const exportName = reader.utf8(nameLen);
        const kind = reader.byte();
        reader.u32(); // index
        if (kind === 0) exportNames.push(exportName); // function exports only
      }
    }

    // Seek past the whole section regardless of whether we parsed it fully.
    reader.pos = sectionStart + size;
  }

  return { customNames, exportNames };
}

function estimateGzipSize(bytes: Buffer): number {
  try {
    return zlib.gzipSync(bytes, { level: 9 }).length;
  } catch {
    return bytes.length; // fallback: treat as uncompressible
  }
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Scans the WASM binary and returns an optimization report, or `undefined`
 * when the buffer is not a valid WASM module.
 */
export function analyzeWasmBinary(bytes: Buffer): WasmOptimizationReport | undefined {
  try {
    const { customNames, exportNames } = scanSections(bytes);
    return {
      size: {
        uncompressedBytes: bytes.length,
        estimatedGzipBytes: estimateGzipSize(bytes),
      },
      debugSections: customNames.filter((n) => DEBUG_SECTION_NAMES.has(n)),
      nonStandardExports: exportNames.filter((n) => !SEP41_EXPORTS.has(n)),
    };
  } catch {
    return undefined;
  }
}

/**
 * Turns a `WasmOptimizationReport` into `Diagnostic`s for a named contract.
 */
export function optimizationDiagnostics(
  contractId: string,
  report: WasmOptimizationReport,
  options: WasmOptimizationOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const maxBytes = options.maxUncompressedBytes ?? STELLAR_MAX_WASM_BYTES;
  const allowed = options.allowedExports ?? SEP41_EXPORTS;

  const sizeSeverity = severityFor(BINARY_TOO_LARGE_RULE, 'error', options.rules);
  if (sizeSeverity !== undefined) {
    const { uncompressedBytes, estimatedGzipBytes } = report.size;
    if (uncompressedBytes > maxBytes) {
      diagnostics.push({
        rule: BINARY_TOO_LARGE_RULE,
        severity: sizeSeverity,
        category: 'network',
        message: `Contract ${contractId} WASM is ${uncompressedBytes} bytes uncompressed, exceeding the ${maxBytes}-byte Stellar network limit`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion:
          'Run `wasm-opt -Oz` to reduce binary size, strip debug sections, and ensure unused imports are removed.',
      });
    } else if (uncompressedBytes > WASM_SIZE_WARNING_THRESHOLD) {
      diagnostics.push({
        rule: BINARY_TOO_LARGE_RULE,
        severity: 'warning',
        category: 'network',
        message: `Contract ${contractId} WASM is ${uncompressedBytes} bytes uncompressed (${Math.round((uncompressedBytes / maxBytes) * 100)}% of the ${maxBytes}-byte limit); estimated gzip: ${estimatedGzipBytes} bytes`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion:
          'Run `wasm-opt -Oz` before deployment to keep headroom for future changes and reduce transaction fees.',
      });
    }
  }

  const debugSeverity = severityFor(DEBUG_SECTION_PRESENT_RULE, 'warning', options.rules);
  if (debugSeverity !== undefined) {
    for (const section of report.debugSections) {
      diagnostics.push({
        rule: DEBUG_SECTION_PRESENT_RULE,
        severity: debugSeverity,
        category: 'network',
        message: `Contract ${contractId} WASM contains a "${section}" debug custom section that should be stripped for production`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion: `Strip the "${section}" section with \`wasm-strip\` or \`wasm-opt --strip-debug\` before deploying.`,
      });
    }
  }

  const deadSeverity = severityFor(DEAD_EXPORT_PRESENT_RULE, 'warning', options.rules);
  if (deadSeverity !== undefined) {
    const nonStandard = report.nonStandardExports.filter((n) => !allowed.has(n));
    for (const exported of nonStandard) {
      diagnostics.push({
        rule: DEAD_EXPORT_PRESENT_RULE,
        severity: deadSeverity,
        category: 'network',
        message: `Contract ${contractId} exports "${exported}", which is not part of the SEP-41 token interface and may be dead code`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion: `Remove the "${exported}" export if it is unreachable, or add it to the allowed-exports list if it is intentional.`,
      });
    }
  }

  return diagnostics;
}

/**
 * Convenience wrapper: analyzes `wasmBytes` and returns diagnostics. Silent
 * when the buffer cannot be parsed as WASM.
 */
export function auditWasmOptimization(
  contractId: string,
  wasmBytes: Buffer,
  options: WasmOptimizationOptions = {},
): Diagnostic[] {
  const report = analyzeWasmBinary(wasmBytes);
  return report === undefined ? [] : optimizationDiagnostics(contractId, report, options);
}

/** Registered so `--list-rules` and rule overrides know these ids. */
export const wasmOptimizationRules: Rule[] = [
  {
    id: BINARY_TOO_LARGE_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract WASM binary exceeds or approaches the Stellar network size limit',
    run() {},
  },
  {
    id: DEBUG_SECTION_PRESENT_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban contract WASM binary contains a debug custom section that inflates binary size',
    run() {},
  },
  {
    id: DEAD_EXPORT_PRESENT_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban contract WASM binary exports a function outside the SEP-41 token interface',
    run() {},
  },
];
