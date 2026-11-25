import { describe, expect, it } from 'vitest';
import {
  BINARY_TOO_LARGE_RULE,
  DEBUG_SECTION_PRESENT_RULE,
  DEAD_EXPORT_PRESENT_RULE,
  STELLAR_MAX_WASM_BYTES,
  WASM_SIZE_WARNING_THRESHOLD,
  analyzeWasmBinary,
  auditWasmOptimization,
  optimizationDiagnostics,
  wasmOptimizationRules,
} from '../src/soroban/wasmOptimizationVerifier.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';

// ---------------------------------------------------------------------------
// Minimal WASM builder (mirrors the pattern in soroban-budget-estimator.test.ts)
// ---------------------------------------------------------------------------

function u32leb(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return Buffer.from(bytes);
}

function wasmName(text: string): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  return Buffer.concat([u32leb(bytes.length), bytes]);
}

function vec(items: Buffer[]): Buffer {
  return Buffer.concat([u32leb(items.length), ...items]);
}

function wasmSection(id: number, payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from([id]), u32leb(payload.length), payload]);
}

function customSection(sectionName: string, data: Buffer = Buffer.alloc(0)): Buffer {
  const payload = Buffer.concat([wasmName(sectionName), data]);
  return wasmSection(0, payload);
}

function exportSection(exports: Array<{ name: string; kind?: number; index?: number }>): Buffer {
  const entries = exports.map(({ name, kind = 0, index = 0 }) =>
    Buffer.concat([wasmName(name), Buffer.from([kind]), u32leb(index)]),
  );
  return wasmSection(7, vec(entries));
}

const WASM_HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function minimalWasm(extra: Buffer[] = []): Buffer {
  return Buffer.concat([WASM_HEADER, ...extra]);
}

function wasmWithExports(names: string[]): Buffer {
  return minimalWasm([exportSection(names.map((name) => ({ name })))]);
}

function wasmWithCustomSections(sections: string[]): Buffer {
  return minimalWasm(sections.map((s) => customSection(s)));
}

function largePadding(bytes: number): Buffer {
  // Use a custom section to pad the binary to the requested size.
  const data = Buffer.alloc(bytes);
  return customSection('padding', data);
}

// ---------------------------------------------------------------------------

describe('analyzeWasmBinary', () => {
  it('returns undefined for non-WASM bytes', () => {
    expect(analyzeWasmBinary(Buffer.from('not wasm'))).toBeUndefined();
    expect(analyzeWasmBinary(Buffer.alloc(4))).toBeUndefined();
  });

  it('reports zero debug sections and no non-standard exports for a bare module', () => {
    const report = analyzeWasmBinary(minimalWasm());
    expect(report?.debugSections).toHaveLength(0);
    expect(report?.nonStandardExports).toHaveLength(0);
  });

  it('detects a "name" debug custom section', () => {
    const report = analyzeWasmBinary(wasmWithCustomSections(['name']));
    expect(report?.debugSections).toContain('name');
  });

  it('detects a "sourceMappingURL" debug custom section', () => {
    const report = analyzeWasmBinary(wasmWithCustomSections(['sourceMappingURL']));
    expect(report?.debugSections).toContain('sourceMappingURL');
  });

  it('detects a "producers" debug custom section', () => {
    const report = analyzeWasmBinary(wasmWithCustomSections(['producers']));
    expect(report?.debugSections).toContain('producers');
  });

  it('ignores non-debug custom sections', () => {
    const report = analyzeWasmBinary(wasmWithCustomSections(['custom-metadata']));
    expect(report?.debugSections).toHaveLength(0);
  });

  it('reports standard SEP-41 exports as non-standard: false', () => {
    const report = analyzeWasmBinary(wasmWithExports(['transfer', 'balance', 'decimals']));
    expect(report?.nonStandardExports).toHaveLength(0);
  });

  it('reports non-standard function exports', () => {
    const report = analyzeWasmBinary(wasmWithExports(['transfer', '__internal_hook']));
    expect(report?.nonStandardExports).toContain('__internal_hook');
    expect(report?.nonStandardExports).not.toContain('transfer');
  });

  it('reports binary size information', () => {
    // Use a larger module with compressible padding so gzip is smaller.
    const wasm = minimalWasm([largePadding(512)]);
    const report = analyzeWasmBinary(wasm);
    expect(report?.size.uncompressedBytes).toBe(wasm.length);
    expect(report?.size.estimatedGzipBytes).toBeGreaterThan(0);
    expect(report?.size.estimatedGzipBytes).toBeLessThan(wasm.length);
  });
});

describe('optimizationDiagnostics', () => {
  it('passes a clean, small module', () => {
    const report = analyzeWasmBinary(minimalWasm())!;
    expect(optimizationDiagnostics(CONTRACT, report)).toHaveLength(0);
  });

  it('errors when binary exceeds the Stellar max size', () => {
    const oversized = minimalWasm([largePadding(STELLAR_MAX_WASM_BYTES)]);
    const report = analyzeWasmBinary(oversized)!;
    const diagnostics = optimizationDiagnostics(CONTRACT, report);
    expect(diagnostics.map((d) => d.rule)).toContain(BINARY_TOO_LARGE_RULE);
    expect(diagnostics.find((d) => d.rule === BINARY_TOO_LARGE_RULE)?.severity).toBe('error');
  });

  it('warns when binary exceeds the warning threshold but not the hard limit', () => {
    const bytes = WASM_SIZE_WARNING_THRESHOLD + 100;
    const oversized = minimalWasm([largePadding(bytes)]);
    const report = analyzeWasmBinary(oversized)!;
    const diagnostics = optimizationDiagnostics(CONTRACT, report);
    const sizeDiag = diagnostics.find((d) => d.rule === BINARY_TOO_LARGE_RULE);
    expect(sizeDiag?.severity).toBe('warning');
  });

  it('warns for each debug custom section found', () => {
    const wasm = wasmWithCustomSections(['name', 'producers']);
    const report = analyzeWasmBinary(wasm)!;
    const diags = optimizationDiagnostics(CONTRACT, report).filter(
      (d) => d.rule === DEBUG_SECTION_PRESENT_RULE,
    );
    expect(diags).toHaveLength(2);
    expect(diags.map((d) => d.message)).toContainEqual(expect.stringContaining('"name"'));
    expect(diags.map((d) => d.message)).toContainEqual(expect.stringContaining('"producers"'));
  });

  it('warns for non-standard exports', () => {
    const wasm = wasmWithExports(['transfer', 'internal_debug_fn']);
    const report = analyzeWasmBinary(wasm)!;
    const diags = optimizationDiagnostics(CONTRACT, report).filter(
      (d) => d.rule === DEAD_EXPORT_PRESENT_RULE,
    );
    expect(diags).toHaveLength(1);
    expect(diags[0]?.message).toContain('"internal_debug_fn"');
  });

  it('suppresses diagnostics for turned-off rules', () => {
    const wasm = wasmWithCustomSections(['name']);
    const report = analyzeWasmBinary(wasm)!;
    const diags = optimizationDiagnostics(CONTRACT, report, {
      rules: { [DEBUG_SECTION_PRESENT_RULE]: 'off' },
    });
    expect(diags.filter((d) => d.rule === DEBUG_SECTION_PRESENT_RULE)).toHaveLength(0);
  });

  it('escalates binary size diagnostic to error via rule override', () => {
    const oversized = minimalWasm([largePadding(STELLAR_MAX_WASM_BYTES)]);
    const report = analyzeWasmBinary(oversized)!;
    const diags = optimizationDiagnostics(CONTRACT, report, {
      rules: { [BINARY_TOO_LARGE_RULE]: 'error' },
    });
    expect(diags[0]?.severity).toBe('error');
  });

  it('allows extra exports via allowedExports option', () => {
    const wasm = wasmWithExports(['transfer', 'my_custom_fn']);
    const report = analyzeWasmBinary(wasm)!;
    const diags = optimizationDiagnostics(CONTRACT, report, {
      allowedExports: new Set(['my_custom_fn']),
    });
    expect(diags.filter((d) => d.rule === DEAD_EXPORT_PRESENT_RULE)).toHaveLength(0);
  });

  it('honours custom maxUncompressedBytes threshold', () => {
    const tiny = minimalWasm([largePadding(100)]);
    const report = analyzeWasmBinary(tiny)!;
    const diags = optimizationDiagnostics(CONTRACT, report, { maxUncompressedBytes: 50 });
    expect(diags.map((d) => d.rule)).toContain(BINARY_TOO_LARGE_RULE);
  });
});

describe('auditWasmOptimization', () => {
  it('returns empty diagnostics for non-WASM bytes', () => {
    expect(auditWasmOptimization(CONTRACT, Buffer.from('not wasm'))).toHaveLength(0);
  });

  it('returns diagnostics for a WASM with debug sections', () => {
    const wasm = wasmWithCustomSections(['name']);
    const diags = auditWasmOptimization(CONTRACT, wasm);
    expect(diags.map((d) => d.rule)).toContain(DEBUG_SECTION_PRESENT_RULE);
  });
});

describe('wasmOptimizationRules', () => {
  it('registers all three rule ids', () => {
    const ids = wasmOptimizationRules.map((r) => r.id);
    expect(ids).toContain(BINARY_TOO_LARGE_RULE);
    expect(ids).toContain(DEBUG_SECTION_PRESENT_RULE);
    expect(ids).toContain(DEAD_EXPORT_PRESENT_RULE);
  });
});
