import { describe, expect, it } from 'vitest';
import {
  SIMD_PROBE_MODULE,
  auditWasmBinary,
  detectSimdSupport,
  renderSimdReport,
  scanWasmBinary,
} from '../../src/wasm/simdAuditor.js';

function leb(value: number): number[] {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return bytes;
}

function section(id: number, payload: number[]): number[] {
  return [id, ...leb(payload.length), ...payload];
}

interface ModuleOptions {
  simd?: boolean;
  memory?: boolean;
  maxPages?: number;
  grow?: boolean;
}

function buildModule(options: ModuleOptions = {}): Uint8Array {
  const body: number[] = [0x00]; // no locals
  if (options.simd === true) body.push(0xfd, 0x0c, ...new Array<number>(16).fill(0), 0x1a);
  if (options.grow === true) body.push(0x41, 0x01, 0x40, 0x00, 0x1a);
  body.push(0x0b);

  const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  bytes.push(...section(1, [0x01, 0x60, 0x00, 0x00]));
  bytes.push(...section(3, [0x01, 0x00]));
  if (options.memory === true) {
    const payload = [0x01, options.maxPages === undefined ? 0x00 : 0x01, 0x01];
    if (options.maxPages !== undefined) payload.push(options.maxPages);
    bytes.push(...section(5, payload));
  }
  bytes.push(...section(10, [0x01, ...leb(body.length), ...body]));
  return Uint8Array.from(bytes);
}

describe('scanWasmBinary', () => {
  it('walks function bodies and reports memory instructions', () => {
    const scan = scanWasmBinary(buildModule({ memory: true, maxPages: 4, grow: true }));
    expect(scan.functionBodies).toBe(1);
    expect(scan.memories).toEqual([{ minPages: 1, maxPages: 4, shared: false }]);
    expect(scan.growOps).toBe(1);
    expect(scan.simdOpcodes).toEqual([]);
  });

  it('finds 0xFD SIMD opcodes', () => {
    const scan = scanWasmBinary(buildModule({ simd: true }));
    expect(scan.simdOpcodes).toEqual([{ opcode: 0x0c, count: 1 }]);
  });

  it('rejects non-WASM and truncated binaries', () => {
    expect(() => scanWasmBinary(Uint8Array.from([1, 2, 3]))).toThrow();
    expect(() =>
      scanWasmBinary(Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10])),
    ).toThrow(/ends inside/);
  });
});

describe('auditWasmBinary', () => {
  it('passes a plain MVP module', () => {
    const report = auditWasmBinary(buildModule(), { runtime: { validate: () => true } });
    expect(report.valid).toBe(true);
    expect(report.simd).toBe(false);
    expect(report.dualBuildRecommended).toBe(false);
    expect(report.findings).toEqual([]);
  });

  it('reports SIMD instructions and recommends a dual build', () => {
    const report = auditWasmBinary(buildModule({ simd: true }), {
      file: 'linter.wasm',
      runtime: { validate: () => true },
    });
    expect(report.simd).toBe(true);
    expect(report.simdOpCount).toBe(1);
    expect(report.instructions[0]).toMatchObject({ name: 'v128.const', count: 1 });
    expect(report.dualBuildRecommended).toBe(true);
    expect(report.findings.map((finding) => finding.code)).toContain('simd/instructions-detected');
    expect(report.findings.some((finding) => finding.code === 'simd/unsupported-runtime')).toBe(
      false,
    );
    const rendered = renderSimdReport(report);
    expect(rendered).toContain('SIMD');
    expect(rendered).toContain('dual build recommended: yes');
    expect(rendered).toContain('target-feature');
  });

  it('errors when the runtime cannot validate SIMD', () => {
    const report = auditWasmBinary(buildModule({ simd: true }), {
      runtime: { validate: () => false },
    });
    expect(report.runtimeSupportsSimd).toBe(false);
    expect(report.findings.map((finding) => finding.code)).toContain('simd/unsupported-runtime');
    expect(
      report.findings.find((finding) => finding.code === 'simd/unsupported-runtime')?.severity,
    ).toBe('error');
  });

  it('audits memory page limits', () => {
    const bounded = auditWasmBinary(buildModule({ memory: true, maxPages: 10 }), {
      runtime: { validate: () => true },
    });
    expect(bounded.memory).toMatchObject({
      memories: 1,
      initialPages: 1,
      maximumPages: 10,
      initialBytes: 65_536,
      maximumBytes: 655_360,
      bounded: true,
    });
  });

  it('warns about memory.grow without a maximum', () => {
    const report = auditWasmBinary(buildModule({ memory: true, grow: true }), {
      runtime: { validate: () => true },
    });
    expect(report.memory.growOps).toBe(1);
    expect(report.memory.bounded).toBe(false);
    expect(report.findings.map((finding) => finding.code)).toContain('memory/unbounded-growth');

    const capped = auditWasmBinary(buildModule({ memory: true, maxPages: 4, grow: true }), {
      runtime: { validate: () => true },
    });
    expect(capped.findings.map((finding) => finding.code)).not.toContain('memory/unbounded-growth');
  });

  it('reports an unparseable binary instead of throwing', () => {
    const report = auditWasmBinary(Uint8Array.from([0, 1, 2, 3]), { file: 'bad.wasm' });
    expect(report.valid).toBe(false);
    expect(report.findings[0]?.code).toBe('wasm/invalid-binary');
    expect(renderSimdReport(report)).toContain('not a valid WebAssembly binary');
  });
});

describe('SIMD runtime detection', () => {
  it('uses WebAssembly.validate on the probe module', () => {
    expect(detectSimdSupport({ validate: (bytes) => bytes === SIMD_PROBE_MODULE })).toBe(true);
    expect(detectSimdSupport({ validate: () => false })).toBe(false);
    expect(detectSimdSupport({})).toBe(false);
  });

  it('validates the probe module in the real runtime when available', () => {
    const supported = detectSimdSupport();
    expect(typeof supported).toBe('boolean');
  });
});
