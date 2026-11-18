import { describe, expect, it } from 'vitest';
import { WasiSandboxRunner } from '../src/wasm/wasiRunner.js';
import { WasiSandboxError } from '../src/wasm/errors.js';
import { FUEL_EXPORT_NAME, injectFuelMeter } from '../src/wasm/fuelMeter.js';
import { isWasmGlobal, wasmRuntime } from '../src/wasm/wasmApi.js';
import {
  I32,
  I64,
  OP,
  WASI_IO_TYPE,
  buildWasm,
  call,
  callDropped,
  funcType,
  i32Const,
  i64Const,
} from './fixtures/wasm-build.js';

const STRING_TYPE = funcType([], []);

/** Calls fd_write(1, 0, 1, 8) with an iovec in data that points at "hi\n". */
function helloModule(): Uint8Array {
  return buildWasm({
    types: [WASI_IO_TYPE, STRING_TYPE],
    imports: [{ module: 'wasi_snapshot_preview1', name: 'fd_write', type: 0 }],
    memoryPages: 1,
    data: [
      { offset: 0, bytes: [16, 0, 0, 0, 3, 0, 0, 0] },
      { offset: 16, bytes: 'hi\n' },
    ],
    functions: [
      {
        type: 1,
        code: callDropped(0, [i32Const(1), i32Const(0), i32Const(1), i32Const(8)]),
      },
    ],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: '_start', kind: 0x00, index: 1 },
    ],
  });
}

/** Reads a virtual file into offset 64, then echoes those bytes to stdout. */
function readThenWriteModule(): Uint8Array {
  return buildWasm({
    types: [WASI_IO_TYPE, STRING_TYPE],
    imports: [
      { module: 'wasi_snapshot_preview1', name: 'fd_read', type: 0 },
      { module: 'wasi_snapshot_preview1', name: 'fd_write', type: 0 },
    ],
    memoryPages: 1,
    data: [{ offset: 0, bytes: [64, 0, 0, 0, 12, 0, 0, 0] }],
    functions: [
      {
        type: 1,
        code: [
          ...callDropped(0, [i32Const(3), i32Const(0), i32Const(1), i32Const(16)]),
          ...callDropped(1, [i32Const(1), i32Const(0), i32Const(1), i32Const(20)]),
        ],
      },
    ],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: '_start', kind: 0x00, index: 2 },
    ],
  });
}

function pathOpenModule(path: string): Uint8Array {
  return buildWasm({
    types: [funcType([I32, I32, I32, I32, I32, I64, I64, I32, I32], [I32]), STRING_TYPE],
    imports: [{ module: 'wasi_snapshot_preview1', name: 'path_open', type: 0 }],
    memoryPages: 1,
    data: [{ offset: 32, bytes: path }],
    functions: [
      {
        type: 1,
        code: callDropped(0, [
          i32Const(3),
          i32Const(0),
          i32Const(32),
          i32Const(path.length),
          i32Const(0),
          i64Const(1),
          i64Const(1),
          i32Const(0),
          i32Const(0),
        ]),
      },
    ],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: '_start', kind: 0x00, index: 1 },
    ],
  });
}

function infiniteLoopModule(): Uint8Array {
  return buildWasm({
    types: [STRING_TYPE],
    memoryPages: 1,
    functions: [{ type: 0, code: [OP.LOOP, 0x40, OP.BR, 0x00, 0x0b] }],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: 'run', kind: 0x00, index: 0 },
    ],
  });
}

function exitModule(code: number): Uint8Array {
  return buildWasm({
    types: [funcType([I32], []), STRING_TYPE],
    imports: [{ module: 'wasi_snapshot_preview1', name: 'proc_exit', type: 0 }],
    memoryPages: 1,
    functions: [{ type: 1, code: call(0, [i32Const(code)]) }],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: '_start', kind: 0x00, index: 1 },
    ],
  });
}

describe('WasiSandboxRunner', () => {
  it('answers fd_write and reports the fuel it spent', async () => {
    const result = await new WasiSandboxRunner({ fuel: 10_000 }).run(helloModule());

    expect(result.stdout).toBe('hi\n');
    expect(result.exitCode).toBe(0);
    expect(result.syscalls['fd_write']).toBe(1);
    expect(result.fuelUsed).toBeGreaterThan(0);
    expect(result.fuelRemaining).toBe(10_000 - result.fuelUsed);
    expect(result.violations).toEqual([]);
    expect(result.memoryBytes).toBe(65_536);
  });

  it('vaults the host filesystem: path_open is denied and recorded', async () => {
    const result = await new WasiSandboxRunner().run(pathOpenModule('/etc/passwd'));

    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.syscall).toBe('path_open');
    expect(result.violations[0]?.detail).toContain('/etc/passwd');
    expect(result.files).toEqual([]);
  });

  it('reads only from mounted virtual files', async () => {
    const result = await new WasiSandboxRunner({
      files: [{ path: 'stellar.toml', contents: 'virtual-read' }],
    }).run(readThenWriteModule());

    expect(result.stdout).toBe('virtual-read');
    expect(result.files).toEqual([{ path: 'stellar.toml', bytes: 12, writable: false }]);
    expect(result.violations).toEqual([]);
  });

  it('denies writes to a read-only mount', async () => {
    const result = await new WasiSandboxRunner({
      files: [{ path: 'stellar.toml', contents: 'x' }],
    }).run(helloModuleWithMountWrite());

    expect(result.violations.map((violation) => violation.syscall)).toContain('fd_write');
    expect(result.violations[0]?.detail).toContain('read-only');
  });

  it('lets a writable mount accept bytes and exposes them afterwards', async () => {
    const runner = new WasiSandboxRunner({
      files: [{ path: 'report.toml', contents: '', writable: true }],
    });
    const result = await runner.run(helloModuleToFile());

    expect(result.violations).toEqual([]);
    expect(result.files).toEqual([{ path: 'report.toml', bytes: 3, writable: true }]);
  });

  it('terminates an infinite loop by spending the fuel budget', async () => {
    await expect(
      new WasiSandboxRunner({ fuel: 1_000 }).run(infiniteLoopModule()),
    ).rejects.toMatchObject({ name: 'WasiSandboxError', code: 'fuel' });
  });

  it('reports proc_exit as the process status without throwing', async () => {
    const result = await new WasiSandboxRunner().run(exitModule(7));
    expect(result.exitCode).toBe(7);
  });

  it('refuses imports outside the WASI module before instantiating', async () => {
    const module = buildWasm({
      types: [STRING_TYPE],
      imports: [{ module: 'env', name: 'abort', type: 0 }],
      memoryPages: 1,
      functions: [{ type: 0, code: [] }],
      exports: [{ name: '_start', kind: 0x00, index: 1 }],
    });

    await expect(new WasiSandboxRunner().run(module)).rejects.toBeInstanceOf(WasiSandboxError);
    await expect(new WasiSandboxRunner().run(module)).rejects.toMatchObject({ code: 'import' });
  });
});

describe('injectFuelMeter', () => {
  it('adds a fuel global seeded from the budget and meters loops', async () => {
    const instrumented = injectFuelMeter(infiniteLoopModule(), 4_242);
    expect(instrumented.loopsMetered).toBe(1);

    const runtime = wasmRuntime();
    const instance = await runtime.instantiate(await runtime.compile(instrumented.bytes), {});
    const global = instance.exports[FUEL_EXPORT_NAME];
    expect(isWasmGlobal(global)).toBe(true);
    expect(isWasmGlobal(global) ? Number(global.value) : 0).toBe(4_242);
  });

  it('leaves an instrumented module valid for the runtime', async () => {
    const instrumented = injectFuelMeter(helloModule(), 1_000);
    const runtime = wasmRuntime();
    await expect(runtime.compile(instrumented.bytes)).resolves.toBeDefined();
  });

  it('rejects a non-positive budget and a non-WASM buffer', () => {
    expect(() => injectFuelMeter(helloModule(), 0)).toThrow(/positive integer/);
    expect(() => injectFuelMeter(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]))).toThrow(
      /magnitude|magic/,
    );
  });
});

/** `fd_write` to descriptor 3, where the read-only mount lives. */
function helloModuleWithMountWrite(): Uint8Array {
  return buildWasm({
    types: [WASI_IO_TYPE, STRING_TYPE],
    imports: [{ module: 'wasi_snapshot_preview1', name: 'fd_write', type: 0 }],
    memoryPages: 1,
    data: [
      { offset: 0, bytes: [16, 0, 0, 0, 3, 0, 0, 0] },
      { offset: 16, bytes: 'nope' },
    ],
    functions: [
      { type: 1, code: callDropped(0, [i32Const(3), i32Const(0), i32Const(1), i32Const(8)]) },
    ],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: '_start', kind: 0x00, index: 1 },
    ],
  });
}

/** Same, but the greeting is "hi\n" written to descriptor 3. */
function helloModuleToFile(): Uint8Array {
  return buildWasm({
    types: [WASI_IO_TYPE, STRING_TYPE],
    imports: [{ module: 'wasi_snapshot_preview1', name: 'fd_write', type: 0 }],
    memoryPages: 1,
    data: [
      { offset: 0, bytes: [16, 0, 0, 0, 3, 0, 0, 0] },
      { offset: 16, bytes: 'hi\n' },
    ],
    functions: [
      { type: 1, code: callDropped(0, [i32Const(3), i32Const(0), i32Const(1), i32Const(8)]) },
    ],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: '_start', kind: 0x00, index: 1 },
    ],
  });
}
