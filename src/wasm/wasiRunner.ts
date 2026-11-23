/**
 * A WASI preview 1 sandbox runner for untrusted validator plugins.
 *
 * A plugin is compiled code with the same reach as the process that hosts it,
 * so "run this third-party module" cannot mean handing it `node:fs`. This
 * runner implements the WASI preview 1 calls a plugin actually needs —
 * `fd_read`, `fd_write`, `clock_time_get`, `random_get` — over an in-memory
 * virtual filesystem, and denies everything else with the WASI errno the guest
 * expects. Denials are also recorded, because a module probing for `/etc` is a
 * finding even when the probe fails.
 *
 * Capabilities are explicit: descriptors 0-2 are stdio, virtual files are
 * mounted at 3 and up, and `path_open` — the only way preview 1 reaches a
 * *host* path — always returns `ENOTCAPABLE`. Execution is bounded by the
 * fuel meter in `fuelMeter.ts`, so a `loop br 0` in a plugin terminates the
 * invocation instead of the host.
 */
import { WasiSandboxError } from './errors.js';
import { DEFAULT_FUEL, FUEL_EXPORT_NAME, injectFuelMeter } from './fuelMeter.js';
import {
  isWasmGlobal,
  isWasmMemory,
  isWasmRuntimeError,
  wasmRuntime,
  type WasmInstanceLike,
} from './wasmApi.js';

const WASI_MODULE = 'wasi_snapshot_preview1';

/** WASI preview 1 `errno` values the runner can return. */
export const WASI_ERRNO = {
  SUCCESS: 0,
  BADF: 8,
  FAULT: 21,
  INVAL: 28,
  NOENT: 44,
  NOSYS: 52,
  PIPE: 64,
  SPIPE: 70,
  NOTCAPABLE: 76,
} as const;

/** `fd_fdstat_get` file types. */
const FILETYPE_UNKNOWN = 0;
const FILETYPE_CHARACTER_DEVICE = 2;
const FILETYPE_REGULAR_FILE = 4;

/** Every preview 1 call the sandbox is willing to answer. */
export const SANDBOX_SYSCALLS = [
  'args_get',
  'args_sizes_get',
  'clock_time_get',
  'environ_get',
  'environ_sizes_get',
  'fd_close',
  'fd_fdstat_get',
  'fd_filestat_get',
  'fd_prestat_dir_name',
  'fd_prestat_get',
  'fd_read',
  'fd_seek',
  'fd_write',
  'path_open',
  'proc_exit',
  'random_get',
  'sched_yield',
] as const;

export interface VirtualFileInput {
  /** Path the guest sees, purely a label: it never resolves on the host. */
  path: string;
  contents: string | Uint8Array;
  writable?: boolean;
}

export interface WasiSandboxOptions {
  files?: VirtualFileInput[];
  args?: string[];
  env?: Record<string, string>;
  stdin?: string | Uint8Array;
  stdout?: (chunk: string) => void;
  stderr?: (chunk: string) => void;
  /** Instruction budget, in metered function entries plus loop iterations. */
  fuel?: number;
  /** Clock source for `clock_time_get`, in milliseconds. */
  clockMs?: () => number;
  /** Deterministic entropy for `random_get`; defaults to the platform CSPRNG. */
  random?: (target: Uint8Array) => void;
  maxMemoryBytes?: number;
  entryPoint?: string;
}

export interface SandboxViolation {
  syscall: string;
  detail: string;
}

export interface SandboxFileSnapshot {
  path: string;
  bytes: number;
  writable: boolean;
}

export interface WasiSandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  fuelUsed: number;
  fuelRemaining: number;
  /** Number of host calls per syscall, for diagnosing a spinning plugin. */
  syscalls: Record<string, number>;
  violations: SandboxViolation[];
  files: SandboxFileSnapshot[];
  memoryBytes: number;
}

interface MountedFile {
  path: string;
  bytes: Uint8Array;
  pos: number;
  writable: boolean;
}

/** Internal signal for `proc_exit`, which unwinds the guest rather than returning. */
class WasiExit extends Error {
  constructor(readonly code: number) {
    super(`proc_exit(${code})`);
    this.name = 'WasiExit';
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBytes(value: string | Uint8Array): Uint8Array {
  return typeof value === 'string' ? encoder.encode(value) : value;
}

function inBounds(view: DataView, ptr: number, length: number): boolean {
  return ptr >= 0 && length >= 0 && ptr + length <= view.byteLength;
}

/**
 * Host-side state for one sandboxed invocation. The import object is built per
 * run, so two runs of the same module cannot observe each other's files.
 */
class WasiHost {
  readonly violations: SandboxViolation[] = [];
  readonly syscalls: Record<string, number> = {};

  private instance: WasmInstanceLike | undefined;
  private readonly stdoutChunks: string[] = [];
  private readonly stderrChunks: string[] = [];
  private readonly files = new Map<number, MountedFile>();
  private readonly stdin: Uint8Array;
  private stdinPos = 0;
  private nextFd = 3;
  private readonly clock: () => number;
  private readonly random: (target: Uint8Array) => void;

  constructor(private readonly options: WasiSandboxOptions) {
    this.stdin = toBytes(options.stdin ?? '');
    this.clock = options.clockMs ?? Date.now;
    this.random = options.random ?? defaultRandom;

    for (const file of options.files ?? []) {
      this.files.set(this.nextFd++, {
        path: file.path,
        bytes: toBytes(file.contents).slice(),
        pos: 0,
        writable: file.writable === true,
      });
    }
  }

  attach(instance: WasmInstanceLike): void {
    this.instance = instance;
  }

  get stdout(): string {
    return this.stdoutChunks.join('');
  }

  get stderr(): string {
    return this.stderrChunks.join('');
  }

  snapshots(): SandboxFileSnapshot[] {
    return [...this.files.values()].map((file) => ({
      path: file.path,
      bytes: file.bytes.length,
      writable: file.writable,
    }));
  }

  /** Bytes written back through a writable mount, exposed for assertions. */
  fileContents(path: string): Uint8Array | undefined {
    for (const file of this.files.values()) {
      if (file.path === path) return file.bytes;
    }
    return undefined;
  }

  fuelRemaining(instance: WasmInstanceLike): number {
    const global = instance.exports[FUEL_EXPORT_NAME];
    return isWasmGlobal(global) ? Number(global.value) : 0;
  }

  private memory(): DataView | undefined {
    const memory = this.instance?.exports['memory'];
    return isWasmMemory(memory) ? new DataView(memory.buffer) : undefined;
  }

  private deny(syscall: string, detail: string, errno: number): number {
    this.violations.push({ syscall, detail });
    return errno;
  }

  private count(syscall: string): void {
    this.syscalls[syscall] = (this.syscalls[syscall] ?? 0) + 1;
  }

  private readString(view: DataView, ptr: number, length: number): string | undefined {
    if (!inBounds(view, ptr, length)) return undefined;
    return decoder.decode(new Uint8Array(view.buffer, ptr, length));
  }

  private writeU64(view: DataView, ptr: number, value: bigint): boolean {
    if (!inBounds(view, ptr, 8)) return false;
    view.setBigUint64(ptr, value, true);
    return true;
  }

  /** The preview 1 import object, wired to this host's capabilities. */
  imports(): Record<string, unknown> {
    return {
      args_sizes_get: (argcPtr: number, sizePtr: number): number =>
        this.wrap('args_sizes_get', (view) => {
          const args = this.options.args ?? [];
          if (!inBounds(view, argcPtr, 4) || !inBounds(view, sizePtr, 4)) return WASI_ERRNO.FAULT;
          view.setUint32(argcPtr, args.length, true);
          view.setUint32(
            sizePtr,
            args.reduce((total, arg) => total + encoder.encode(arg).length + 1, 0),
            true,
          );
          return WASI_ERRNO.SUCCESS;
        }),

      args_get: (argvPtr: number, bufferPtr: number): number =>
        this.wrap('args_get', (view) => {
          let cursor = bufferPtr;
          for (const [index, arg] of (this.options.args ?? []).entries()) {
            const bytes = encoder.encode(arg);
            if (
              !inBounds(view, argvPtr + index * 4, 4) ||
              !inBounds(view, cursor, bytes.length + 1)
            ) {
              return WASI_ERRNO.FAULT;
            }
            view.setUint32(argvPtr + index * 4, cursor, true);
            new Uint8Array(view.buffer, cursor, bytes.length).set(bytes);
            new Uint8Array(view.buffer)[cursor + bytes.length] = 0;
            cursor += bytes.length + 1;
          }
          return WASI_ERRNO.SUCCESS;
        }),

      environ_sizes_get: (countPtr: number, sizePtr: number): number =>
        this.wrap('environ_sizes_get', (view) => {
          const entries = Object.entries(this.options.env ?? {}).map(([k, v]) => `${k}=${v}`);
          if (!inBounds(view, countPtr, 4) || !inBounds(view, sizePtr, 4)) return WASI_ERRNO.FAULT;
          view.setUint32(countPtr, entries.length, true);
          view.setUint32(
            sizePtr,
            entries.reduce((total, entry) => total + encoder.encode(entry).length + 1, 0),
            true,
          );
          return WASI_ERRNO.SUCCESS;
        }),

      environ_get: (environPtr: number, bufferPtr: number): number =>
        this.wrap('environ_get', (view) => {
          let cursor = bufferPtr;
          const entries = Object.entries(this.options.env ?? {}).map(([k, v]) => `${k}=${v}`);
          for (const [index, entry] of entries.entries()) {
            const bytes = encoder.encode(entry);
            if (
              !inBounds(view, environPtr + index * 4, 4) ||
              !inBounds(view, cursor, bytes.length + 1)
            ) {
              return WASI_ERRNO.FAULT;
            }
            view.setUint32(environPtr + index * 4, cursor, true);
            new Uint8Array(view.buffer, cursor, bytes.length).set(bytes);
            new Uint8Array(view.buffer)[cursor + bytes.length] = 0;
            cursor += bytes.length + 1;
          }
          return WASI_ERRNO.SUCCESS;
        }),

      clock_time_get: (clockId: number, _precision: bigint, timePtr: number): number =>
        this.wrap('clock_time_get', (view) => {
          if (clockId !== 0 && clockId !== 1) {
            return this.deny(
              'clock_time_get',
              `clock id ${clockId} is not granted`,
              WASI_ERRNO.INVAL,
            );
          }
          const nanos = BigInt(Math.round(this.clock() * 1_000_000));
          return this.writeU64(view, timePtr, nanos) ? WASI_ERRNO.SUCCESS : WASI_ERRNO.FAULT;
        }),

      random_get: (bufferPtr: number, length: number): number =>
        this.wrap('random_get', (view) => {
          if (!inBounds(view, bufferPtr, length)) return WASI_ERRNO.FAULT;
          this.random(new Uint8Array(view.buffer, bufferPtr, length));
          return WASI_ERRNO.SUCCESS;
        }),

      sched_yield: (): number => this.wrap('sched_yield', () => WASI_ERRNO.SUCCESS),

      proc_exit: (code: number): void => {
        this.count('proc_exit');
        throw new WasiExit(code);
      },

      fd_write: (fd: number, iovsPtr: number, iovsLen: number, nwrittenPtr: number): number =>
        this.wrap('fd_write', (view) => {
          if (!inBounds(view, iovsPtr, iovsLen * 8) || !inBounds(view, nwrittenPtr, 4)) {
            return WASI_ERRNO.FAULT;
          }
          let total = 0;
          const chunks: Uint8Array[] = [];
          for (let i = 0; i < iovsLen; i++) {
            const ptr = view.getUint32(iovsPtr + i * 8, true);
            const length = view.getUint32(iovsPtr + i * 8 + 4, true);
            if (!inBounds(view, ptr, length)) return WASI_ERRNO.FAULT;
            const chunk = new Uint8Array(view.buffer, ptr, length);
            chunks.push(chunk);
            total += length;
          }

          const bytes = concatBytes(chunks);
          if (fd === 1) {
            this.stdoutChunks.push(decoder.decode(bytes));
            this.options.stdout?.(decoder.decode(bytes));
          } else if (fd === 2) {
            this.stderrChunks.push(decoder.decode(bytes));
            this.options.stderr?.(decoder.decode(bytes));
          } else {
            const file = this.files.get(fd);
            if (file === undefined) return WASI_ERRNO.BADF;
            if (!file.writable) {
              return this.deny(
                'fd_write',
                `write to read-only mount "${file.path}" on fd ${fd}`,
                WASI_ERRNO.NOTCAPABLE,
              );
            }
            const end = file.pos + bytes.length;
            if (end > file.bytes.length) {
              const grown = new Uint8Array(end);
              grown.set(file.bytes);
              file.bytes = grown;
            }
            file.bytes.set(bytes, file.pos);
            file.pos = end;
          }

          view.setUint32(nwrittenPtr, total, true);
          return WASI_ERRNO.SUCCESS;
        }),

      fd_read: (fd: number, iovsPtr: number, iovsLen: number, nreadPtr: number): number =>
        this.wrap('fd_read', (view) => {
          if (!inBounds(view, iovsPtr, iovsLen * 8) || !inBounds(view, nreadPtr, 4)) {
            return WASI_ERRNO.FAULT;
          }

          const source = fd === 0 ? this.stdin : this.files.get(fd)?.bytes;
          if (source === undefined) {
            return fd < 3 && fd !== 0 ? WASI_ERRNO.BADF : WASI_ERRNO.NOTCAPABLE;
          }
          let cursor = fd === 0 ? this.stdinPos : (this.files.get(fd)?.pos ?? 0);
          let total = 0;

          for (let i = 0; i < iovsLen; i++) {
            const ptr = view.getUint32(iovsPtr + i * 8, true);
            const length = view.getUint32(iovsPtr + i * 8 + 4, true);
            if (!inBounds(view, ptr, length)) return WASI_ERRNO.FAULT;
            const available = source.subarray(cursor, Math.min(source.length, cursor + length));
            new Uint8Array(view.buffer, ptr, available.length).set(available);
            cursor += available.length;
            total += available.length;
            if (available.length < length) break;
          }

          if (fd === 0) this.stdinPos = cursor;
          else {
            const file = this.files.get(fd);
            if (file) file.pos = cursor;
          }
          view.setUint32(nreadPtr, total, true);
          return WASI_ERRNO.SUCCESS;
        }),

      fd_seek: (fd: number, offset: bigint, whence: number, newOffsetPtr: number): number =>
        this.wrap('fd_seek', (view) => {
          const file = this.files.get(fd);
          if (file === undefined) return WASI_ERRNO.BADF;
          if (whence > 2) return WASI_ERRNO.INVAL;
          const base = whence === 0 ? 0 : whence === 1 ? file.pos : file.bytes.length;
          const next = base + Number(offset);
          if (next < 0) return WASI_ERRNO.INVAL;
          file.pos = next;
          if (!this.writeU64(view, newOffsetPtr, BigInt(next))) return WASI_ERRNO.FAULT;
          return WASI_ERRNO.SUCCESS;
        }),

      fd_close: (fd: number): number =>
        this.wrap('fd_close', () => {
          if (fd <= 2) return WASI_ERRNO.SUCCESS;
          return this.files.delete(fd) ? WASI_ERRNO.SUCCESS : WASI_ERRNO.BADF;
        }),

      fd_fdstat_get: (fd: number, statPtr: number): number =>
        this.wrap('fd_fdstat_get', (view) => {
          if (!inBounds(view, statPtr, 24)) return WASI_ERRNO.FAULT;
          const file = this.files.get(fd);
          if (file === undefined && fd > 2) return WASI_ERRNO.BADF;
          const filetype =
            fd <= 2
              ? FILETYPE_CHARACTER_DEVICE
              : file === undefined
                ? FILETYPE_UNKNOWN
                : FILETYPE_REGULAR_FILE;
          view.setUint8(statPtr, filetype);
          view.setUint16(statPtr + 2, 0, true);
          view.setBigUint64(statPtr + 8, file === undefined ? 0n : 1n << 1n, true);
          view.setBigUint64(statPtr + 16, 0n, true);
          return WASI_ERRNO.SUCCESS;
        }),

      fd_filestat_get: (fd: number, statPtr: number): number =>
        this.wrap('fd_filestat_get', (view) => {
          if (!inBounds(view, statPtr, 64)) return WASI_ERRNO.FAULT;
          const file = this.files.get(fd);
          if (file === undefined && fd > 2) return WASI_ERRNO.BADF;
          view.setBigUint64(statPtr, 0n, true);
          view.setBigUint64(statPtr + 8, BigInt(fd), true);
          view.setUint8(
            statPtr + 16,
            file === undefined ? FILETYPE_CHARACTER_DEVICE : FILETYPE_REGULAR_FILE,
          );
          view.setBigUint64(statPtr + 24, 1n, true);
          view.setBigUint64(statPtr + 32, BigInt(file?.bytes.length ?? 0), true);
          const now = BigInt(Math.round(this.clock() * 1_000_000));
          for (const offset of [40, 48, 56]) view.setBigUint64(statPtr + offset, now, true);
          return WASI_ERRNO.SUCCESS;
        }),

      // The only preview 1 call that turns a guest path into a host descriptor.
      // There is deliberately no resolver behind it: the virtual mounts are
      // addressed by descriptor, never by path, so a plugin cannot name a file
      // it was not handed.
      // The trailing rights/flags arguments are part of the ABI but have no
      // meaning here — nothing is ever opened — so they are simply ignored.
      path_open: (...args: Array<number | bigint>): number =>
        this.wrap('path_open', (view) => {
          const pathPtr = Number(args[2] ?? 0);
          const pathLen = Number(args[3] ?? 0);
          const path = this.readString(view, pathPtr, pathLen) ?? '<unreadable>';
          return this.deny(
            'path_open',
            `attempted to open host path "${path}"`,
            WASI_ERRNO.NOTCAPABLE,
          );
        }),

      fd_prestat_get: (fd: number): number =>
        this.wrap('fd_prestat_get', () =>
          this.deny(
            'fd_prestat_get',
            `attempted to enumerate preopen fd ${fd}`,
            WASI_ERRNO.NOTCAPABLE,
          ),
        ),

      fd_prestat_dir_name: (fd: number): number =>
        this.wrap('fd_prestat_dir_name', () =>
          this.deny(
            'fd_prestat_dir_name',
            `attempted to read the name of preopen fd ${fd}`,
            WASI_ERRNO.NOTCAPABLE,
          ),
        ),
    };
  }

  private wrap(syscall: string, body: (view: DataView) => number): number {
    this.count(syscall);
    const view = this.memory();
    if (view === undefined) return WASI_ERRNO.FAULT;
    try {
      return body(view);
    } catch (error) {
      if (error instanceof WasiExit) throw error;
      this.violations.push({
        syscall,
        detail: error instanceof Error ? error.message : String(error),
      });
      return WASI_ERRNO.FAULT;
    }
  }
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  if (chunks.length === 1) return chunks[0] as Uint8Array;
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function defaultRandom(target: Uint8Array): void {
  const crypto = (globalThis as unknown as { crypto?: { getRandomValues<T>(array: T): T } }).crypto;
  if (crypto !== undefined) {
    crypto.getRandomValues(target);
    return;
  }
  for (let i = 0; i < target.length; i++) target[i] = Math.floor(Math.random() * 256);
}

/** Runs one plugin module inside the capability sandbox. */
export class WasiSandboxRunner {
  constructor(private readonly options: WasiSandboxOptions = {}) {}

  /** Virtual mounts, so a caller can inspect bytes a plugin wrote back. */
  async run(module: Uint8Array): Promise<WasiSandboxResult> {
    const runtime = wasmRuntime();
    const fuel = this.options.fuel ?? DEFAULT_FUEL;

    const compiled = await runtime.compile(module);
    for (const imported of runtime.Module.imports(compiled)) {
      if (imported.module !== WASI_MODULE) {
        throw new WasiSandboxError(
          'import',
          `Module imports "${imported.module}.${imported.name}". Only ${WASI_MODULE} is available inside the sandbox.`,
        );
      }
      if (!(SANDBOX_SYSCALLS as readonly string[]).includes(imported.name)) {
        throw new WasiSandboxError(
          'import',
          `Module imports the unsupported WASI call "${imported.name}".`,
        );
      }
    }

    const instrumented = injectFuelMeter(module, fuel);
    const host = new WasiHost(this.options);
    let instance: WasmInstanceLike;
    try {
      const metered = await runtime.compile(instrumented.bytes);
      instance = await runtime.instantiate(metered, { [WASI_MODULE]: host.imports() });
    } catch (error) {
      if (isWasmRuntimeError(error)) {
        throw new WasiSandboxError('format', `Module failed to instantiate: ${error.message}`);
      }
      throw error;
    }
    host.attach(instance);

    const memory = instance.exports['memory'];
    const memoryBytes = isWasmMemory(memory) ? memory.buffer.byteLength : 0;
    if (this.options.maxMemoryBytes !== undefined && memoryBytes > this.options.maxMemoryBytes) {
      throw new WasiSandboxError(
        'memory',
        `Module reserved ${memoryBytes} bytes, over the ${this.options.maxMemoryBytes}-byte limit.`,
      );
    }

    const entryName =
      this.options.entryPoint ??
      (typeof instance.exports['_start'] === 'function'
        ? '_start'
        : typeof instance.exports['run'] === 'function'
          ? 'run'
          : typeof instance.exports['main'] === 'function'
            ? 'main'
            : undefined);

    if (entryName === undefined) {
      throw new WasiSandboxError(
        'format',
        'Module exports no entry point. Expected _start, run, or main.',
      );
    }

    const entry = instance.exports[entryName];
    if (typeof entry !== 'function') {
      throw new WasiSandboxError('format', `Export "${entryName}" is not a function.`);
    }

    let exitCode = 0;
    try {
      await (entry as () => unknown)();
    } catch (error) {
      if (error instanceof WasiExit) {
        exitCode = error.code;
      } else if (isWasmRuntimeError(error)) {
        const remaining = host.fuelRemaining(instance);
        if (remaining === 0) {
          throw new WasiSandboxError(
            'fuel',
            `Module exhausted its ${fuel}-step fuel budget and was terminated.`,
            'fuel',
          );
        }
        throw new WasiSandboxError('trap', `Module trapped: ${error.message}`, 'trap');
      } else {
        throw error;
      }
    }

    const remaining = host.fuelRemaining(instance);
    return {
      exitCode,
      stdout: host.stdout,
      stderr: host.stderr,
      fuelUsed: Math.max(0, fuel - remaining),
      fuelRemaining: remaining,
      syscalls: host.syscalls,
      violations: host.violations,
      files: host.snapshots(),
      memoryBytes,
    };
  }
}
