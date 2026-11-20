/**
 * Heap-growth profiling for repeated WebAssembly invocations.
 *
 * A linter daemon or a long-lived studio session runs the same plugin hundreds
 * of times; a module that forgets to free guest memory costs one page per run
 * and eventually takes the process down. `WasmHeapProfiler` samples
 * `instance.exports.memory.buffer.byteLength` between runs, fits a line through
 * the samples, and separates a module that *stabilises* (allocator high-water
 * mark, then flat) from one that grows without bound.
 *
 * Sampling after each iteration rather than inside it keeps the overhead to one
 * property read per run. The regression is reported in exact bytes per
 * iteration so a CI budget can be set from a measurement instead of a guess,
 * and the growth curve is emitted as a standalone SVG — no chart dependency.
 */
import type { DanglingPointer, PointerLedger } from './pointerLedger.js';

export interface HeapSample {
  iteration: number;
  bytes: number;
  /** Change from the previous sample, in bytes. */
  deltaBytes: number;
}

export interface HeapProfile {
  iterations: number;
  baselineBytes: number;
  finalBytes: number;
  peakBytes: number;
  totalDeltaBytes: number;
  samples: HeapSample[];
  /** Least-squares slope of bytes against iteration. */
  growthPerIterationBytes: number;
  /** True when samples never fall back for more than a rounding-sized window. */
  monotonicGrowth: boolean;
  /** First iteration after which the sample spread stays inside tolerance. */
  plateauedAtIteration: number | null;
  leaked: boolean;
  verdict: 'stable' | 'leaking' | 'inconclusive';
  danglingPointers: DanglingPointer[];
  danglingBytes: number;
}

export interface HeapProfilerOptions {
  /** Total growth under which a module is never called a leak. Default 64 KiB. */
  leakThresholdBytes?: number;
  /** Number of trailing samples a plateau must hold for. */
  stableWindow?: number;
  /** Optional host-pointer ledger, to report pointers a run never released. */
  pointerLedger?: PointerLedger;
}

/** WASM linear memory is allocated in 64 KiB pages. */
export const WASM_PAGE_BYTES = 65_536;

export const DEFAULT_LEAK_THRESHOLD_BYTES = WASM_PAGE_BYTES;

export const DEFAULT_STABLE_WINDOW = 10;

function round(bytes: number): number {
  return Math.round(bytes * 1000) / 1000;
}

/** Least-squares slope of y over x. */
function slope(xs: number[], ys: number[]): number {
  const n = Math.min(xs.length, ys.length);
  if (n < 2) return 0;
  const meanX = xs.reduce((sum, x) => sum + x, 0) / n;
  const meanY = ys.reduce((sum, y) => sum + y, 0) / n;
  let numerator = 0;
  let denominator = 0;
  for (let i = 0; i < n; i++) {
    const dx = (xs[i] as number) - meanX;
    numerator += dx * ((ys[i] as number) - meanY);
    denominator += dx * dx;
  }
  return denominator === 0 ? 0 : numerator / denominator;
}

export class WasmHeapProfiler {
  private readonly leakThresholdBytes: number;
  private readonly stableWindow: number;
  private readonly pointerLedger: PointerLedger | undefined;

  constructor(options: HeapProfilerOptions = {}) {
    this.leakThresholdBytes = options.leakThresholdBytes ?? DEFAULT_LEAK_THRESHOLD_BYTES;
    this.stableWindow = options.stableWindow ?? DEFAULT_STABLE_WINDOW;
    this.pointerLedger = options.pointerLedger;
  }

  /**
   * Runs `run` `iterations` times, reading `memoryBytes` after each call.
   *
   * `run` is awaited, so an async plugin host works unchanged; `memoryBytes`
   * is re-read every iteration because growing memory detaches the old
   * `ArrayBuffer` and a cached length would freeze at the baseline.
   */
  async profile(
    run: (iteration: number) => void | Promise<void>,
    memoryBytes: () => number,
    iterations = 1_000,
  ): Promise<HeapProfile> {
    if (!Number.isInteger(iterations) || iterations < 1) {
      throw new Error('iterations must be a positive integer.');
    }

    const baselineBytes = memoryBytes();
    const samples: HeapSample[] = [];
    let previous = baselineBytes;

    for (let iteration = 1; iteration <= iterations; iteration++) {
      await run(iteration);
      const bytes = memoryBytes();
      samples.push({ iteration, bytes, deltaBytes: bytes - previous });
      previous = bytes;
    }

    return this.analyze(samples, baselineBytes);
  }

  /** Classifies a set of samples; exposed so recorded profiles can be re-checked. */
  analyze(samples: HeapSample[], baselineBytes: number): HeapProfile {
    const finalBytes =
      samples.length > 0 ? (samples[samples.length - 1] as HeapSample).bytes : baselineBytes;
    const peakBytes = samples.reduce((peak, sample) => Math.max(peak, sample.bytes), baselineBytes);
    const totalDeltaBytes = finalBytes - baselineBytes;

    const xs = samples.map((sample) => sample.iteration);
    const ys = samples.map((sample) => sample.bytes);
    const growthPerIterationBytes = round(slope(xs, ys));

    const window = Math.max(2, Math.min(this.stableWindow, samples.length));
    const tail = samples.slice(-window);
    const regressions = tail.filter((sample) => sample.deltaBytes < 0).length;
    // One page of slack absorbs an allocator that frees in a different order
    // than it allocated; a leak keeps stepping up every iteration.
    const monotonicGrowth =
      tail.length > 0 &&
      regressions <= Math.floor(tail.length * 0.05) &&
      totalDeltaBytes > this.leakThresholdBytes;

    const plateauedAtIteration = this.plateau(samples);
    const leaked = totalDeltaBytes > this.leakThresholdBytes && monotonicGrowth;
    const verdict: HeapProfile['verdict'] = leaked
      ? 'leaking'
      : plateauedAtIteration !== null
        ? 'stable'
        : 'inconclusive';

    const danglingPointers = this.pointerLedger?.dangling() ?? [];

    return {
      iterations: samples.length,
      baselineBytes,
      finalBytes,
      peakBytes,
      totalDeltaBytes,
      samples,
      growthPerIterationBytes,
      monotonicGrowth,
      plateauedAtIteration,
      leaked,
      verdict,
      danglingPointers,
      danglingBytes: danglingPointers.reduce((sum, pointer) => sum + pointer.bytes, 0),
    };
  }

  /**
   * Finds the first iteration whose remaining samples stay inside one page.
   * A stable module plateaus as soon as its allocator stops requesting pages,
   * usually within the first few runs.
   */
  private plateau(samples: HeapSample[]): number | null {
    if (samples.length === 0) return null;
    const tolerance = Math.max(1_024, Math.round(this.leakThresholdBytes / 16));
    const window = Math.max(2, Math.min(this.stableWindow, samples.length));

    // A single flat sample is not a plateau: the last `window` readings have to
    // agree before the trailling flat run means anything.
    const tail = samples.slice(-window);
    const spread = (values: HeapSample[]): number =>
      Math.max(...values.map((sample) => sample.bytes)) -
      Math.min(...values.map((sample) => sample.bytes));
    if (spread(tail) > tolerance) return null;

    let min = Infinity;
    let max = -Infinity;
    for (let i = samples.length - 1; i >= 0; i--) {
      const bytes = (samples[i] as HeapSample).bytes;
      min = Math.min(min, bytes);
      max = Math.max(max, bytes);
      if (max - min > tolerance) {
        const next = samples[i + 1];
        return next === undefined ? null : next.iteration;
      }
    }
    return (samples[0] as HeapSample).iteration;
  }

  /** A self-contained SVG growth curve: no chart library, no fonts to fetch. */
  renderGrowthCurve(
    profile: HeapProfile,
    options: { width?: number; height?: number } = {},
  ): string {
    const width = options.width ?? 640;
    const height = options.height ?? 240;
    const padding = { top: 24, right: 16, bottom: 32, left: 64 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    const maxBytes = Math.max(profile.peakBytes, profile.baselineBytes, 1);
    const count = profile.samples.length;
    const x = (iteration: number): number =>
      padding.left + (count <= 1 ? 0 : ((iteration - 1) / (count - 1)) * plotWidth);
    const y = (bytes: number): number => padding.top + plotHeight - (bytes / maxBytes) * plotHeight;

    const points = profile.samples
      .map((sample) => `${x(sample.iteration).toFixed(2)},${y(sample.bytes).toFixed(2)}`)
      .join(' ');
    const colour = profile.leaked ? '#d1242f' : '#1a7f37';
    const label = profile.leaked ? 'growing' : profile.verdict;

    return [
      `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="WASM heap growth">`,
      `<rect width="${width}" height="${height}" fill="#ffffff"/>`,
      `<line x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${padding.top + plotHeight}" stroke="#d0d7de"/>`,
      `<line x1="${padding.left}" y1="${padding.top + plotHeight}" x2="${padding.left + plotWidth}" y2="${padding.top + plotHeight}" stroke="#d0d7de"/>`,
      `<text x="${padding.left}" y="${padding.top + plotHeight + 20}" font-family="monospace" font-size="11" fill="#57606a">1</text>`,
      `<text x="${padding.left + plotWidth}" y="${padding.top + plotHeight + 20}" text-anchor="end" font-family="monospace" font-size="11" fill="#57606a">${count}</text>`,
      `<text x="${padding.left - 8}" y="${padding.top + 4}" text-anchor="end" font-family="monospace" font-size="11" fill="#57606a">${maxBytes} B</text>`,
      `<text x="${padding.left - 8}" y="${padding.top + plotHeight}" text-anchor="end" font-family="monospace" font-size="11" fill="#57606a">0 B</text>`,
      `<polyline fill="none" stroke="${colour}" stroke-width="2" points="${points}"/>`,
      `<text x="${padding.left}" y="16" font-family="monospace" font-size="12" fill="${colour}">${label} · ${profile.growthPerIterationBytes} B/iteration</text>`,
      '</svg>',
      '',
    ].join('\n');
  }

  /** Text diagnostic for the CLI: the numbers a reviewer needs, in order. */
  formatReport(profile: HeapProfile): string {
    const lines = [
      `WASM heap profile — ${profile.verdict}`,
      `  iterations       ${profile.iterations}`,
      `  baseline         ${profile.baselineBytes} B`,
      `  final            ${profile.finalBytes} B`,
      `  peak             ${profile.peakBytes} B`,
      `  delta            ${profile.totalDeltaBytes} B`,
      `  growth           ${profile.growthPerIterationBytes} B/iteration`,
      `  plateau          ${
        profile.plateauedAtIteration === null
          ? 'never (memory keeps growing)'
          : `iteration ${profile.plateauedAtIteration}`
      }`,
    ];

    if (profile.danglingPointers.length > 0) {
      lines.push(
        `  dangling         ${profile.danglingPointers.length} pointer(s), ${profile.danglingBytes} B`,
      );
      for (const pointer of profile.danglingPointers.slice(0, 5)) {
        lines.push(`    ${pointer.label} @ ${pointer.pointer} (${pointer.bytes} B)`);
      }
    }

    return `${lines.join('\n')}\n`;
  }
}
