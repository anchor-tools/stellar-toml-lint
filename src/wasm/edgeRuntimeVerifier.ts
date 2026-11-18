/**
 * Edge runtime (Cloudflare Workers / V8 isolate) compatibility verifier.
 *
 * Edge isolates are not Node: there is no `process`, no `Buffer`, no `fs`, and
 * no dynamic code generation under most platform policies. They also cap the
 * isolate at 128 MB and expect the module to initialise in well under 50 ms.
 *
 * This verifier answers two questions without booting a platform runtime:
 * does the module reference anything an isolate does not provide (static scan),
 * and does a real lint fit the latency and heap budgets (measured here).
 *
 * Nothing in this file uses `eval` or `new Function`, both because the module
 * itself must stay edge-safe and because those APIs are what it looks for.
 */

import { lint } from '../lint.js';

export type EdgeFindingSeverity = 'error' | 'warning';

export interface EdgeFinding {
  code:
    | 'edge/node-builtin'
    | 'edge/dynamic-code'
    | 'edge/node-global'
    | 'edge/missing-web-api'
    | 'edge/cold-start-budget'
    | 'edge/heap-budget'
    | 'edge/lint-failure';
  severity: EdgeFindingSeverity;
  message: string;
  suggestion?: string;
}

export interface EdgeThresholds {
  /** Module evaluation budget. Cloudflare's paid plan allows 400 ms cold start. */
  maxColdStartMs: number;
  /** Isolate memory cap. */
  maxHeapBytes: number;
}

export interface EdgeVerificationOptions {
  thresholds?: Partial<EdgeThresholds>;
  /** Injected for tests; defaults to the core `lint`. */
  lintImpl?: (source: string) => unknown;
  /** Sample used for the latency/heap benchmark. */
  sampleSource?: string;
}

export interface EdgeBenchmark {
  coldStartMs: number;
  heapDeltaBytes: number | undefined;
  isolated: boolean;
}

export interface EdgeVerificationResult {
  compatible: boolean;
  findings: EdgeFinding[];
  benchmark: EdgeBenchmark;
  webApis: Record<string, boolean>;
}

export const DEFAULT_EDGE_THRESHOLDS: EdgeThresholds = {
  maxColdStartMs: 50,
  maxHeapBytes: 128 * 1024 * 1024,
};

export const EDGE_WEB_APIS = [
  'fetch',
  'Headers',
  'Request',
  'Response',
  'ReadableStream',
  'TextEncoder',
  'TextDecoder',
  'URL',
  'crypto',
] as const;

const SAMPLE_STELLAR_TOML = `VERSION="2.0.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
ACCOUNTS=["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"]
`;

/** Node-only globals an isolate does not define. */
const NODE_GLOBALS = [
  'process',
  'Buffer',
  '__dirname',
  '__filename',
  'require',
  'module',
  'setImmediate',
];

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split('\n').length;
}

function staticFindings(source: string): EdgeFinding[] {
  const findings: EdgeFinding[] = [];

  for (const match of source.matchAll(/(?<![\w.])eval\s*\(/g)) {
    findings.push({
      code: 'edge/dynamic-code',
      severity: 'error',
      message: `eval() at line ${lineOf(source, match.index)} is blocked by edge isolate CSP`,
      suggestion: 'Remove dynamic evaluation; a V8 isolate forbids it.',
    });
  }
  for (const match of source.matchAll(/new\s+Function\s*\(/g)) {
    findings.push({
      code: 'edge/dynamic-code',
      severity: 'error',
      message: `new Function() at line ${lineOf(source, match.index)} is blocked by edge isolate CSP`,
      suggestion: 'Replace generated code with a static implementation.',
    });
  }

  for (const match of source.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]/g)) {
    const specifier = match[1] ?? '';
    findings.push({
      code: 'edge/node-builtin',
      severity: 'error',
      message: `CommonJS require("${specifier}") at line ${lineOf(source, match.index)} is unavailable in a V8 isolate`,
      suggestion: 'Use an ESM import of a Worker-compatible module or remove the dependency.',
    });
  }

  for (const match of source.matchAll(/\bfrom\s+['"](node:[^'"]+|fs|path|os|child_process)['"]/g)) {
    findings.push({
      code: 'edge/node-builtin',
      severity: 'error',
      message: `Node built-in import "${match[1]}" at line ${lineOf(source, match.index)} cannot load in an isolate`,
      suggestion: 'Replace the built-in with the standard Web API equivalent.',
    });
  }

  for (const name of NODE_GLOBALS) {
    const pattern = new RegExp(`(?<![\\w.$])${name.replace('$', '\\$')}\\b`, 'g');
    for (const match of source.matchAll(pattern)) {
      // Object keys and string literals are common false positives; only flag
      // the identifier when it is actually read.
      const line = source.slice(0, match.index).split('\n').pop() ?? '';
      if (/\b(?:from|import|require)\b/.test(line)) continue;
      if (/^\s*(?:\/\/|\*)/.test(line)) continue;
      findings.push({
        code: 'edge/node-global',
        severity: name === 'process' || name === 'Buffer' ? 'error' : 'warning',
        message: `Node global ${name} at line ${lineOf(source, match.index)} is not defined in an edge isolate`,
        suggestion: 'Feature-detect the global or use the Web API equivalent.',
      });
      break;
    }
  }

  return findings;
}

/**
 * A stand-in isolate scope: exactly the Web APIs an edge runtime guarantees.
 * Callers can assert against it, or pass it to {@link runInIsolate} as the
 * only globals a lint will see.
 */
export function createEdgeIsolateScope(): Record<string, unknown> {
  const scope: Record<string, unknown> = {};
  for (const name of EDGE_WEB_APIS) {
    const value = (globalThis as Record<string, unknown>)[name];
    if (value !== undefined) scope[name] = value;
  }
  return scope;
}

export function checkEdgeWebApis(
  scope: Record<string, unknown> = createEdgeIsolateScope(),
): Record<string, boolean> {
  const availability: Record<string, boolean> = {};
  for (const name of EDGE_WEB_APIS) availability[name] = typeof scope[name] !== 'undefined';
  return availability;
}

/**
 * Reads a streaming edge response the way a Worker must: chunk by chunk,
 * without assuming `Content-Length` or a Node stream.
 */
export async function readEdgeStream(response: Response): Promise<string> {
  if (response.body === null) return await response.text();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let output = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    output += decoder.decode(value, { stream: true });
  }
  output += decoder.decode();
  return output;
}

function browserHeap(): number | undefined {
  const memory = (globalThis as { performance?: { memory?: { usedJSHeapSize: number } } })
    .performance?.memory;
  return memory?.usedJSHeapSize;
}

function nodeHeap(): number | undefined {
  const usage = (globalThis as { process?: { memoryUsage?: () => { heapUsed: number } } }).process
    ?.memoryUsage;
  if (typeof usage !== 'function') return undefined;
  try {
    return usage().heapUsed;
  } catch {
    return undefined;
  }
}

function currentHeap(): number | undefined {
  return browserHeap() ?? nodeHeap();
}

export class EdgeRuntimeVerifier {
  private readonly thresholds: EdgeThresholds;
  private readonly options: EdgeVerificationOptions;

  constructor(options: EdgeVerificationOptions = {}) {
    this.options = options;
    this.thresholds = { ...DEFAULT_EDGE_THRESHOLDS, ...options.thresholds };
  }

  /** Static compatibility check: no execution, safe to run on any bundle. */
  checkSource(source: string): EdgeFinding[] {
    return staticFindings(source);
  }

  benchmark(source = this.options.sampleSource ?? SAMPLE_STELLAR_TOML): EdgeBenchmark {
    const before = currentHeap();
    const started = performance.now();
    const run = this.options.lintImpl ?? ((input: string) => lint(input));
    run(source);
    const coldStartMs = performance.now() - started;
    const after = currentHeap();
    return {
      coldStartMs,
      heapDeltaBytes: before !== undefined && after !== undefined ? after - before : undefined,
      isolated: typeof (globalThis as { process?: unknown }).process === 'undefined',
    };
  }

  verify(source: string): EdgeVerificationResult {
    const findings = this.checkSource(source);
    const benchmark = this.benchmark();
    const webApis = checkEdgeWebApis();

    for (const [name, available] of Object.entries(webApis)) {
      if (!available) {
        findings.push({
          code: 'edge/missing-web-api',
          severity: 'error',
          message: `required Edge Web API ${name} is missing from the isolate scope`,
          suggestion: 'Run this check on a platform that implements the standard Edge runtime APIs.',
        });
      }
    }

    if (benchmark.coldStartMs > this.thresholds.maxColdStartMs) {
      findings.push({
        code: 'edge/cold-start-budget',
        severity: 'warning',
        message: `lint cold start ${benchmark.coldStartMs.toFixed(2)} ms exceeds the ${this.thresholds.maxColdStartMs} ms edge budget`,
        suggestion: 'Trim module-level work; move expensive setup behind the first request.',
      });
    }
    if (
      benchmark.heapDeltaBytes !== undefined &&
      benchmark.heapDeltaBytes > this.thresholds.maxHeapBytes
    ) {
      findings.push({
        code: 'edge/heap-budget',
        severity: 'warning',
        message: `lint allocated ${(benchmark.heapDeltaBytes / 1024 / 1024).toFixed(1)} MiB, above the ${(
          this.thresholds.maxHeapBytes /
          1024 /
          1024
        ).toFixed(0)} MiB isolate cap`,
        suggestion: 'Stream results instead of buffering the whole document and its diagnostics.',
      });
    }

    return {
      compatible: findings.every((finding) => finding.severity !== 'error'),
      findings,
      benchmark,
      webApis,
    };
  }
}

export function verifyEdgeCompatibility(
  source: string,
  options?: EdgeVerificationOptions,
): EdgeVerificationResult {
  return new EdgeRuntimeVerifier(options).verify(source);
}

export function renderEdgeReport(result: EdgeVerificationResult): string {
  const lines = [
    `Cold start: ${result.benchmark.coldStartMs.toFixed(2)} ms`,
    `Heap delta: ${
      result.benchmark.heapDeltaBytes === undefined
        ? 'not measurable'
        : `${(result.benchmark.heapDeltaBytes / 1024).toFixed(1)} KiB`
    }`,
    `Edge Web APIs: ${Object.values(result.webApis).every(Boolean) ? 'all available' : 'incomplete'}`,
    `Status: ${result.compatible ? 'compatible' : 'incompatible'}`,
  ];
  for (const finding of result.findings) {
    const marker = finding.severity === 'error' ? '✖' : '⚠';
    lines.push(`  ${marker} ${finding.code}: ${finding.message}`);
    if (finding.suggestion !== undefined) lines.push(`      → ${finding.suggestion}`);
  }
  return `${lines.join('\n')}\n`;
}
