/**
 * WebAssembly streaming-compilation verifier.
 *
 * `WebAssembly.instantiateStreaming` compiles a module while the response
 * bodies are still arriving, but it refuses anything whose
 * `Content-Type` is not exactly `application/wasm`. A static host that serves
 * `.wasm` as `application/octet-stream` silently falls back to a two-pass
 * download + compile, which is measurably slower on a cold cache.
 *
 * `WasmStreamingVerifier` inspects the headers a deployed URL actually sends,
 * benchmark-compiles the fetched bytes with `instantiateStreaming` against the
 * buffered `instantiate` path, and renders copy-paste fixes for Nginx, Apache,
 * and Cloudflare. Runtimes without streaming support degrade to a header-only
 * check rather than failing the run.
 */

export type StreamingFindingCode =
  | 'streaming/unreachable'
  | 'streaming/http-error'
  | 'streaming/missing-content-type'
  | 'streaming/invalid-content-type'
  | 'streaming/not-wasm'
  | 'streaming/benchmark-failed';

export interface StreamingFinding {
  code: StreamingFindingCode;
  severity: 'error' | 'warning';
  subject: string;
  message: string;
  suggestion: string;
}

export interface StreamingBenchmark {
  /** True when this runtime exposes `WebAssembly.instantiateStreaming`. */
  supported: boolean;
  /** True when both paths were actually timed. */
  ran: boolean;
  streamingMs?: number;
  bufferedMs?: number;
  /** bufferedMs / streamingMs; above 1 means streaming won. */
  speedup?: number;
  error?: string;
}

export interface StreamingVerificationResult {
  ok: boolean;
  url: string;
  status?: number;
  contentType?: string;
  findings: StreamingFinding[];
  benchmark: StreamingBenchmark;
  /** Platform snippets that make the server send `application/wasm`. */
  fixes: string[];
}

export interface StreamingRuntimeLike {
  instantiateStreaming?: (
    source: Response | Promise<Response>,
    imports?: Record<string, Record<string, unknown>>,
  ) => Promise<unknown>;
  instantiate?: (
    bytes: Uint8Array,
    imports?: Record<string, Record<string, unknown>>,
  ) => Promise<unknown>;
  compile?: (bytes: Uint8Array) => Promise<unknown>;
}

export interface StreamingVerifierOptions {
  fetchImpl?: typeof fetch;
  runtime?: StreamingRuntimeLike;
  /** Per-request timeout in milliseconds; defaults to 10s. */
  timeoutMs?: number;
  /** Set false to skip timing and only inspect headers. */
  benchmark?: boolean;
}

const WASM_MIME = 'application/wasm';

function defaultRuntime(): StreamingRuntimeLike | undefined {
  return (globalThis as unknown as { WebAssembly?: StreamingRuntimeLike }).WebAssembly;
}

/** Whether the active runtime can compile from a response stream. */
export function supportsStreamingCompilation(
  runtime: StreamingRuntimeLike | undefined = defaultRuntime(),
): boolean {
  return typeof runtime?.instantiateStreaming === 'function';
}

function mimeType(contentType: string | undefined): string | undefined {
  const base = contentType?.split(';')[0]?.trim().toLowerCase();
  return base === undefined || base === '' ? undefined : base;
}

function round(ms: number): number {
  return Math.round(ms * 1000) / 1000;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isWasmBody(bytes: Uint8Array): boolean {
  return (
    bytes.length >= 4 &&
    bytes[0] === 0x00 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x73 &&
    bytes[3] === 0x6d
  );
}

async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([fetchImpl(url, { signal: controller.signal }), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class WasmStreamingVerifier {
  private readonly fetchImpl: typeof fetch;
  private readonly runtime: StreamingRuntimeLike | undefined;
  private readonly timeoutMs: number;
  private readonly benchmark: boolean;

  constructor(options: StreamingVerifierOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.runtime = options.runtime ?? defaultRuntime();
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.benchmark = options.benchmark ?? true;
  }

  /**
   * Pure header check, usable from a deployment manifest or a test without
   * issuing a request.
   */
  evaluateHeaders(contentType: string | undefined): StreamingFinding[] {
    const base = mimeType(contentType);
    if (base === undefined) {
      return [
        {
          code: 'streaming/missing-content-type',
          severity: 'error',
          subject: 'Content-Type',
          message: 'The response has no Content-Type header, so streaming compilation is disabled',
          suggestion: `Serve .wasm files with \`Content-Type: ${WASM_MIME}\`.`,
        },
      ];
    }
    if (base !== WASM_MIME) {
      return [
        {
          code: 'streaming/invalid-content-type',
          severity: 'error',
          subject: 'Content-Type',
          message: `Content-Type is "${base}"; streaming compilation requires "${WASM_MIME}"`,
          suggestion:
            base === 'application/octet-stream'
              ? `Stop the catch-all octet-stream mapping; send \`Content-Type: ${WASM_MIME}\` for .wasm.`
              : `Configure the server to send \`Content-Type: ${WASM_MIME}\` for .wasm files.`,
        },
      ];
    }
    return [];
  }

  async verify(url: string): Promise<StreamingVerificationResult> {
    let response: Response;
    try {
      response = await fetchWithTimeout(this.fetchImpl, url, this.timeoutMs);
    } catch (error) {
      return {
        ok: false,
        url,
        findings: [
          {
            code: 'streaming/unreachable',
            severity: 'error',
            subject: url,
            message: `Could not fetch ${url}: ${message(error)}`,
            suggestion: 'Check the URL is deployed and reachable from this host.',
          },
        ],
        benchmark: { supported: supportsStreamingCompilation(this.runtime), ran: false },
        fixes: renderStreamingFixes(),
      };
    }

    const contentType = response.headers.get('content-type') ?? undefined;
    const findings = this.evaluateHeaders(contentType);

    if (!response.ok) {
      findings.push({
        code: 'streaming/http-error',
        severity: 'error',
        subject: url,
        message: `${url} returned HTTP ${response.status}, so no module can be compiled`,
        suggestion: 'Point the check at the deployed .wasm asset URL.',
      });
    }

    let bytes = new Uint8Array(0);
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      findings.push({
        code: 'streaming/unreachable',
        severity: 'error',
        subject: url,
        message: `Could not read the response body: ${message(error)}`,
        suggestion: 'Retry the check; a truncated response cannot be benchmarked.',
      });
    }

    if (bytes.byteLength > 0 && !isWasmBody(bytes)) {
      findings.push({
        code: 'streaming/not-wasm',
        severity: 'error',
        subject: url,
        message: `${url} does not serve a WebAssembly binary (missing \\0asm magic)`,
        suggestion: 'Verify the URL points at the .wasm artifact and not an HTML error page.',
      });
    }

    const benchmark = await this.benchmarkCompilation(bytes, findings);

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      url,
      status: response.status,
      ...(contentType !== undefined ? { contentType } : {}),
      findings,
      benchmark,
      fixes: renderStreamingFixes(),
    };
  }

  private async benchmarkCompilation(
    bytes: Uint8Array,
    findings: StreamingFinding[],
  ): Promise<StreamingBenchmark> {
    const supported = supportsStreamingCompilation(this.runtime);
    if (!this.benchmark || bytes.byteLength === 0) {
      return { supported, ran: false };
    }
    if (!supported || this.runtime?.instantiateStreaming === undefined) {
      return { supported: false, ran: false };
    }

    try {
      const streamBody = new Response(
        bytes as unknown as ConstructorParameters<typeof Response>[0],
        { headers: { 'content-type': WASM_MIME } },
      );
      const streamStart = performance.now();
      await this.runtime.instantiateStreaming(streamBody, {});
      const streamingMs = round(performance.now() - streamStart);

      let bufferedMs: number | undefined;
      if (typeof this.runtime.instantiate === 'function') {
        const bufferStart = performance.now();
        await this.runtime.instantiate(bytes, {});
        bufferedMs = round(performance.now() - bufferStart);
      } else if (typeof this.runtime.compile === 'function') {
        const compileStart = performance.now();
        await this.runtime.compile(bytes);
        bufferedMs = round(performance.now() - compileStart);
      }

      return {
        supported: true,
        ran: true,
        streamingMs,
        ...(bufferedMs !== undefined ? { bufferedMs } : {}),
        ...(bufferedMs !== undefined && streamingMs > 0
          ? { speedup: round(bufferedMs / streamingMs) }
          : {}),
      };
    } catch (error) {
      findings.push({
        code: 'streaming/benchmark-failed',
        severity: 'warning',
        subject: 'benchmark',
        message: `Streaming compilation benchmark could not run: ${message(error)}`,
        suggestion:
          'The header check is still authoritative; benchmark in a browser with WebAssembly support.',
      });
      return { supported: true, ran: false, error: message(error) };
    }
  }
}

/** Copy-paste configuration for the hosts anchors most often deploy to. */
export function renderStreamingFixes(): string[] {
  return [
    'Nginx — map the .wasm extension in the server block:',
    '  types { application/wasm wasm; }',
    '  # a `default_type application/octet-stream` or a catch-all types block overrides it',
    'Apache — in .htaccess or the server config:',
    '  AddType application/wasm .wasm',
    'Cloudflare — Pages serves .wasm as application/wasm by default; for Rules or Workers:',
    '  respond with `Content-Type: application/wasm` and do not let a transform rule rewrite it',
  ];
}

export function renderStreamingReport(result: StreamingVerificationResult): string {
  const lines: string[] = [];
  const state = result.ok ? 'streaming-ready' : 'NOT streaming-ready';
  lines.push(
    `${result.url} — ${state}${result.status === undefined ? '' : ` (HTTP ${result.status})`}`,
  );
  lines.push(`  Content-Type: ${result.contentType ?? '(missing)'}`);
  lines.push(
    `  instantiateStreaming: ${result.benchmark.supported ? 'supported' : 'not available in this runtime'}`,
  );
  if (result.benchmark.ran) {
    const buffered =
      result.benchmark.bufferedMs === undefined ? 'n/a' : `${result.benchmark.bufferedMs}ms`;
    const speedup = result.benchmark.speedup === undefined ? '' : ` (${result.benchmark.speedup}x)`;
    lines.push(
      `  benchmark: streaming ${result.benchmark.streamingMs}ms vs buffered ${buffered}${speedup}`,
    );
  }
  if (result.findings.length > 0) {
    lines.push('');
    for (const finding of result.findings) {
      lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
      lines.push(`         fix: ${finding.suggestion}`);
    }
  }
  if (!result.ok) {
    lines.push('');
    lines.push('Configuration fixes:');
    for (const fix of result.fixes) lines.push(`  ${fix}`);
  }
  return `${lines.join('\n')}\n`;
}
