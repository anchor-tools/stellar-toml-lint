import { describe, expect, it } from 'vitest';
import {
  WasmStreamingVerifier,
  renderStreamingFixes,
  renderStreamingReport,
  supportsStreamingCompilation,
  type StreamingRuntimeLike,
} from '../../src/wasm/streamingVerifier.js';

const WASM = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

type ResponseBody = ConstructorParameters<typeof Response>[0];

function wasmResponse(bytes: Uint8Array, init: ResponseInit = {}): Response {
  return new Response(bytes as unknown as ResponseBody, init);
}

const fetchImpl = (async (input: string | URL | Request) => {
  const url = String(input);
  if (url.includes('boom')) throw new Error('connection refused');
  if (url.includes('missing-mime')) return wasmResponse(WASM);
  if (url.includes('octet')) {
    return wasmResponse(WASM, { headers: { 'content-type': 'application/octet-stream' } });
  }
  if (url.includes('not-wasm')) {
    return new Response('<html></html>', { headers: { 'content-type': 'application/wasm' } });
  }
  if (url.includes('gone')) {
    return wasmResponse(WASM, { status: 404, headers: { 'content-type': 'application/wasm' } });
  }
  return wasmResponse(WASM, {
    headers: { 'content-type': 'application/wasm; charset=binary' },
  });
}) as unknown as typeof fetch;

const runtime: StreamingRuntimeLike = {
  instantiateStreaming: async () => ({}),
  instantiate: async () => ({}),
};

describe('WasmStreamingVerifier headers', () => {
  const verifier = new WasmStreamingVerifier();

  it('accepts application/wasm with parameters', () => {
    expect(verifier.evaluateHeaders('application/wasm')).toEqual([]);
    expect(verifier.evaluateHeaders('APPLICATION/WASM; charset=binary')).toEqual([]);
  });

  it('reports a missing content type', () => {
    expect(verifier.evaluateHeaders(undefined).map((finding) => finding.code)).toEqual([
      'streaming/missing-content-type',
    ]);
  });

  it('reports octet-stream and other MIME types', () => {
    const octet = verifier.evaluateHeaders('application/octet-stream');
    expect(octet[0]?.code).toBe('streaming/invalid-content-type');
    expect(octet[0]?.message).toContain('application/octet-stream');
    expect(verifier.evaluateHeaders('text/plain')[0]?.code).toBe('streaming/invalid-content-type');
  });
});

describe('WasmStreamingVerifier.verify', () => {
  it('passes a streaming-ready asset and benchmarks both paths', async () => {
    const result = await new WasmStreamingVerifier({ fetchImpl, runtime }).verify(
      'https://cdn.example.com/linter.wasm',
    );
    expect(result.ok).toBe(true);
    expect(result.contentType).toContain('application/wasm');
    expect(result.benchmark.supported).toBe(true);
    expect(result.benchmark.ran).toBe(true);
    expect(result.benchmark.streamingMs).toBeTypeOf('number');
    expect(result.benchmark.bufferedMs).toBeTypeOf('number');
    expect(renderStreamingReport(result)).toContain('streaming-ready');
  });

  it('fails an octet-stream asset and prints platform fixes', async () => {
    const result = await new WasmStreamingVerifier({ fetchImpl, runtime }).verify(
      'https://cdn.example.com/octet.wasm',
    );
    expect(result.ok).toBe(false);
    expect(result.findings[0]?.code).toBe('streaming/invalid-content-type');
    const fixes = renderStreamingFixes().join('\n');
    expect(fixes).toContain('Nginx');
    expect(fixes).toContain('Apache');
    expect(fixes).toContain('Cloudflare');
    expect(renderStreamingReport(result)).toContain('Configuration fixes');
  });

  it('reports an unreachable URL', async () => {
    const result = await new WasmStreamingVerifier({ fetchImpl }).verify(
      'https://cdn.example.com/boom.wasm',
    );
    expect(result.ok).toBe(false);
    expect(result.findings[0]?.code).toBe('streaming/unreachable');
    expect(result.benchmark.ran).toBe(false);
  });

  it('reports an HTTP error and a non-WASM body separately', async () => {
    const missing = await new WasmStreamingVerifier({ fetchImpl }).verify(
      'https://cdn.example.com/gone.wasm',
    );
    expect(missing.ok).toBe(false);
    expect(missing.findings.map((finding) => finding.code)).toContain('streaming/http-error');

    const html = await new WasmStreamingVerifier({ fetchImpl }).verify(
      'https://cdn.example.com/not-wasm.wasm',
    );
    expect(html.findings.map((finding) => finding.code)).toContain('streaming/not-wasm');
  });

  it('degrades gracefully when the runtime has no streaming support', async () => {
    const result = await new WasmStreamingVerifier({ fetchImpl, runtime: {} }).verify(
      'https://cdn.example.com/linter.wasm',
    );
    expect(result.ok).toBe(true);
    expect(result.benchmark).toEqual({ supported: false, ran: false });
    expect(supportsStreamingCompilation({})).toBe(false);
  });

  it('keeps the header verdict when the benchmark cannot compile', async () => {
    const broken: StreamingRuntimeLike = {
      instantiateStreaming: async () => {
        throw new Error('CompileError: bad bytecode');
      },
    };
    const result = await new WasmStreamingVerifier({ fetchImpl, runtime: broken }).verify(
      'https://cdn.example.com/linter.wasm',
    );
    expect(result.ok).toBe(true);
    expect(result.benchmark.ran).toBe(false);
    expect(result.findings[0]?.code).toBe('streaming/benchmark-failed');
    expect(result.findings[0]?.severity).toBe('warning');
  });
});
