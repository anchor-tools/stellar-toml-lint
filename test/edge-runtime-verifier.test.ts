import { describe, expect, it } from 'vitest';
import {
  EDGE_WEB_APIS,
  EdgeRuntimeVerifier,
  checkEdgeWebApis,
  createEdgeIsolateScope,
  readEdgeStream,
  verifyEdgeCompatibility,
} from '../src/wasm/edgeRuntimeVerifier.js';

const CLEAN_MODULE = `
import { lint } from './lint.js';
export default { fetch: (request) => new Response(lint('VERSION="2.0.0"').ok) };
`;

describe('static edge compatibility scan', () => {
  it('accepts a module that only uses Web APIs', () => {
    const verifier = new EdgeRuntimeVerifier();
    expect(verifier.checkSource(CLEAN_MODULE)).toEqual([]);
  });

  it('rejects eval and new Function', () => {
    const verifier = new EdgeRuntimeVerifier();
    const findings = verifier.checkSource(`eval('1'); const f = new Function('return 1');`);
    expect(findings.filter((finding) => finding.code === 'edge/dynamic-code')).toHaveLength(2);
    expect(findings.every((finding) => finding.severity === 'error')).toBe(true);
  });

  it('rejects Node built-in imports and require', () => {
    const verifier = new EdgeRuntimeVerifier();
    const findings = verifier.checkSource(`import fs from 'node:fs';\nconst os = require('os');`);
    expect(findings.some((finding) => finding.code === 'edge/node-builtin')).toBe(true);
  });

  it('flags Node-only globals', () => {
    const verifier = new EdgeRuntimeVerifier();
    const findings = verifier.checkSource(`const cwd = process.cwd();`);
    expect(findings[0]?.code).toBe('edge/node-global');
    expect(findings[0]?.message).toContain('process');
  });
});

describe('isolate scope and Web APIs', () => {
  it('exposes the standard edge surface', () => {
    const availability = checkEdgeWebApis();
    for (const name of EDGE_WEB_APIS) expect(availability[name]).toBeTypeOf('boolean');
    expect(availability.fetch).toBe(true);
    expect(availability.Response).toBe(true);
    expect(Object.keys(createEdgeIsolateScope())).toContain('ReadableStream');
  });

  it('reads a streaming response chunk by chunk', async () => {
    const response = new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('VERSION='));
          controller.enqueue(new TextEncoder().encode('"2.0.0"'));
          controller.close();
        },
      }),
    );
    await expect(readEdgeStream(response)).resolves.toBe('VERSION="2.0.0"');
  });
});

describe('EdgeRuntimeVerifier.verify', () => {
  it('reports a compatible module with a measured cold start', () => {
    const result = verifyEdgeCompatibility(CLEAN_MODULE);
    expect(result.compatible).toBe(true);
    expect(result.benchmark.coldStartMs).toBeGreaterThanOrEqual(0);
    expect(result.webApis.fetch).toBe(true);
  });

  it('warns when the cold-start budget is exceeded', () => {
    const verifier = new EdgeRuntimeVerifier({
      thresholds: { maxColdStartMs: 0 },
      lintImpl: () => {
        const start = Date.now();
        while (Date.now() - start < 2) {
          // burn the budget on purpose
        }
        return { diagnostics: [], ok: true, counts: { error: 0, warning: 0, info: 0 } };
      },
    });
    const result = verifier.verify(CLEAN_MODULE);
    expect(result.findings.some((finding) => finding.code === 'edge/cold-start-budget')).toBe(true);
    expect(result.compatible).toBe(true);
  });

  it('does not throw when heap usage cannot be measured', () => {
    const result = verifyEdgeCompatibility(CLEAN_MODULE, {
      lintImpl: () => ({ diagnostics: [], ok: true, counts: { error: 0, warning: 0, info: 0 } }),
    });
    expect(result.findings.every((finding) => finding.code !== 'edge/heap-budget')).toBe(true);
  });
});
