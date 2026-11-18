import { describe, expect, it } from 'vitest';
import {
  CrossOriginIsolationAuditor,
  normalizeHeaders,
  renderDeploymentGuide,
  renderIsolationReport,
} from '../../src/wasm/isolationAuditor.js';

const ISOLATED = {
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
};

describe('CrossOriginIsolationAuditor headers', () => {
  it('accepts a cross-origin isolated response', () => {
    const auditor = new CrossOriginIsolationAuditor();
    expect(auditor.evaluateHeaders(normalizeHeaders(ISOLATED))).toEqual([]);
  });

  it('accepts credentialless COEP', () => {
    const auditor = new CrossOriginIsolationAuditor();
    expect(
      auditor.evaluateHeaders({
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-embedder-policy': 'credentialless',
      }),
    ).toEqual([]);
  });

  it('reports missing COOP and COEP', () => {
    const auditor = new CrossOriginIsolationAuditor();
    const codes = auditor.evaluateHeaders({}).map((finding) => finding.code);
    expect(codes).toEqual(['isolation/missing-coop', 'isolation/missing-coep']);
  });

  it('rejects same-origin-allow-popups and unsafe-none COEP', () => {
    const auditor = new CrossOriginIsolationAuditor();
    const codes = auditor
      .evaluateHeaders({
        'cross-origin-opener-policy': 'same-origin-allow-popups',
        'cross-origin-embedder-policy': 'unsafe-none',
      })
      .map((finding) => finding.code);
    expect(codes).toEqual(['isolation/invalid-coop', 'isolation/invalid-coep']);
  });

  it('treats report-only headers as not enforcing isolation', () => {
    const auditor = new CrossOriginIsolationAuditor();
    const findings = auditor.evaluateHeaders({
      'cross-origin-embedder-policy-report-only': 'require-corp',
      'cross-origin-opener-policy': 'same-origin',
    });
    expect(findings.some((finding) => finding.code === 'isolation/missing-coep')).toBe(true);
  });
});

describe('CrossOriginIsolationAuditor resources', () => {
  const auditor = new CrossOriginIsolationAuditor();
  const crossOrigin = {
    url: 'https://cdn.example.net/app.js',
    origin: 'https://cdn.example.net',
    crossOrigin: true,
    ok: true,
  };

  it('requires CORP on cross-origin assets', () => {
    expect(auditor.evaluateResource(crossOrigin, 'require-corp')[0]?.code).toBe(
      'isolation/missing-corp',
    );
  });

  it('accepts a valid CORP and rejects an invalid one', () => {
    expect(
      auditor.evaluateResource({ ...crossOrigin, corp: 'cross-origin' }, 'require-corp'),
    ).toEqual([]);
    expect(
      auditor.evaluateResource({ ...crossOrigin, corp: 'bogus' }, 'require-corp')[0]?.code,
    ).toBe('isolation/invalid-corp');
  });

  it('does not require CORP for same-origin resources or credentialless COEP', () => {
    expect(
      auditor.evaluateResource({ ...crossOrigin, crossOrigin: false }, 'require-corp'),
    ).toEqual([]);
    expect(auditor.evaluateResource(crossOrigin, 'credentialless')).toEqual([]);
  });
});

describe('CrossOriginIsolationAuditor.audit', () => {
  const html = `<html><head><script src="/app.js"></script>
    <script src="https://cdn.example.net/lib.js"></script></head></html>`;

  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes('/boom')) throw new Error('connection refused');
    if (url.endsWith('lib.js')) {
      return new Response('x', { headers: { 'cross-origin-resource-policy': 'cross-origin' } });
    }
    if (url.endsWith('app.js')) return new Response('x');
    return new Response(html, {
      headers: { ...ISOLATED, 'content-type': 'text/html' },
    });
  }) as unknown as typeof fetch;

  it('reports an isolated page with compliant embedded assets', async () => {
    const report = await new CrossOriginIsolationAuditor({ fetchImpl }).audit(
      'https://studio.example.com/',
    );
    expect(report.ok).toBe(true);
    expect(report.resources).toHaveLength(2);
    expect(renderIsolationReport(report)).toContain('cross-origin isolated');
    expect(renderDeploymentGuide().join('\n')).toContain('Cross-Origin-Embedder-Policy');
  });

  it('reports an unreachable app', async () => {
    const report = await new CrossOriginIsolationAuditor({ fetchImpl }).audit(
      'https://studio.example.com/boom',
    );
    expect(report.ok).toBe(false);
    expect(report.findings[0]?.code).toBe('isolation/unreachable');
  });
});
