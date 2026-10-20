import { describe, expect, it, vi } from 'vitest';
import {
  checkHsts,
  INSUFFICIENT_HSTS_MAX_AGE_RULE,
  MISSING_HSTS_HEADER_RULE,
} from '../../src/security/hsts-auditor.js';

const doc = { TRANSFER_SERVER: 'https://anchor.example/sep6' };

function response(header?: string): Response {
  return new Response(null, {
    status: 200,
    headers: header === undefined ? {} : { 'strict-transport-security': header },
  });
}

describe('HSTS auditor', () => {
  it('accepts a one-year policy with includeSubDomains and preload', async () => {
    const fetchImpl = vi.fn(async () =>
      response('max-age=31536000; includeSubDomains; preload'),
    ) as unknown as typeof fetch;
    expect(await checkHsts(doc, fetchImpl)).toEqual([]);
  });

  it('reports a missing header as an error', async () => {
    const fetchImpl = vi.fn(async () => response()) as unknown as typeof fetch;
    const diagnostics = await checkHsts(doc, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: MISSING_HSTS_HEADER_RULE, severity: 'error' });
  });

  it('warns when max-age or required policy directives are incomplete', async () => {
    const fetchImpl = vi.fn(async () =>
      response('max-age=86400; includeSubDomains'),
    ) as unknown as typeof fetch;
    const diagnostics = await checkHsts(doc, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: INSUFFICIENT_HSTS_MAX_AGE_RULE,
      severity: 'warning',
    });
    expect(diagnostics[0]?.message).toContain('preload is missing');
  });
});
