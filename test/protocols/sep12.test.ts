import { describe, expect, it } from 'vitest';

import {
  verifySep12,
  BINARY_UPLOAD_UNSUPPORTED_RULE,
  INVALID_CUSTOMER_STATUS_RULE,
  MISSING_REQUIRED_KYC_FIELDS_RULE,
  sep12Rules,
} from '../../src/protocols/sep12.js';

const KYC_SERVER = 'https://kyc.example.com/sep12';

const DOC = { KYC_SERVER };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Routes {
  getCustomer?: (type: string) => Response;
  putCustomer?: (payload: Record<string, unknown>) => Response;
  putVerification?: (init: RequestInit) => Response;
}

function fetchServer(routes: Routes): typeof fetch {
  return (async (input: unknown, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = (init?.method ?? 'GET').toUpperCase();

    if (method === 'GET' && url.pathname.endsWith('/customer')) {
      const type = url.searchParams.get('type') ?? '';
      return (routes.getCustomer ?? (() => jsonResponse({ status: 'ACCEPTED' })))(type);
    }

    if (method === 'PUT' && url.pathname.endsWith('/customer')) {
      const payload =
        typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : {};
      return (routes.putCustomer ?? (() => jsonResponse({ id: 'cust-1', status: 'PROCESSING' })))(
        payload,
      );
    }

    if (method === 'PUT' && url.pathname.endsWith('/customer/verification')) {
      return (
        routes.putVerification ?? (() => jsonResponse({ id: 'cust-1', status: 'PROCESSING' }))
      )(init ?? {});
    }

    throw new Error(`unexpected request ${method} ${url}`);
  }) as unknown as typeof fetch;
}

describe('SEP-12 interactive KYC verification suite', () => {
  it('passes cleanly when the mock server adheres to SEP-12', async () => {
    const diagnostics = await verifySep12(DOC, fetchServer({}));
    expect(diagnostics).toEqual([]);
  });

  it('stays silent when KYC_SERVER is absent or not a URL', async () => {
    expect(await verifySep12({}, fetchServer({}))).toEqual([]);
    expect(await verifySep12({ KYC_SERVER: 'not a url' }, fetchServer({}))).toEqual([]);
    expect(await verifySep12({ KYC_SERVER: 'ftp://example.com' }, fetchServer({}))).toEqual([]);
  });

  it('asserts sep12/invalid-customer-status for an unknown status string', async () => {
    const diagnostics = await verifySep12(
      DOC,
      fetchServer({
        getCustomer: () => jsonResponse({ id: 'cust-1', status: 'WEIRD_STATUS' }),
      }),
    );

    const hits = diagnostics.filter((d) => d.rule === INVALID_CUSTOMER_STATUS_RULE);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]?.severity).toBe('error');
    expect(hits[0]?.message).toContain('WEIRD_STATUS');
    expect(hits[0]?.category).toBe('sep12');
  });

  it('asserts sep12/missing-required-kyc-fields on an incomplete NEEDS_INFO response', async () => {
    const diagnostics = await verifySep12(
      DOC,
      fetchServer({
        getCustomer: () =>
          jsonResponse({
            id: 'cust-1',
            status: 'NEEDS_INFO',
            fields: { first_name: { type: 'string' } },
          }),
      }),
    );

    const hits = diagnostics.filter((d) => d.rule === MISSING_REQUIRED_KYC_FIELDS_RULE);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe('warning');
    expect(hits[0]?.message).toContain('last_name');
    expect(hits[0]?.message).toContain('email_address');
    expect(hits[0]?.path).toBe('KYC_SERVER');
  });

  it('asserts sep12/binary-upload-unsupported when verification rejects multipart', async () => {
    const diagnostics = await verifySep12(
      DOC,
      fetchServer({
        putVerification: () =>
          jsonResponse({ error: 'unsupported content-type: application/json' }, 415),
      }),
    );

    const hits = diagnostics.filter((d) => d.rule === BINARY_UPLOAD_UNSUPPORTED_RULE);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe('error');
    expect(hits[0]?.message).toContain('multipart/form-data');
  });

  it('sends the multipart PUT with a binary body and no manual Content-Type header', async () => {
    let captured: RequestInit | undefined;

    await verifySep12(
      DOC,
      fetchServer({
        putVerification: (init) => {
          captured = init;
          return jsonResponse({ status: 'PROCESSING' });
        },
      }),
    );

    expect(captured).toBeDefined();
    expect(captured?.method).toBe('PUT');
    const body = captured?.body;
    expect(body).toBeInstanceOf(FormData);
    const form = body as FormData;
    const file = form.get('file');
    expect(file).toBeInstanceOf(Blob);
    expect((file as Blob).type).toBe('image/png');
    // We must let fetch generate the boundary - setting Content-Type manually
    // would break the multipart body.
    const headers = new Headers(captured?.headers);
    expect(headers.get('content-type')).toBeNull();
  });

  it('honours severity overrides on its rules', async () => {
    const broken = fetchServer({
      getCustomer: () => jsonResponse({ id: 'cust-1', status: 'WEIRD_STATUS' }),
    });

    const silenced = await verifySep12(DOC, broken, {
      rules: { [INVALID_CUSTOMER_STATUS_RULE]: 'off' },
    });
    expect(silenced.filter((d) => d.rule === INVALID_CUSTOMER_STATUS_RULE)).toEqual([]);

    const raised = await verifySep12(
      DOC,
      fetchServer({
        getCustomer: () =>
          jsonResponse({ status: 'NEEDS_INFO', fields: { first_name: { type: 'string' } } }),
      }),
      { rules: { [MISSING_REQUIRED_KYC_FIELDS_RULE]: 'error' } },
    );
    expect(raised[0]?.severity).toBe('error');
  });
});

describe('sep12Rules', () => {
  it('registers every diagnostic the suite can emit, all categorised as sep12', () => {
    const byId = new Map(sep12Rules.map((rule) => [rule.id, rule]));

    expect([...byId.keys()].sort()).toEqual(
      [
        INVALID_CUSTOMER_STATUS_RULE,
        MISSING_REQUIRED_KYC_FIELDS_RULE,
        BINARY_UPLOAD_UNSUPPORTED_RULE,
      ].sort(),
    );
    expect(byId.get(INVALID_CUSTOMER_STATUS_RULE)?.severity).toBe('error');
    expect(byId.get(MISSING_REQUIRED_KYC_FIELDS_RULE)?.severity).toBe('warning');
    expect(byId.get(BINARY_UPLOAD_UNSUPPORTED_RULE)?.severity).toBe('error');
    for (const rule of sep12Rules) expect(rule.category).toBe('sep12');
  });
});
