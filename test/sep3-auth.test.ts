import { describe, expect, it } from 'vitest';
import { checkSep3Auth, sep3Rules } from '../src/rules/sep3-auth.js';

const AUTH_SERVER = 'https://compliance.example.com/sep3';

function response(status = 200, cors = '*'): Response {
  return new Response(null, {
    status,
    headers: cors === '' ? {} : { 'access-control-allow-origin': cors },
  });
}

function fetchReturning(result: Response | Promise<Response>): typeof fetch {
  return (async () => result) as unknown as typeof fetch;
}

describe('checkSep3Auth', () => {
  it('passes when the endpoint returns 200 with CORS headers', async () => {
    const diagnostics = await checkSep3Auth({ AUTH_SERVER }, fetchReturning(response()));

    expect(diagnostics).toEqual([]);
  });

  it('sends the SEP-3 POST handshake with a browser origin', async () => {
    let request: RequestInit | undefined;
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      request = init;
      return response();
    }) as unknown as typeof fetch;

    await checkSep3Auth({ AUTH_SERVER }, fetchImpl);

    expect(request?.method).toBe('POST');
    expect(new Headers(request?.headers).get('content-type')).toBe(
      'application/x-www-form-urlencoded',
    );
    expect(new Headers(request?.headers).get('origin')).toBe('https://stellar-toml-lint.invalid');
    expect(String(request?.body)).toBe('data=&sig=');
  });

  it('reports sep3/missing-cors-headers when the response omits CORS', async () => {
    const diagnostics = await checkSep3Auth({ AUTH_SERVER }, fetchReturning(response(200, '')));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'sep3/missing-cors-headers',
      severity: 'error',
      category: 'network',
      path: 'AUTH_SERVER',
    });
  });

  it('reports sep3/auth-server-unreachable when the request times out', async () => {
    const fetchImpl = (async () => {
      throw new Error('The operation timed out');
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep3Auth({ AUTH_SERVER }, fetchImpl);

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'sep3/auth-server-unreachable',
      severity: 'error',
      path: 'AUTH_SERVER',
    });
    expect(diagnostics[0]?.message).toContain('timed out');
  });

  it('accepts every status code defined by SEP-3 when CORS is present', async () => {
    for (const status of [200, 202, 400, 403, 500]) {
      await expect(
        checkSep3Auth({ AUTH_SERVER }, fetchReturning(response(status))),
      ).resolves.toEqual([]);
    }
  });

  it('reports sep3/auth-server-unreachable for an invalid status code', async () => {
    const diagnostics = await checkSep3Auth({ AUTH_SERVER }, fetchReturning(response(404)));

    expect(diagnostics[0]?.rule).toBe('sep3/auth-server-unreachable');
    expect(diagnostics[0]?.message).toContain('HTTP 404');
  });

  it('does not request an endpoint that is not HTTPS', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return response();
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep3Auth(
      { AUTH_SERVER: 'http://compliance.example.com/sep3' },
      fetchImpl,
    );

    expect(diagnostics[0]?.rule).toBe('sep3/auth-server-unreachable');
    expect(calls).toBe(0);
  });

  it('stays silent without AUTH_SERVER', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return response();
    }) as unknown as typeof fetch;

    await expect(checkSep3Auth({}, fetchImpl)).resolves.toEqual([]);
    expect(calls).toBe(0);
  });
});

describe('sep3Rules', () => {
  it('registers the required network rule ids with error severity', () => {
    expect(sep3Rules.map((rule) => ({ id: rule.id, severity: rule.severity }))).toEqual([
      { id: 'sep3/auth-server-unreachable', severity: 'error' },
      { id: 'sep3/missing-cors-headers', severity: 'error' },
    ]);
  });
});
