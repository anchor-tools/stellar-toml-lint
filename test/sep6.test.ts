import { describe, expect, it } from 'vitest';
import { checkSep6, sep6Rules, verifySep6Info } from '../src/cross-sep/sep6.js';

const TRANSFER_SERVER = 'https://api.example.com/sep6';
const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

const DOC = {
  TRANSFER_SERVER,
  CURRENCIES: [{ code: 'USDX', issuer: ISSUER }],
};

function jsonResponse(body: unknown, status = 200, contentType = 'application/json'): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': contentType },
  });
}

function fetchInfo(handler: () => Response | Promise<Response>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), ...(init ? { init } : {}) });
    return handler();
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

/** A `/info` body advertising USDX for both deposit and withdraw. */
const VALID_INFO = {
  deposit: { USDX: { enabled: true } },
  withdraw: { USDX: { enabled: true } },
};

describe('checkSep6', () => {
  it('passes when /info advertises every declared currency', async () => {
    const { fetchImpl } = fetchInfo(() => jsonResponse(VALID_INFO));
    expect(await checkSep6(DOC, fetchImpl)).toEqual([]);
  });

  it('GETs <TRANSFER_SERVER>/info with redirects followed', async () => {
    const { fetchImpl, calls } = fetchInfo(() => jsonResponse(VALID_INFO));
    await checkSep6(DOC, fetchImpl);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${TRANSFER_SERVER}/info`);
    expect(calls[0]?.init?.redirect).toBe('follow');
  });

  it('warns when a declared currency is missing from both maps', async () => {
    const { fetchImpl } = fetchInfo(() =>
      jsonResponse({ deposit: { USD: {} }, withdraw: { EUR: {} } }),
    );

    const diagnostics = await checkSep6(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'network/sep6-missing-asset',
      severity: 'warning',
      category: 'network',
      path: 'CURRENCIES',
    });
    expect(diagnostics[0]?.message).toContain('USDX');
  });

  it('accepts an asset keyed by CODE:issuer', async () => {
    const { fetchImpl } = fetchInfo(() =>
      jsonResponse({ deposit: { [`USDX:${ISSUER}`]: {} }, withdraw: {} }),
    );
    expect(await checkSep6(DOC, fetchImpl)).toEqual([]);
  });

  it('warns (without throwing) when /info answers 500', async () => {
    const { fetchImpl } = fetchInfo(() => jsonResponse({ error: 'boom' }, 500));

    const diagnostics = await checkSep6(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: 'network/sep6-info-error', severity: 'warning' });
    expect(diagnostics[0]?.message).toContain('HTTP 500');
  });

  it('warns when the transport fails', async () => {
    const fetchImpl = (async () => {
      throw new Error('connect ECONNREFUSED');
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep6(DOC, fetchImpl);
    expect(diagnostics[0]?.rule).toBe('network/sep6-info-error');
    expect(diagnostics[0]?.message).toContain('ECONNREFUSED');
  });

  it('warns when /info is served as HTML', async () => {
    const { fetchImpl } = fetchInfo(
      () =>
        new Response('<html>portal</html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        }),
    );

    const diagnostics = await checkSep6(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('network/sep6-info-malformed');
  });

  it('warns when /info omits both the deposit and withdraw maps', async () => {
    const { fetchImpl } = fetchInfo(() => jsonResponse({ assets: [] }));

    const diagnostics = await checkSep6(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('network/sep6-info-malformed');
    expect(diagnostics[0]?.message).toContain('deposit');
  });

  it('skips the native asset when cross-referencing', async () => {
    const { fetchImpl } = fetchInfo(() => jsonResponse({ deposit: {}, withdraw: {} }));

    const diagnostics = await checkSep6(
      { TRANSFER_SERVER, CURRENCIES: [{ code: 'native' }] },
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('stays silent without a usable TRANSFER_SERVER', async () => {
    const { fetchImpl, calls } = fetchInfo(() => jsonResponse(VALID_INFO));

    expect(await checkSep6({ CURRENCIES: DOC.CURRENCIES }, fetchImpl)).toEqual([]);
    expect(await checkSep6({ ...DOC, TRANSFER_SERVER: 'not a url' }, fetchImpl)).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it('honours --off for network/sep6-missing-asset', async () => {
    const { fetchImpl } = fetchInfo(() => jsonResponse({ deposit: {}, withdraw: {} }));

    const diagnostics = await checkSep6(DOC, fetchImpl, {
      rules: { 'network/sep6-missing-asset': 'off' },
    });
    expect(diagnostics).toEqual([]);
  });
});

describe('verifySep6Info', () => {
  it('cross-references the currencies it is handed', async () => {
    const { fetchImpl } = fetchInfo(() => jsonResponse(VALID_INFO));
    const diagnostics = await verifySep6Info(
      TRANSFER_SERVER,
      [{ code: 'EUR', issuer: ISSUER }],
      fetchImpl,
    );
    expect(diagnostics[0]).toMatchObject({ rule: 'network/sep6-missing-asset' });
  });

  it('trims a trailing slash before appending /info', async () => {
    const { fetchImpl, calls } = fetchInfo(() => jsonResponse(VALID_INFO));
    await verifySep6Info(`${TRANSFER_SERVER}/`, [{ code: 'USDX', issuer: ISSUER }], fetchImpl);
    expect(calls[0]?.url).toBe(`${TRANSFER_SERVER}/info`);
  });
});

describe('sep6Rules', () => {
  it('registers the rule ids with warning severity', () => {
    expect(sep6Rules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: 'network/sep6-info-error', severity: 'warning' },
      { id: 'network/sep6-info-malformed', severity: 'warning' },
      { id: 'network/sep6-missing-asset', severity: 'warning' },
    ]);
  });
});
