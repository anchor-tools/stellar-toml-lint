import { describe, expect, it } from 'vitest';
import {
  DEFAULT_OVERSIZED_BYTES,
  FALLBACK_BINARY_FIELDS,
  Sep12FileUploadValidator,
  sep12FileUploadRuleIds,
  testSep12FileUploads,
} from '../../src/protocols/sep12FileUpload.js';

const KYC_SERVER = 'https://kyc.example.com';
const DOC = { KYC_SERVER };
const TOKEN = 'jwt-token';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

type Verdict = { status: number; body?: unknown };

interface FormInfo {
  field: string;
  filename: string;
  type: string;
  size: number;
  account: string;
  authorization: string | undefined;
}

/** Inspects the multipart request and hands the caller a verdict. */
function uploadServer(
  verdict: (upload: FormInfo) => Verdict,
  options: { customer?: unknown; calls?: FormInfo[] } = {},
): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.pathname === '/customer') {
      return jsonResponse(
        options.customer ?? {
          fields: {
            photo_id_front: { type: 'binary', description: 'Photo ID' },
            email_address: { type: 'string' },
          },
        },
      );
    }
    if (url.pathname === '/customer/verification' && init?.method === 'PUT') {
      const body = init.body as FormData;
      const field = [...body.keys()].find((key) => key !== 'account') ?? '';
      const file = body.get(field) as File;
      const info: FormInfo = {
        field,
        filename: file.name,
        type: file.type,
        size: file.size,
        account: String(body.get('account')),
        authorization: new Headers(init.headers).get('authorization') ?? undefined,
      };
      if (options.calls) options.calls.push(info);
      const result = verdict(info);
      return jsonResponse(result.body ?? { error: 'invalid document' }, result.status);
    }
    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

function audit(fetchImpl: typeof fetch, options: Record<string, unknown> = {}) {
  return testSep12FileUploads(DOC, fetchImpl, {
    token: TOKEN,
    oversizedBytes: 2048,
    ...options,
  });
}

describe('SEP-12 upload helpers', () => {
  it('registers the upload rule ids', () => {
    expect(sep12FileUploadRuleIds).toEqual([
      'sep12/unsafe-upload-executable',
      'sep12/oversized-upload-accepted',
      'sep12/mime-type-spoofing',
      'sep12/valid-format-rejected',
      'sep12/upload-error-schema',
      'sep12/upload-server-error',
      'sep12/upload-unverifiable',
    ]);
    expect(DEFAULT_OVERSIZED_BYTES).toBe(6 * 1024 * 1024);
    expect(FALLBACK_BINARY_FIELDS).toContain('photo_id_front');
  });
});

describe('Sep12FileUploadValidator', () => {
  it('passes an anchor that rejects executables, oversized files and spoofing', async () => {
    const calls: FormInfo[] = [];
    const result = await audit(
      uploadServer(
        (upload) => {
          if (upload.filename.endsWith('.exe')) return { status: 400 };
          if (upload.size > 1024) return { status: 413 };
          return { status: 200 };
        },
        { calls },
      ),
    );
    expect(result.diagnostics).toEqual([]);
    expect(result.fields).toEqual(['photo_id_front']);
    expect(result.probes).toHaveLength(4);
    expect(calls[0]?.field).toBe('photo_id_front');
    expect(calls[0]?.account).toBeTypeOf('string');
    expect(calls[0]?.authorization).toBe(`Bearer ${TOKEN}`);
    expect(result.summary).toContain('advertised binary field');
  });

  it('errors when an executable is accepted', async () => {
    const result = await audit(uploadServer(() => ({ status: 200 })));
    const rules = result.diagnostics.map((d) => d.rule);
    expect(rules).toContain('sep12/unsafe-upload-executable');
    expect(
      result.diagnostics.find((d) => d.rule === 'sep12/unsafe-upload-executable')?.severity,
    ).toBe('error');
  });

  it('errors when an oversized upload is accepted', async () => {
    const result = await audit(
      uploadServer((upload) => (upload.size > 1024 ? { status: 200 } : { status: 400 })),
    );
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep12/oversized-upload-accepted');
    expect(result.diagnostics[0]?.message).toContain('MiB');
  });

  it('errors when a spoofed MIME type is accepted', async () => {
    const result = await audit(
      uploadServer((upload) =>
        upload.filename.endsWith('.exe') && upload.type === 'image/jpeg'
          ? { status: 200 }
          : { status: 400 },
      ),
    );
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep12/mime-type-spoofing');
  });

  it('warns when rejected uploads omit the SEP-12 error schema', async () => {
    const result = await audit(uploadServer(() => ({ status: 400, body: {} })));
    const schema = result.diagnostics.filter((d) => d.rule === 'sep12/upload-error-schema');
    expect(schema).toHaveLength(4);
    expect(schema[0]?.severity).toBe('warning');
  });

  it('warns when a valid PNG is rejected as unsupported', async () => {
    const result = await audit(
      uploadServer((upload) => (upload.filename === 'id.png' ? { status: 415 } : { status: 400 })),
    );
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep12/valid-format-rejected');
  });

  it('warns on a server error without accepting the upload', async () => {
    const result = await audit(uploadServer(() => ({ status: 500, body: 'boom' })));
    const rules = result.diagnostics.map((d) => d.rule);
    expect(rules).toContain('sep12/upload-server-error');
    expect(rules).not.toContain('sep12/unsafe-upload-executable');
  });

  it('falls back to standard binary fields when /customer advertises none', async () => {
    const result = await audit(
      uploadServer(() => ({ status: 400 }), {
        customer: { fields: { email: { type: 'string' } } },
      }),
    );
    expect(result.fields).toEqual([...FALLBACK_BINARY_FIELDS]);
  });

  it('requires a token', async () => {
    let called = 0;
    const result = await audit(
      (async () => {
        called++;
        return jsonResponse({});
      }) as unknown as typeof fetch,
      { token: undefined },
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep12/upload-unverifiable']);
    expect(called).toBe(0);
  });

  it('stays silent without a usable KYC_SERVER', async () => {
    const result = await testSep12FileUploads({ KYC_SERVER: 'http://insecure' }, fetch, {
      token: TOKEN,
    });
    expect(result.diagnostics).toEqual([]);
    expect(result.probes).toEqual([]);
  });

  it('reports an unreachable upload endpoint', async () => {
    const result = await audit((async (input: string | URL | Request) => {
      if (new URL(String(input)).pathname === '/customer') {
        return jsonResponse({ fields: { photo_id_front: { type: 'binary' } } });
      }
      throw new Error('offline');
    }) as unknown as typeof fetch);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep12/upload-unverifiable');
    expect(result.diagnostics[0]?.severity).toBe('info');
  });

  it('honours severity overrides', async () => {
    const result = await audit(
      uploadServer(() => ({ status: 200 })),
      {
        rules: {
          'sep12/unsafe-upload-executable': 'off',
          'sep12/oversized-upload-accepted': 'off',
          'sep12/mime-type-spoofing': 'off',
        },
      },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('works through the class with an injected oversized size', async () => {
    const result = await new Sep12FileUploadValidator(
      uploadServer((upload) => (upload.size > 16 ? { status: 200 } : { status: 400 })),
      { token: TOKEN, oversizedBytes: 32 },
    ).verify(DOC);
    expect(result.probes.find((probe) => probe.name === 'oversized')?.bytes).toBe(32);
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep12/oversized-upload-accepted']);
  });
});
