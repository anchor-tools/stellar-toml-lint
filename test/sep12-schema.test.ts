import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { allRules } from '../src/rules/index.js';
import {
  SEP9_KYC_FIELDS,
  checkSep12Schema,
  isValidCustomerType,
  sep12Rules,
} from '../src/rules/sep12-schema.js';

const KYC_SERVER = 'https://kyc.example.com';

const DOC = { KYC_SERVER };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function fetchReturning(body: unknown, status = 200): typeof fetch {
  return (async () => jsonResponse(body, status)) as unknown as typeof fetch;
}

function rulesOf(diagnostics: { rule: string }[]): string[] {
  return diagnostics.map((d) => d.rule);
}

/** A schema whose required fields are exactly the four canonical SEP-9 names. */
function validSchema(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'sep31-sender',
    status: 'NEEDS_INFO',
    fields: {
      first_name: { type: 'string', description: 'Given name' },
      last_name: { type: 'string', description: 'Family name' },
      email_address: { type: 'string', description: 'Email address' },
      id_country_code: { type: 'string', description: 'ISO 3166-1 alpha-3 issuing country' },
    },
    ...overrides,
  };
}

describe('SEP-9 field table', () => {
  it('includes the canonical names the issue calls out', () => {
    for (const field of ['first_name', 'last_name', 'email_address', 'id_country_code']) {
      expect(SEP9_KYC_FIELDS.has(field)).toBe(true);
    }
  });

  it('accepts SEP-9 dot notation for organization and card fields', () => {
    expect(SEP9_KYC_FIELDS.has('organization.name')).toBe(true);
    expect(SEP9_KYC_FIELDS.has('card.number')).toBe(true);
  });
});

describe('customer type syntax', () => {
  it.each(['sep31-sender', 'sep31-receiver', 'sep6-deposit', 'counterparty_organization'])(
    'accepts "%s"',
    (type) => {
      expect(isValidCustomerType(type)).toBe(true);
    },
  );

  it.each(['SEP31-SENDER', 'sep31 sender', '31sender', 'sep31--sender', '-sep31', ''])(
    'rejects "%s"',
    (type) => {
      expect(isValidCustomerType(type)).toBe(false);
    },
  );
});

describe('checkSep12Schema', () => {
  it('passes when the schema requires standard SEP-9 fields', async () => {
    const diagnostics = await checkSep12Schema(DOC, fetchReturning(validSchema()));
    expect(diagnostics).toEqual([]);
  });

  it('passes for every documented customer type', async () => {
    for (const type of ['sep31-receiver', 'sep6-deposit', 'sep6-withdrawal']) {
      const diagnostics = await checkSep12Schema(DOC, fetchReturning(validSchema({ type })));
      expect(diagnostics).toEqual([]);
    }
  });

  it('warns on a non-standard field name', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning(
        validSchema({
          fields: {
            first_name: { type: 'string' },
            phone_number: { type: 'string' },
          },
        }),
      ),
    );

    expect(rulesOf(diagnostics)).toContain('sep12/unknown-kyc-field-name');
    const [d] = diagnostics.filter((x) => x.rule === 'sep12/unknown-kyc-field-name');
    expect(d?.severity).toBe('warning');
    expect(d?.message).toContain('phone_number');
    expect(d?.message).toContain('SEP-9');
    expect(d?.category).toBe('sep12');
    expect(d?.path).toBe('KYC_SERVER');
    expect(d?.helpUri).toContain('sep-0009');
    expect(d?.suggestion).toBeTruthy();
  });

  it('errors on invalid customer-type syntax', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning(validSchema({ type: 'SEP31 Sender' })),
    );

    expect(rulesOf(diagnostics)).toContain('sep12/invalid-customer-type-syntax');
    const [d] = diagnostics.filter((x) => x.rule === 'sep12/invalid-customer-type-syntax');
    expect(d?.severity).toBe('error');
    expect(d?.message).toContain('SEP31 Sender');
    expect(d?.helpUri).toContain('sep-0012');
    expect(d?.suggestion).toContain('sep31-sender');
  });

  it('validates provided_fields keys as well', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning(
        validSchema({
          status: 'ACCEPTED',
          fields: {},
          provided_fields: {
            first_name: { type: 'string', status: 'ACCEPTED' },
            drivers_licence_number: { type: 'string', status: 'ACCEPTED' },
          },
        }),
      ),
    );

    expect(rulesOf(diagnostics)).toEqual(['sep12/unknown-kyc-field-name']);
    expect(diagnostics[0]?.message).toContain('drivers_licence_number');
  });

  it('validates a multi-type declaration keyed by type name', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning({
        types: {
          'sep31-sender': { fields: ['first_name', 'last_name', 'email_address'] },
          'sep31-receiver': { fields: ['first_name', 'bank_account_number', 'bank_name'] },
        },
      }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('reports unknown fields inside a multi-type declaration', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning({
        types: {
          'sep31-sender': { fields: ['first_name', 'full_legal_name'] },
        },
      }),
    );

    expect(rulesOf(diagnostics)).toEqual(['sep12/unknown-kyc-field-name']);
    expect(diagnostics[0]?.message).toContain('sep31-sender');
    expect(diagnostics[0]?.message).toContain('full_legal_name');
  });

  it('reports invalid type names inside a multi-type declaration', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning({
        types: {
          'SEP31 Sender': { fields: ['first_name'] },
        },
      }),
    );

    expect(rulesOf(diagnostics)).toEqual(['sep12/invalid-customer-type-syntax']);
  });

  it('validates an array-form types declaration', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning({
        types: [
          { type: 'sep31-sender', fields: ['first_name', 'last_name'] },
          { type: 'bad type', fields: ['fname'] },
        ],
      }),
    );

    expect(rulesOf(diagnostics).sort()).toEqual([
      'sep12/invalid-customer-type-syntax',
      'sep12/unknown-kyc-field-name',
    ]);
  });

  it('queries KYC_SERVER/customer', async () => {
    let requested = '';
    const fetchImpl = (async (url: string | URL | globalThis.Request) => {
      requested = url.toString();
      return jsonResponse(validSchema());
    }) as unknown as typeof fetch;

    await checkSep12Schema(DOC, fetchImpl);
    expect(requested).toBe(`${KYC_SERVER}/customer`);
  });

  it('normalises a trailing slash on KYC_SERVER', async () => {
    let requested = '';
    const fetchImpl = (async (url: string | URL | globalThis.Request) => {
      requested = url.toString();
      return jsonResponse(validSchema());
    }) as unknown as typeof fetch;

    await checkSep12Schema({ KYC_SERVER: `${KYC_SERVER}/` }, fetchImpl);
    expect(requested).toBe(`${KYC_SERVER}/customer`);
  });

  it('is silent when the file declares no KYC_SERVER', async () => {
    let called = 0;
    const fetchImpl = (async () => {
      called++;
      return jsonResponse(validSchema());
    }) as unknown as typeof fetch;

    expect(await checkSep12Schema({}, fetchImpl)).toEqual([]);
    expect(called).toBe(0);
  });

  it('is silent when KYC_SERVER is not a usable URL', async () => {
    expect(
      await checkSep12Schema({ KYC_SERVER: 'not a url' }, fetchReturning(validSchema())),
    ).toEqual([]);
  });

  it('is silent when the endpoint is unreachable or rejects the probe', async () => {
    const throwing = (async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;
    expect(await checkSep12Schema(DOC, throwing)).toEqual([]);

    // 401 is the expected answer without a SEP-10 JWT — not a schema finding.
    expect(await checkSep12Schema(DOC, fetchReturning(validSchema(), 401))).toEqual([]);
    expect(await checkSep12Schema(DOC, fetchReturning(validSchema(), 500))).toEqual([]);
  });

  it('is silent when the response is not a JSON object', async () => {
    expect(await checkSep12Schema(DOC, fetchReturning('<html>nope</html>', 200))).toEqual([]);
    expect(await checkSep12Schema(DOC, fetchReturning([1, 2, 3]))).toEqual([]);
    expect(await checkSep12Schema(DOC, fetchReturning('plain'))).toEqual([]);
  });

  it('honours --off', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning(validSchema({ type: 'BAD TYPE', fields: { fname: { type: 'string' } } })),
      { rules: { 'sep12/unknown-kyc-field-name': 'off' } },
    );
    expect(rulesOf(diagnostics)).toEqual(['sep12/invalid-customer-type-syntax']);
  });

  it('honours a severity override', async () => {
    const diagnostics = await checkSep12Schema(
      DOC,
      fetchReturning(validSchema({ fields: { fname: { type: 'string' } } })),
      { rules: { 'sep12/unknown-kyc-field-name': 'error' } },
    );
    expect(diagnostics[0]?.severity).toBe('error');
  });
});

describe('offline linting', () => {
  it('never emits sep12 diagnostics from lint(), even with checkNetwork', () => {
    const source = ['VERSION="2.7.0"', 'KYC_SERVER="https://kyc.example.com"'].join('\n');

    for (const options of [{}, { checkNetwork: true }]) {
      const result = lint(source, options);
      expect(rulesOf(result.diagnostics)).not.toContain('sep12/unknown-kyc-field-name');
      expect(rulesOf(result.diagnostics)).not.toContain('sep12/invalid-customer-type-syntax');
    }
  });

  it('registers both rules so --list-rules and --off know them', () => {
    const ids = allRules.map((r) => r.id);
    expect(ids).toContain('sep12/unknown-kyc-field-name');
    expect(ids).toContain('sep12/invalid-customer-type-syntax');
    expect(sep12Rules.map((r) => r.id)).toEqual([
      'sep12/unknown-kyc-field-name',
      'sep12/invalid-customer-type-syntax',
    ]);
  });
});
