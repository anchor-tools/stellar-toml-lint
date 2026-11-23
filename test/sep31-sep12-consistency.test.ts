import { describe, expect, it } from 'vitest';
import { allRules } from '../src/rules/index.js';
import {
  collectCustomerTypes,
  canonicalSep9Type,
  extractSep31Corridors,
  parseSep12CustomerSchema,
  renderSep31Sep12Report,
  sep31Sep12Rules,
  Sep31Sep12ConsistencyEngine,
  type SchemaLookup,
  type Sep12SchemaResult,
  verifySep31Sep12,
} from '../src/protocols/sep31Sep12Consistency.js';

const DIRECT = 'https://anchor.example.com/sep31';
const KYC = 'https://anchor.example.com/kyc';

const INFO: any = {
  receive: {
    USDC: {
      sep12: {
        sender: {
          types: {
            'sep31-sender': { description: 'Individual sending money' },
          },
        },
        receiver: {
          types: {
            'sep31-receiver': { description: 'Individual receiving money' },
          },
        },
      },
      fields: {
        transaction: {
          routing_number: {
            description: 'ABA routing number of the receiving bank',
            optional: false,
          },
          reference: { description: 'Sender reference', optional: true },
        },
      },
    },
  },
};

const SENDER_SCHEMA: any = {
  type: 'sep31-sender',
  status: 'NEEDS_INFO',
  fields: {
    first_name: { type: 'string', description: 'Given name' },
    birth_date: { type: 'date', description: 'Date of birth' },
    id_number: { type: 'string', description: 'ID number' },
    postal_code: { type: 'string', description: 'Postal code' },
    routing_number: {
      type: 'string',
      description: 'ABA routing number of the receiving bank',
      optional: false,
    },
    reference: {
      type: 'string',
      description: 'Sender reference',
      optional: true,
    },
  },
};

const RECEIVER_SCHEMA: any = {
  type: 'sep31-receiver',
  status: 'NEEDS_INFO',
  fields: {
    first_name: { type: 'string', description: 'Given name' },
    bank_account_number: { type: 'string', description: 'Bank account number' },
    routing_number: {
      type: 'string',
      description: 'ABA routing number of the receiving bank',
      optional: false,
    },
    reference: {
      type: 'string',
      description: 'Sender reference',
      optional: true,
    },
  },
};

function lookupOf(entries: Record<string, unknown>): SchemaLookup {
  const map = new Map<string, Sep12SchemaResult>();
  for (const [type, body] of Object.entries(entries)) {
    if (body instanceof Error) {
      map.set(type, { error: body.message });
    } else {
      const schema = parseSep12CustomerSchema(body, type);
      map.set(type, schema === undefined ? { error: 'not an object' } : { schema });
    }
  }
  return map;
}

function rulesOf(discrepancies: { rule: string }[]): string[] {
  return discrepancies.map((discrepancy) => discrepancy.rule);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Routes by pathname + query, so tests assert the exact URLs the engine builds. */
function routedFetch(routes: Record<string, () => Response | Promise<Response>>): {
  fetchImpl: typeof fetch;
  requests: string[];
} {
  const requests: string[] = [];
  const fetchImpl = (async (input: string | URL | globalThis.Request) => {
    const url = input.toString();
    requests.push(url);
    const route = routes[url];
    if (route === undefined) return jsonResponse({ error: 'not found' }, 404);
    return route();
  }) as unknown as typeof fetch;
  return { fetchImpl, requests };
}

function routesFor(
  info: unknown,
  schemas: Record<string, unknown>,
): Record<string, () => Response> {
  const routes: Record<string, () => Response> = {
    [`${DIRECT}/info`]: () => jsonResponse(info),
  };
  for (const [type, body] of Object.entries(schemas)) {
    routes[`${KYC}/customer?type=${encodeURIComponent(type)}`] = () => jsonResponse(body);
  }
  return routes;
}

describe('extractSep31Corridors', () => {
  it('extracts types, transaction fields and deprecated type fallbacks', () => {
    const corridors = extractSep31Corridors({
      receive: {
        'USDC:GISSUER': {
          sender_sep12_type: 'legacy-sender',
          receiver_sep12_type: 'legacy-receiver',
          fields: {
            transaction: {
              memo: { description: 'Transfer memo', optional: true },
            },
          },
        },
      },
    });

    expect(corridors).toHaveLength(1);
    expect(corridors[0]?.asset).toBe('USDC:GISSUER');
    expect(corridors[0]?.sender).toEqual([]);
    expect(corridors[0]?.deprecatedSenderType).toBe('legacy-sender');
    expect(corridors[0]?.deprecatedReceiverType).toBe('legacy-receiver');
    expect(corridors[0]?.transactionFields.memo).toEqual({
      description: 'Transfer memo',
      optional: true,
    });
  });

  it('accepts the array form of a customer-types declaration', () => {
    const corridors = extractSep31Corridors({
      receive: {
        EURC: {
          sep12: {
            sender: {
              types: [
                'sep31-sender',
                { type: 'business-sender', description: 'Business' },
                { type: 'no-description' },
              ],
            },
            receiver: { types: { 'sep31-receiver': 'Receiver description' } },
          },
        },
      },
    });

    expect(corridors[0]?.sender).toEqual([
      { type: 'sep31-sender' },
      { type: 'business-sender', description: 'Business' },
      { type: 'no-description' },
    ]);
    expect(corridors[0]?.receiver).toEqual([
      { type: 'sep31-receiver', description: 'Receiver description' },
    ]);
  });

  it('returns nothing for malformed documents', () => {
    expect(extractSep31Corridors(null)).toEqual([]);
    expect(extractSep31Corridors({})).toEqual([]);
    expect(extractSep31Corridors({ receive: [] })).toEqual([]);
    expect(extractSep31Corridors({ receive: { USDC: 'nope' } })).toEqual([]);
  });

  it('ignores malformed field and type definitions', () => {
    const corridors = extractSep31Corridors({
      receive: {
        USDC: {
          sep12: { sender: { types: [42, {}, { type: 7 }] } },
          fields: { transaction: { good: { description: 'ok' }, bad: 'nope' } },
        },
      },
    });
    expect(corridors[0]?.sender).toEqual([]);
    expect(corridors[0]?.transactionFields).toEqual({ good: { description: 'ok' }, bad: {} });
  });
});

describe('collectCustomerTypes', () => {
  it('deduplicates types across corridors and includes deprecated fallbacks', () => {
    const corridors = extractSep31Corridors({
      receive: {
        USDC: {
          sender_sep12_type: 'deprecated-sender',
          sep12: {
            sender: { types: { shared: { description: 'Shared' } } },
            receiver: { types: { shared: { description: 'Shared' }, receiver: {} } },
          },
        },
        EURC: {
          sep12: { sender: { types: { shared: {} } } },
        },
      },
    });

    // A deprecated single type is only used when no types map exists.
    expect(collectCustomerTypes(corridors).sort()).toEqual(['receiver', 'shared']);
  });
});

describe('parseSep12CustomerSchema', () => {
  it('parses object-form fields and records that fields was present', () => {
    const schema = parseSep12CustomerSchema({
      type: 'sep31-sender',
      status: 'NEEDS_INFO',
      fields: { first_name: { type: 'string', description: 'Given name' } },
      provided_fields: { last_name: { type: 'string', description: 'Family name' } },
    });

    expect(schema?.type).toBe('sep31-sender');
    expect(schema?.status).toBe('NEEDS_INFO');
    expect(schema?.hasFields).toBe(true);
    expect(schema?.hasProvidedFields).toBe(true);
    expect(schema?.fields.first_name?.type).toBe('string');
    expect(schema?.providedFields.last_name?.description).toBe('Family name');
  });

  it('distinguishes an empty fields object from a missing one', () => {
    const empty = parseSep12CustomerSchema({ status: 'ACCEPTED', fields: {} });
    expect(empty?.hasFields).toBe(true);
    expect(empty?.fields).toEqual({});

    const missing = parseSep12CustomerSchema({ status: 'ACCEPTED' });
    expect(missing?.hasFields).toBe(false);
  });

  it('accepts an array of field names and ignores malformed properties', () => {
    const schema = parseSep12CustomerSchema({
      fields: ['first_name', 'last_name', 42],
      provided_fields: {
        first_name: { type: 7, optional: 'yes', choices: 'a' },
        not_an_object: 'string',
      },
    });
    expect(schema?.fields).toEqual({ first_name: {}, last_name: {} });
    expect(schema?.providedFields.first_name).toEqual({});
    expect(schema?.providedFields.not_an_object).toEqual({});
  });

  it('narrows a multi-type response to the requested type', () => {
    const schema = parseSep12CustomerSchema(
      {
        types: {
          'sep31-sender': { fields: { first_name: { type: 'string' } } },
          'sep31-receiver': { fields: { bank_account_number: { type: 'string' } } },
        },
      },
      'sep31-receiver',
    );
    expect(Object.keys(schema?.fields ?? {})).toEqual(['bank_account_number']);
  });

  it('falls back to the whole body when the requested type is absent', () => {
    const schema = parseSep12CustomerSchema({ types: {}, fields: { first_name: {} } }, 'missing');
    expect(Object.keys(schema?.fields ?? {})).toEqual(['first_name']);
  });

  it('returns undefined for non-object bodies', () => {
    expect(parseSep12CustomerSchema([])).toBeUndefined();
    expect(parseSep12CustomerSchema('nope')).toBeUndefined();
    expect(parseSep12CustomerSchema(null)).toBeUndefined();
  });
});

describe('canonicalSep9Type', () => {
  it('knows the non-string SEP-9 fields', () => {
    expect(canonicalSep9Type('birth_date')).toBe('date');
    expect(canonicalSep9Type('card.expiration_date')).toBe('date');
    expect(canonicalSep9Type('photo_id_front')).toBe('binary');
    expect(canonicalSep9Type('occupation')).toBe('number');
    expect(canonicalSep9Type('organization.number_of_shareholders')).toBe('number');
  });

  it('treats the remaining SEP-9 fields as strings', () => {
    expect(canonicalSep9Type('first_name')).toBe('string');
    expect(canonicalSep9Type('postal_code')).toBe('string');
    expect(canonicalSep9Type('id_number')).toBe('string');
    expect(canonicalSep9Type('address')).toBe('string');
  });

  it('has no canonical type for a custom field', () => {
    expect(canonicalSep9Type('routing_number')).toBeUndefined();
  });
});

describe('Sep31Sep12ConsistencyEngine.analyze', () => {
  const engine = new Sep31Sep12ConsistencyEngine();

  it('passes a consistent corridor in both directions', () => {
    const report = engine.analyze(
      INFO,
      lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
    );

    expect(report.ok).toBe(true);
    expect(report.discrepancies).toEqual([]);
    expect(report.corridors).toEqual([
      {
        asset: 'USDC',
        senderTypes: ['sep31-sender'],
        receiverTypes: ['sep31-receiver'],
        transactionFields: ['routing_number', 'reference'],
      },
    ]);
    expect(report.counts).toEqual({ error: 0, warning: 0, info: 0 });
  });

  it('reports a transaction field missing from SEP-12 as orphaned', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: { ...SENDER_SCHEMA.fields, routing_number: undefined },
    };
    delete (schema.fields as Record<string, unknown>).routing_number;

    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const [orphan] = report.discrepancies.filter((d) => d.rule === 'sep31/field-orphaned');

    expect(orphan?.severity).toBe('error');
    expect(orphan?.field).toBe('routing_number');
    expect(orphan?.customerType).toBe('sep31-sender');
    expect(orphan?.message).toContain('routing_number');
    expect(orphan?.suggestion).toContain('SEP-12');
    expect(report.ok).toBe(false);
  });

  it('reports a field advertised as optional in SEP-31 but required in SEP-12', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        reference: { type: 'string', description: 'Sender reference', optional: false },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const [mismatch] = report.discrepancies.filter(
      (d) => d.rule === 'sep31/optional-flag-mismatch',
    );

    expect(mismatch?.severity).toBe('error');
    expect(mismatch?.expected).toBe('optional: false');
    expect(mismatch?.actual).toBe('optional: true');
    expect(mismatch?.message).toContain('optional in SEP-31');
  });

  it('reports the opposite mandatory-flag contradiction', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: { type: 'string', description: 'Routing', optional: true },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const [mismatch] = report.discrepancies.filter(
      (d) => d.rule === 'sep31/optional-flag-mismatch',
    );
    expect(mismatch?.message).toContain('required in SEP-31 /info but optional in SEP-12');
  });

  it('does not compare the optional flag for fields only in provided_fields', () => {
    const schema = {
      type: 'sep31-sender',
      status: 'ACCEPTED',
      provided_fields: {
        routing_number: { type: 'string', description: 'Routing', status: 'ACCEPTED' },
        reference: { type: 'string', description: 'Sender reference', status: 'ACCEPTED' },
      },
    };
    const report = engine.analyze(
      { receive: { USDC: INFO.receive.USDC } },
      lookupOf({ 'sep31-sender': schema }),
    );
    expect(rulesOf(report.discrepancies)).not.toContain('sep31/optional-flag-mismatch');
  });

  it('warns when the same field is described differently', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: { type: 'string', description: 'Bank routing number' },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const [mismatch] = report.discrepancies.filter((d) => d.rule === 'sep31/description-mismatch');

    expect(mismatch?.severity).toBe('warning');
    expect(mismatch?.expected).toContain('ABA routing number');
    expect(mismatch?.actual).toBe('Bank routing number');
  });

  it('warns when SEP-12 does not describe a field at all', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: { type: 'string' },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const [missing] = report.discrepancies.filter((d) => d.rule === 'sep31/description-mismatch');
    expect(missing?.message).toContain('has no description');
  });

  it('treats equivalent descriptions as consistent', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: {
          type: 'string',
          description: '  aba   ROUTING number of the receiving bank ',
        },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    expect(rulesOf(report.discrepancies)).not.toContain('sep31/description-mismatch');
  });

  it('reports contradictory choices and missing choices', () => {
    const info = structuredClone(INFO);
    info.receive.USDC.fields.transaction.routing_number = {
      description: 'ABA routing number of the receiving bank',
      choices: ['ACH', 'WIRE'],
    };
    const mismatched = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: {
          type: 'string',
          description: 'ABA routing number of the receiving bank',
          choices: ['ACH', 'SWIFT'],
        },
      },
    };
    const report = engine.analyze(info, lookupOf({ 'sep31-sender': mismatched }));
    const [mismatch] = report.discrepancies.filter((d) => d.rule === 'sep31/choices-mismatch');
    expect(mismatch?.severity).toBe('error');
    expect(mismatch?.expected).toBe('ACH, WIRE');
    expect(mismatch?.actual).toBe('ACH, SWIFT');

    const missing = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: {
          type: 'string',
          description: 'ABA routing number of the receiving bank',
        },
      },
    };
    const missingReport = engine.analyze(info, lookupOf({ 'sep31-sender': missing }));
    expect(rulesOf(missingReport.discrepancies)).toContain('sep31/choices-missing');

    const shorter = {
      ...missing,
      fields: {
        ...missing.fields,
        routing_number: {
          type: 'string',
          description: 'ABA routing number of the receiving bank',
          choices: ['ACH'],
        },
      },
    };
    const shorterReport = engine.analyze(info, lookupOf({ 'sep31-sender': shorter }));
    expect(rulesOf(shorterReport.discrepancies)).toContain('sep31/choices-mismatch');
  });

  it('ignores choice ordering differences', () => {
    const info = structuredClone(INFO);
    info.receive.USDC.fields.transaction.routing_number = {
      description: 'ABA routing number of the receiving bank',
      choices: ['ACH', 'WIRE'],
    };
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: {
          type: 'string',
          description: 'ABA routing number of the receiving bank',
          choices: ['WIRE', 'ACH'],
        },
      },
    };
    const report = engine.analyze(info, lookupOf({ 'sep31-sender': schema }));
    expect(rulesOf(report.discrepancies)).not.toContain('sep31/choices-mismatch');
  });

  it('reports a declared value type that contradicts SEP-12', () => {
    const info = structuredClone(INFO);
    info.receive.USDC.fields.transaction.routing_number = {
      description: 'ABA routing number of the receiving bank',
      type: 'number',
    };
    const report = engine.analyze(info, lookupOf({ 'sep31-sender': SENDER_SCHEMA }));
    const [mismatch] = report.discrepancies.filter(
      (d) => d.rule === 'sep12/field-type-incompatible',
    );
    expect(mismatch?.expected).toBe('number');
    expect(mismatch?.actual).toBe('string');
  });

  it('flags a date declared as a string as non-canonical', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        birth_date: { type: 'string', description: 'Date of birth' },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const [noncanonical] = report.discrepancies.filter(
      (d) => d.rule === 'sep12/field-type-noncanonical',
    );
    expect(noncanonical?.severity).toBe('warning');
    expect(noncanonical?.expected).toBe('date');
    expect(noncanonical?.actual).toBe('string');
  });

  it('flags an incompatible SEP-9 type for a national ID or binary field', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        id_number: { type: 'number', description: 'ID number' },
        id_type: { type: 'binary', description: 'ID type' },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const offending = report.discrepancies.filter(
      (d) => d.rule === 'sep12/field-type-incompatible' && d.field !== 'routing_number',
    );
    expect(offending.map((d) => d.field)).toEqual(['id_number', 'id_type']);
    expect(offending[0]?.expected).toBe('string');
  });

  it('reports a missing type and an invalid type', () => {
    const info = structuredClone(INFO);
    info.receive.USDC.fields.transaction.routing_number = {
      description: 'ABA routing number of the receiving bank',
    };
    const missing = {
      ...SENDER_SCHEMA,
      fields: { ...SENDER_SCHEMA.fields, routing_number: { description: 'Routing' } },
    };
    const missingReport = engine.analyze(info, lookupOf({ 'sep31-sender': missing }));
    expect(rulesOf(missingReport.discrepancies)).toContain('sep12/field-type-missing');

    const invalid = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        routing_number: { type: 'integer', description: 'Routing' },
      },
    };
    const invalidReport = engine.analyze(info, lookupOf({ 'sep31-sender': invalid }));
    expect(rulesOf(invalidReport.discrepancies)).toContain('sep12/field-type-invalid');
  });

  it('warns about a required custom SEP-12 field missing from /info', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        tax_residency: { type: 'string', description: 'Tax residency' },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    const orphan = report.discrepancies.find(
      (d) => d.rule === 'sep31/orphaned-sep12-required-field',
    );
    expect(orphan?.severity).toBe('warning');
    expect(orphan?.field).toBe('tax_residency');
  });

  it('does not treat standard SEP-9 fields or optional custom fields as orphans', () => {
    const schema = {
      ...SENDER_SCHEMA,
      fields: {
        ...SENDER_SCHEMA.fields,
        tax_residency: { type: 'string', description: 'Tax residency', optional: true },
      },
    };
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    expect(rulesOf(report.discrepancies)).not.toContain('sep31/orphaned-sep12-required-field');
  });

  it('accepts a plain record of schemas and treats absent keys as missing', () => {
    const schema = parseSep12CustomerSchema({ fields: {} }, 'sep31-sender');
    const report = engine.analyze(INFO, {
      'sep31-sender': { schema: schema as NonNullable<typeof schema> },
    });
    expect(rulesOf(report.discrepancies)).toContain('sep12/customer-schema-missing');
    expect(
      report.discrepancies.find((d) => d.rule === 'sep12/customer-schema-missing')?.customerType,
    ).toBe('sep31-receiver');
  });

  it('reports a customer type with no SEP-12 schema', () => {
    const report = engine.analyze(INFO, lookupOf({ 'sep31-sender': SENDER_SCHEMA }));
    const missing = report.discrepancies.find((d) => d.rule === 'sep12/customer-schema-missing');
    expect(missing?.severity).toBe('error');
    expect(missing?.customerType).toBe('sep31-receiver');
  });

  it('reports a SEP-12 response with no fields at all', () => {
    const report = engine.analyze(
      INFO,
      lookupOf({
        'sep31-sender': { status: 'NEEDS_INFO' },
        'sep31-receiver': RECEIVER_SCHEMA,
      }),
    );
    const missing = report.discrepancies.find((d) => d.rule === 'sep12/customer-schema-missing');
    expect(missing?.message).toContain('no fields or provided_fields');
  });

  it('accepts an empty fields object as "no KYC required"', () => {
    const info = { receive: { USDC: { sep12: { sender: { types: { 'sep31-sender': {} } } } } } };
    const report = engine.analyze(
      info,
      lookupOf({ 'sep31-sender': { status: 'ACCEPTED', fields: {} } }),
    );
    expect(report.ok).toBe(true);
  });

  it('reports a customer type the response labels differently', () => {
    const schema = { ...SENDER_SCHEMA, type: 'sep31-receiver' };
    const report = engine.analyze(
      INFO,
      lookupOf({
        'sep31-sender': schema,
        'sep31-receiver': RECEIVER_SCHEMA,
      }),
    );
    const [mismatch] = report.discrepancies.filter(
      (d) => d.rule === 'sep12/customer-type-mismatch',
    );
    expect(mismatch?.expected).toBe('sep31-sender');
    expect(mismatch?.actual).toBe('sep31-receiver');
  });

  it('reports transaction fields with no discoverable customer type', () => {
    const info = {
      receive: {
        USDC: { fields: { transaction: { memo: { description: 'Memo' } } } },
      },
    };
    const report = engine.analyze(info, {});
    expect(rulesOf(report.discrepancies)).toContain(
      'sep31/transaction-fields-without-customer-type',
    );
  });

  it('warns about a transaction field with no description', () => {
    const info = {
      receive: {
        USDC: {
          sep12: { sender: { types: { 'sep31-sender': {} } } },
          fields: { transaction: { memo: { optional: true } } },
        },
      },
    };
    const report = engine.analyze(info, lookupOf({ 'sep31-sender': { fields: {} } }));
    expect(rulesOf(report.discrepancies)).toContain('sep31/field-description-missing');
    expect(rulesOf(report.discrepancies)).toContain('sep31/customer-type-description-missing');
  });

  it('warns when a deprecated type is no longer advertised', () => {
    const info = structuredClone(INFO);
    (info.receive.USDC as Record<string, unknown>).sender_sep12_type = 'legacy-sender';
    const report = engine.analyze(
      info,
      lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
    );
    expect(rulesOf(report.discrepancies)).toContain('sep31/deprecated-type-not-advertised');
  });

  it('accepts a deprecated type that is also listed in types', () => {
    const info = structuredClone(INFO);
    (info.receive.USDC as Record<string, unknown>).sender_sep12_type = 'sep31-sender';
    const report = engine.analyze(
      info,
      lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
    );
    expect(rulesOf(report.discrepancies)).not.toContain('sep31/deprecated-type-not-advertised');
  });

  it('warns when a deprecated receiver type is no longer advertised', () => {
    const info = structuredClone(INFO);
    (info.receive.USDC as Record<string, unknown>).receiver_sep12_type = 'legacy-receiver';
    const report = engine.analyze(
      info,
      lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
    );
    const warning = report.discrepancies.find(
      (d) => d.rule === 'sep31/deprecated-type-not-advertised',
    );
    expect(warning?.role).toBe('receiver');
    expect(warning?.customerType).toBe('legacy-receiver');
  });

  it('accepts a deprecated receiver type that is also listed in types', () => {
    const info = structuredClone(INFO);
    (info.receive.USDC as Record<string, unknown>).receiver_sep12_type = 'sep31-receiver';
    const report = engine.analyze(
      info,
      lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
    );
    expect(rulesOf(report.discrepancies)).not.toContain('sep31/deprecated-type-not-advertised');
  });

  it('uses a deprecated receiver type when no types map exists', () => {
    const info = {
      receive: {
        USDC: {
          receiver_sep12_type: 'legacy-receiver',
          fields: { transaction: { memo: { description: 'Memo' } } },
        },
      },
    };
    const schema = { status: 'NEEDS_INFO', fields: { memo: { description: 'Memo' } } };
    const report = engine.analyze(info, lookupOf({ 'legacy-receiver': schema }));
    expect(report.corridors[0]?.receiverTypes).toEqual(['legacy-receiver']);
    expect(report.ok).toBe(true);
  });

  it('uses a deprecated type when no types map exists', () => {
    const info = {
      receive: {
        USDC: {
          sender_sep12_type: 'legacy-sender',
          fields: { transaction: { memo: { description: 'Memo' } } },
        },
      },
    };
    const schema = { status: 'NEEDS_INFO', fields: { memo: { description: 'Memo' } } };
    const report = engine.analyze(info, lookupOf({ 'legacy-sender': schema }));
    expect(report.corridors[0]?.senderTypes).toEqual(['legacy-sender']);
    expect(report.ok).toBe(true);
  });

  it('reports malformed /info responses', () => {
    for (const info of [null, {}, { receive: [] }, { receive: {} }]) {
      const report = engine.analyze(info, {});
      expect(report.ok).toBe(true);
      expect(rulesOf(report.discrepancies)).toEqual(['sep31/info-malformed']);
    }
  });

  it('reports lookup failures by status', () => {
    const failures: [Sep12SchemaResult, string][] = [
      [{ status: 404, error: 'HTTP 404' }, 'sep12/customer-type-not-found'],
      [{ status: 401, error: 'HTTP 401' }, 'sep12/customer-schema-unauthorized'],
      [{ status: 403, error: 'HTTP 403' }, 'sep12/customer-schema-unauthorized'],
      [{ status: 500, error: 'HTTP 500' }, 'sep12/customer-schema-unreachable'],
      [{ error: 'network down' }, 'sep12/customer-schema-malformed'],
      [{}, 'sep12/customer-schema-malformed'],
    ];

    for (const [result, rule] of failures) {
      const report = engine.analyze(INFO, new Map([['sep31-sender', result]]));
      expect(rulesOf(report.discrepancies)).toContain(rule);
    }
  });

  it('honours rule overrides and severity escalation', () => {
    const disabled = new Sep31Sep12ConsistencyEngine({
      rules: { 'sep31/field-orphaned': 'off' },
    });
    const schema = { ...SENDER_SCHEMA, fields: {} };
    const off = disabled.analyze(INFO, lookupOf({ 'sep31-sender': schema }));
    expect(rulesOf(off.discrepancies)).not.toContain('sep31/field-orphaned');

    const escalated = new Sep31Sep12ConsistencyEngine({
      rules: { 'sep31/customer-type-description-missing': 'error' },
    });
    const info = structuredClone(INFO);
    info.receive.USDC.sep12.sender.types['sep31-sender'] = {};
    const report = escalated.analyze(
      info,
      lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
    );
    const finding = report.discrepancies.find(
      (d) => d.rule === 'sep31/customer-type-description-missing',
    );
    expect(finding?.severity).toBe('error');
  });
});

describe('Sep31Sep12ConsistencyEngine.verify', () => {
  it('fetches /info and every advertised schema, normalising trailing slashes', async () => {
    const { fetchImpl, requests } = routedFetch(
      routesFor(INFO, {
        'sep31-sender': SENDER_SCHEMA,
        'sep31-receiver': RECEIVER_SCHEMA,
      }),
    );
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: `${DIRECT}/`,
      kycServer: `${KYC}/`,
    });

    expect(report.ok).toBe(true);
    expect(report.directPaymentServer).toBe(DIRECT);
    expect(report.kycServer).toBe(KYC);
    expect(requests).toEqual(
      expect.arrayContaining([
        `${DIRECT}/info`,
        `${KYC}/customer?type=sep31-sender`,
        `${KYC}/customer?type=sep31-receiver`,
      ]),
    );
  });

  it('URL-encodes customer type names', async () => {
    const info = {
      receive: {
        USDC: { sep12: { sender: { types: { 'sep31 sender/ü': {} } } } },
      },
    };
    const { fetchImpl, requests } = routedFetch({
      [`${DIRECT}/info`]: () => jsonResponse(info),
      [`${KYC}/customer?type=sep31%20sender%2F%C3%BC`]: () => jsonResponse({ fields: {} }),
    });
    await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(requests).toContain(`${KYC}/customer?type=sep31%20sender%2F%C3%BC`);
  });

  it('reports an unreachable /info endpoint as a warning', async () => {
    const { fetchImpl } = routedFetch({
      [`${DIRECT}/info`]: () => jsonResponse({ error: 'down' }, 503),
    });
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });

    expect(report.ok).toBe(true);
    expect(report.counts.warning).toBe(1);
    expect(rulesOf(report.discrepancies)).toEqual(['sep31/info-unavailable']);
    expect(report.directPaymentServer).toBe(DIRECT);
  });

  it('reports a /info fetch exception as a warning', async () => {
    const fetchImpl = (async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(rulesOf(report.discrepancies)).toEqual(['sep31/info-unavailable']);
    expect(report.discrepancies[0]?.message).toContain('network down');
  });

  it('reports a 404 customer type as a missing schema', async () => {
    const { fetchImpl } = routedFetch(routesFor(INFO, { 'sep31-sender': SENDER_SCHEMA }));
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(rulesOf(report.discrepancies)).toContain('sep12/customer-type-not-found');
    expect(report.ok).toBe(false);
  });

  it('classifies a 401 schema response as needing authentication', async () => {
    const { fetchImpl } = routedFetch({
      [`${DIRECT}/info`]: () => jsonResponse(INFO),
      [`${KYC}/customer?type=sep31-sender`]: () => jsonResponse({}, 401),
      [`${KYC}/customer?type=sep31-receiver`]: () => jsonResponse({}, 403),
    });
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(rulesOf(report.discrepancies).sort()).toEqual([
      'sep12/customer-schema-unauthorized',
      'sep12/customer-schema-unauthorized',
    ]);
  });

  it('reports non-JSON schema responses as malformed', async () => {
    const { fetchImpl } = routedFetch({
      [`${DIRECT}/info`]: () => jsonResponse(INFO),
      [`${KYC}/customer?type=sep31-sender`]: () =>
        new Response('<html>not json</html>', { status: 200 }),
      [`${KYC}/customer?type=sep31-receiver`]: () => new Response('not json', { status: 200 }),
    });
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(rulesOf(report.discrepancies)).toEqual([
      'sep12/customer-schema-malformed',
      'sep12/customer-schema-malformed',
    ]);
  });

  it('reports a JSON array as a malformed schema', async () => {
    const { fetchImpl } = routedFetch({
      [`${DIRECT}/info`]: () => jsonResponse(INFO),
      [`${KYC}/customer?type=sep31-sender`]: () => jsonResponse([]),
      [`${KYC}/customer?type=sep31-receiver`]: () => jsonResponse([]),
    });
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(report.discrepancies[0]?.message).toContain('not a JSON object');
  });

  it('reports a schema fetch exception as malformed', async () => {
    const fetchImpl = (async (input: string | URL | globalThis.Request) => {
      const url = input.toString();
      if (url.endsWith('/info')) return jsonResponse(INFO);
      throw new Error('schema timeout');
    }) as unknown as typeof fetch;
    const report = await new Sep31Sep12ConsistencyEngine({ fetchImpl }).verify({
      directPaymentServer: DIRECT,
      kycServer: KYC,
    });
    expect(rulesOf(report.discrepancies)).toEqual([
      'sep12/customer-schema-malformed',
      'sep12/customer-schema-malformed',
    ]);
    expect(report.discrepancies[0]?.message).toContain('schema timeout');
  });

  it('honours a non-default timeout', async () => {
    const { fetchImpl } = routedFetch(
      routesFor(INFO, {
        'sep31-sender': SENDER_SCHEMA,
        'sep31-receiver': RECEIVER_SCHEMA,
      }),
    );
    const report = await new Sep31Sep12ConsistencyEngine({
      fetchImpl,
      timeoutMs: 1234,
    }).verify({ directPaymentServer: DIRECT, kycServer: KYC });
    expect(report.ok).toBe(true);
  });
});

describe('verifySep31Sep12 document helper', () => {
  it('is silent without both servers and does not fetch', async () => {
    let called = 0;
    const fetchImpl = (async () => {
      called += 1;
      return jsonResponse({});
    }) as unknown as typeof fetch;

    for (const doc of [
      {},
      { DIRECT_PAYMENT_SERVER: DIRECT },
      { KYC_SERVER: KYC },
      { DIRECT_PAYMENT_SERVER: 'not a url', KYC_SERVER: KYC },
      { DIRECT_PAYMENT_SERVER: DIRECT, KYC_SERVER: 'not a url' },
    ]) {
      const report = await verifySep31Sep12(doc, fetchImpl);
      expect(report.corridors).toEqual([]);
      expect(report.discrepancies).toEqual([]);
    }
    expect(called).toBe(0);
  });

  it('runs against the servers in the document', async () => {
    const { fetchImpl } = routedFetch(
      routesFor(INFO, {
        'sep31-sender': SENDER_SCHEMA,
        'sep31-receiver': RECEIVER_SCHEMA,
      }),
    );
    const report = await verifySep31Sep12(
      { DIRECT_PAYMENT_SERVER: DIRECT, KYC_SERVER: KYC },
      fetchImpl,
    );
    expect(report.ok).toBe(true);
    expect(report.corridors).toHaveLength(1);
  });

  it('passes rule overrides through the helper', async () => {
    const { fetchImpl } = routedFetch({
      [`${DIRECT}/info`]: () => jsonResponse(INFO),
      [`${KYC}/customer?type=sep31-sender`]: () => jsonResponse({}, 401),
      [`${KYC}/customer?type=sep31-receiver`]: () => jsonResponse({}, 401),
    });
    const report = await verifySep31Sep12(
      { DIRECT_PAYMENT_SERVER: DIRECT, KYC_SERVER: KYC },
      fetchImpl,
      { rules: { 'sep12/customer-schema-unauthorized': 'off' } },
    );
    expect(rulesOf(report.discrepancies)).not.toContain('sep12/customer-schema-unauthorized');
  });
});

describe('renderSep31Sep12Report', () => {
  const engine = new Sep31Sep12ConsistencyEngine();

  it('renders corridors, findings and a summary', () => {
    const schema = { ...SENDER_SCHEMA, fields: {} };
    const report = {
      ...engine.analyze(INFO, lookupOf({ 'sep31-sender': schema })),
      directPaymentServer: DIRECT,
      kycServer: KYC,
    };
    const text = renderSep31Sep12Report(report);

    expect(text).toContain(`SEP-31 ↔ SEP-12 consistency: ${DIRECT} ↔ ${KYC}`);
    expect(text).toContain('Corridors: 1');
    expect(text).toContain('USDC');
    expect(text).toContain('sender: sep31-sender');
    expect(text).toContain('Discrepancies:');
    expect(text).toContain('[error] sep31/field-orphaned');
    expect(text).toContain('fix:');
    expect(text).toContain('Summary:');
  });

  it('renders a clean report and the empty-corridor case', async () => {
    const clean = renderSep31Sep12Report(
      engine.analyze(
        INFO,
        lookupOf({ 'sep31-sender': SENDER_SCHEMA, 'sep31-receiver': RECEIVER_SCHEMA }),
      ),
    );
    expect(clean).toContain('No SEP-31 / SEP-12 discrepancies found.');

    const empty = renderSep31Sep12Report(engine.analyze({}, {}));
    expect(empty).toContain('No asset corridors could be inspected.');

    const typeless = renderSep31Sep12Report(engine.analyze({ receive: { USDC: {} } }, {}));
    expect(typeless).toContain('sender: (none)');
    expect(typeless).toContain('receiver: (none)');
    expect(typeless).not.toContain('transaction fields:');

    const silent = await verifySep31Sep12({});
    expect(renderSep31Sep12Report(silent)).not.toContain('No SEP-31 / SEP-12 discrepancies');
  });
});

describe('rule registration', () => {
  it('registers every consistency rule with a unique id', () => {
    const ids = sep31Sep12Rules.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain('sep31/field-orphaned');
    expect(ids).toContain('sep12/field-type-incompatible');
  });

  it('exposes the rules through the catalog for --list-rules', () => {
    const catalog = allRules.map((rule) => rule.id);
    for (const rule of sep31Sep12Rules) expect(catalog).toContain(rule.id);
  });

  it('never emits consistency diagnostics from an offline lint', async () => {
    const { lint } = await import('../src/lint.js');
    const result = lint(
      ['VERSION="2.7.0"', `DIRECT_PAYMENT_SERVER="${DIRECT}"`, `KYC_SERVER="${KYC}"`].join('\n'),
    );
    expect(result.diagnostics.map((d) => d.rule)).not.toContain('sep31/field-orphaned');
  });
});
