import { describe, expect, it } from 'vitest';
import {
  validateSep31KycMatrix,
  generateSep31PaymentJsonSchema,
  generateSep31ClientSchemas,
  INVALID_KYC_FIELD_DEFINITION_RULE,
  MISSING_SENDER_KYC_DECLARATION_RULE,
} from '../../src/protocols/sep31-kyc-matrix.js';

describe('SEP-31 sender and receiver KYC requirement matrix validator and schema generator', () => {
  const directPaymentServer = 'https://sep31.example.com';
  const doc = {
    DIRECT_PAYMENT_SERVER: directPaymentServer,
  };

  const validInfoResponse = {
    receive: {
      USD: {
        fee_fixed: 5,
        fee_percent: 1,
        min_amount: 1,
        max_amount: 10000,
        sender_sep12_type: 'sep31-sender',
        receiver_sep12_type: 'sep31-receiver',
        fields: {
          transaction: {
            routing_number: {
              description: 'US bank ABA routing number',
              optional: false,
            },
            account_number: {
              description: 'US bank account number',
              optional: false,
            },
          },
          sender: {
            first_name: {
              description: 'Sender first name',
              optional: false,
            },
            last_name: {
              description: 'Sender last name',
              optional: false,
            },
            email_address: {
              description: 'Sender contact email',
              optional: true,
            },
          },
          receiver: {
            first_name: {
              description: 'Receiver legal first name',
              optional: false,
            },
            last_name: {
              description: 'Receiver legal last name',
              optional: false,
            },
          },
        },
      },
    },
  };

  it('passes cleanly for a fully conforming SEP-31 KYC matrix', async () => {
    const fetchImpl = (async () => {
      return new Response(JSON.stringify(validInfoResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await validateSep31KycMatrix(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep31/missing-sender-kyc-declaration when asset lacks sender_sep12_type and fields.sender', async () => {
    const responseWithoutSender = {
      receive: {
        USD: {
          receiver_sep12_type: 'sep31-receiver',
          fields: {
            transaction: {
              routing_number: { description: 'Routing number' },
            },
            receiver: {
              first_name: { description: 'First name' },
            },
          },
        },
      },
    };

    const fetchImpl = (async () => {
      return new Response(JSON.stringify(responseWithoutSender), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await validateSep31KycMatrix(doc, fetchImpl);
    const warning = diagnostics.find((d) => d.rule === MISSING_SENDER_KYC_DECLARATION_RULE);
    expect(warning).toBeDefined();
    expect(warning?.severity).toBe('warning');
    expect(warning?.message).toContain('missing a sender KYC declaration');
  });

  it('asserts sep31/invalid-kyc-field-definition when a KYC field violates SEP-9 standards', async () => {
    const responseWithInvalidSep9 = {
      receive: {
        USD: {
          sender_sep12_type: 'sep31-sender',
          fields: {
            sender: {
              invalid_custom_kyc_field_123: {
                description: 'Non-standard KYC field name',
                optional: false,
              },
            },
          },
        },
      },
    };

    const fetchImpl = (async () => {
      return new Response(JSON.stringify(responseWithInvalidSep9), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await validateSep31KycMatrix(doc, fetchImpl);
    const errorDiag = diagnostics.find((d) => d.rule === INVALID_KYC_FIELD_DEFINITION_RULE);
    expect(errorDiag).toBeDefined();
    expect(errorDiag?.severity).toBe('error');
    expect(errorDiag?.message).toContain('does not conform to the SEP-9 standard');
  });

  it('asserts sep31/invalid-kyc-field-definition when a field definition is not an object', async () => {
    const invalidDefinitionResponse = {
      receive: {
        USD: {
          sender_sep12_type: 'sep31-sender',
          fields: {
            transaction: {
              routing_number: 'not-an-object',
            },
          },
        },
      },
    };

    const fetchImpl = (async () => {
      return new Response(JSON.stringify(invalidDefinitionResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await validateSep31KycMatrix(doc, fetchImpl);
    const errorDiag = diagnostics.find((d) => d.rule === INVALID_KYC_FIELD_DEFINITION_RULE);
    expect(errorDiag).toBeDefined();
    expect(errorDiag?.message).toContain('definition must be an object');
  });

  it('asserts sep31/invalid-kyc-field-definition when description is missing or invalid', async () => {
    const missingDescResponse = {
      receive: {
        USD: {
          sender_sep12_type: 'sep31-sender',
          fields: {
            sender: {
              first_name: {
                optional: false,
              },
            },
          },
        },
      },
    };

    const fetchImpl = (async () => {
      return new Response(JSON.stringify(missingDescResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await validateSep31KycMatrix(doc, fetchImpl);
    const errorDiag = diagnostics.find((d) => d.rule === INVALID_KYC_FIELD_DEFINITION_RULE);
    expect(errorDiag).toBeDefined();
    expect(errorDiag?.message).toContain('missing a required description string');
  });

  it('asserts sep31/invalid-kyc-field-definition when optional is not boolean or choices is not array of strings', async () => {
    const invalidPropsResponse = {
      receive: {
        USD: {
          sender_sep12_type: 'sep31-sender',
          fields: {
            transaction: {
              routing_number: {
                description: 'Routing number',
                optional: 'not-boolean',
                choices: [123, 456],
              },
            },
          },
        },
      },
    };

    const fetchImpl = (async () => {
      return new Response(JSON.stringify(invalidPropsResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await validateSep31KycMatrix(doc, fetchImpl);
    const errors = diagnostics.filter((d) => d.rule === INVALID_KYC_FIELD_DEFINITION_RULE);
    expect(errors.some((e) => e.message.includes('must be a boolean'))).toBe(true);
    expect(errors.some((e) => e.message.includes('must be an array of strings'))).toBe(true);
  });

  it('generates a valid client validation JSON schema with generateSep31PaymentJsonSchema', () => {
    const schema = generateSep31PaymentJsonSchema('USD', validInfoResponse.receive.USD);

    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.type).toBe('object');

    const properties = schema.properties as Record<string, any>;
    expect(properties.amount).toBeDefined();
    expect(properties.asset_code).toBeDefined();
    expect(properties.sender_id).toBeDefined();
    expect(properties.receiver_id).toBeDefined();
    expect(properties.fields).toBeDefined();

    const fieldsProps = properties.fields.properties as Record<string, any>;
    expect(fieldsProps.transaction.properties.routing_number).toBeDefined();
    expect(fieldsProps.transaction.required).toContain('routing_number');
    expect(fieldsProps.sender.properties.first_name).toBeDefined();
    expect(fieldsProps.sender.required).toContain('first_name');
    expect(fieldsProps.sender.required).not.toContain('email_address'); // email_address was optional: true
  });

  it('generates client validation JSON schemas for all assets in /info response', () => {
    const schemas = generateSep31ClientSchemas(validInfoResponse);
    expect(schemas.USD).toBeDefined();
    expect(schemas.USD?.type).toBe('object');
  });

  it('returns empty diagnostics when DIRECT_PAYMENT_SERVER is not declared', async () => {
    const diagnostics = await validateSep31KycMatrix({});
    expect(diagnostics).toEqual([]);
  });
});
