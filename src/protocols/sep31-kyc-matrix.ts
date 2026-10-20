/**
 * SEP-31 Sender and Receiver KYC Requirement Matrix Validator and Schema Generator.
 *
 * In SEP-31 cross-border direct payments, GET /info returns complex nested JSON defining
 * required sender and receiver KYC fields for each asset and transaction direction.
 *
 * This module:
 * 1. Queries DIRECT_PAYMENT_SERVER/info.
 * 2. Audits fields.transaction, fields.sender, and fields.receiver.
 * 3. Verifies that required fields conform to the SEP-9 financial client standard.
 * 4. Exports a validated JSON schema of required payment parameters for client wallets.
 * 5. Emits `sep31/invalid-kyc-field-definition` (error).
 * 6. Emits `sep31/missing-sender-kyc-declaration` (warning).
 *
 * Runs under opt-in `--check-network` and `--verify-sep31`.
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { SEP9_KYC_FIELDS } from '../rules/sep12-schema.js';

export const INVALID_KYC_FIELD_DEFINITION_RULE = 'sep31/invalid-kyc-field-definition';
export const MISSING_SENDER_KYC_DECLARATION_RULE = 'sep31/missing-sender-kyc-declaration';

export const SEP31_SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md';
export const SEP9_SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0009.md';

export interface Sep31FieldDefinition {
  description?: string;
  optional?: boolean;
  choices?: string[];
  [key: string]: unknown;
}

export interface Sep31AssetFields {
  transaction?: Record<string, Sep31FieldDefinition>;
  sender?: Record<string, Sep31FieldDefinition>;
  receiver?: Record<string, Sep31FieldDefinition>;
  [key: string]: unknown;
}

export interface Sep31AssetInfo {
  fee_fixed?: number;
  fee_percent?: number;
  min_amount?: number;
  max_amount?: number;
  sender_sep12_type?: string;
  receiver_sep12_type?: string;
  fields?: Sep31AssetFields;
  [key: string]: unknown;
}

export interface Sep31KycMatrixOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Generates a JSON Schema (Draft 2020-12) describing the payment parameters
 * and KYC field matrix required to initiate a direct payment for a given asset.
 */
export function generateSep31PaymentJsonSchema(
  assetCode: string,
  assetConfig: Sep31AssetInfo,
): Record<string, unknown> {
  const properties: Record<string, unknown> = {
    amount: {
      type: 'string',
      pattern: '^[0-9]+(\\.[0-9]+)?$',
      description: 'Payment amount to be sent',
    },
    asset_code: {
      type: 'string',
      const: assetCode,
      description: 'Asset code for direct payment',
    },
  };

  const requiredRoot: string[] = ['amount', 'asset_code'];

  if (assetConfig.sender_sep12_type) {
    properties.sender_id = {
      type: 'string',
      description: 'SEP-12 customer ID representing the sender',
    };
    requiredRoot.push('sender_id');
  }

  if (assetConfig.receiver_sep12_type) {
    properties.receiver_id = {
      type: 'string',
      description: 'SEP-12 customer ID representing the receiver',
    };
    requiredRoot.push('receiver_id');
  }

  const fields = assetConfig.fields;
  if (isRecord(fields)) {
    const fieldsProperties: Record<string, unknown> = {};
    const fieldsRequired: string[] = [];

    const categories = ['transaction', 'sender', 'receiver'] as const;
    for (const category of categories) {
      const categoryMap = fields[category];
      if (isRecord(categoryMap)) {
        const catProps: Record<string, unknown> = {};
        const catRequired: string[] = [];

        for (const [fieldName, def] of Object.entries(categoryMap)) {
          const fieldDef = isRecord(def) ? (def as Sep31FieldDefinition) : {};
          const propSchema: Record<string, unknown> = {
            type: 'string',
            description:
              typeof fieldDef.description === 'string' ? fieldDef.description : fieldName,
          };
          if (Array.isArray(fieldDef.choices) && fieldDef.choices.length > 0) {
            propSchema.enum = fieldDef.choices;
          }
          catProps[fieldName] = propSchema;

          if (fieldDef.optional !== true) {
            catRequired.push(fieldName);
          }
        }

        fieldsProperties[category] = {
          type: 'object',
          properties: catProps,
          ...(catRequired.length > 0 ? { required: catRequired } : {}),
          additionalProperties: false,
        };

        if (catRequired.length > 0) {
          fieldsRequired.push(category);
        }
      }
    }

    if (Object.keys(fieldsProperties).length > 0) {
      properties.fields = {
        type: 'object',
        properties: fieldsProperties,
        ...(fieldsRequired.length > 0 ? { required: fieldsRequired } : {}),
      };
      if (fieldsRequired.length > 0) {
        requiredRoot.push('fields');
      }
    }
  }

  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: `SEP-31 Direct Payment Parameters Schema (${assetCode})`,
    type: 'object',
    properties,
    required: requiredRoot,
    additionalProperties: true,
  };
}

/**
 * Generates JSON schemas for every asset declared in a SEP-31 /info response.
 */
export function generateSep31ClientSchemas(
  infoResponse: Record<string, unknown>,
): Record<string, Record<string, unknown>> {
  const schemas: Record<string, Record<string, unknown>> = {};
  if (isRecord(infoResponse.receive)) {
    for (const [assetCode, config] of Object.entries(infoResponse.receive)) {
      if (isRecord(config)) {
        schemas[assetCode] = generateSep31PaymentJsonSchema(assetCode, config as Sep31AssetInfo);
      }
    }
  }
  return schemas;
}

/**
 * Validates DIRECT_PAYMENT_SERVER/info sender and receiver KYC requirement matrix
 * against SEP-9 standards and field definition specifications.
 */
export async function validateSep31KycMatrix(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep31KycMatrixOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.DIRECT_PAYMENT_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const base = server.replace(/\/+$/, '');
  const diagnostics: Diagnostic[] = [];

  let infoData: Record<string, unknown> | null = null;
  try {
    const res = await fetchImpl(`${base}/info`, { redirect: 'follow' });
    if (!res.ok) return [];
    const json = await res.json();
    if (!isRecord(json) || !isRecord(json.receive)) return [];
    infoData = json;
  } catch {
    return [];
  }

  const receiveMap = infoData.receive as Record<string, unknown>;

  for (const [assetCode, assetConfig] of Object.entries(receiveMap)) {
    if (!isRecord(assetConfig)) continue;

    // 1. Audit sender KYC declaration
    const hasSenderSep12 =
      typeof assetConfig.sender_sep12_type === 'string' &&
      assetConfig.sender_sep12_type.trim().length > 0;

    const fieldsObj = isRecord(assetConfig.fields) ? assetConfig.fields : undefined;
    const hasSenderFields =
      fieldsObj && isRecord(fieldsObj.sender) && Object.keys(fieldsObj.sender).length > 0;

    if (!hasSenderSep12 && !hasSenderFields) {
      const sev = severityFor(MISSING_SENDER_KYC_DECLARATION_RULE, 'warning', options.rules);
      if (sev) {
        diagnostics.push({
          rule: MISSING_SENDER_KYC_DECLARATION_RULE,
          severity: sev,
          category: 'network',
          message: `Asset "${assetCode}" in DIRECT_PAYMENT_SERVER /info is missing a sender KYC declaration (sender_sep12_type or fields.sender)`,
          path: `DIRECT_PAYMENT_SERVER.receive.${assetCode}`,
          helpUri: SEP31_SPEC,
          suggestion: `Declare sender_sep12_type or fields.sender for asset "${assetCode}" to enable sender KYC identification.`,
        });
      }
    }

    // 2. Audit fields.transaction, fields.sender, and fields.receiver
    if (!fieldsObj) continue;

    const categories = ['transaction', 'sender', 'receiver'] as const;
    for (const category of categories) {
      if (!(category in fieldsObj)) continue;
      const categoryMap = fieldsObj[category];

      if (!isRecord(categoryMap)) {
        const sev = severityFor(INVALID_KYC_FIELD_DEFINITION_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_KYC_FIELD_DEFINITION_RULE,
            severity: sev,
            category: 'network',
            message: `Asset "${assetCode}" fields.${category} must be an object of field definitions`,
            path: `DIRECT_PAYMENT_SERVER.receive.${assetCode}.fields.${category}`,
            helpUri: SEP31_SPEC,
            suggestion: `Define fields.${category} as a mapping of field names to field configuration objects.`,
          });
        }
        continue;
      }

      for (const [fieldName, fieldDef] of Object.entries(categoryMap)) {
        const fieldPath = `DIRECT_PAYMENT_SERVER.receive.${assetCode}.fields.${category}.${fieldName}`;

        // Field definition must be an object
        if (!isRecord(fieldDef)) {
          const sev = severityFor(INVALID_KYC_FIELD_DEFINITION_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: INVALID_KYC_FIELD_DEFINITION_RULE,
              severity: sev,
              category: 'network',
              message: `Asset "${assetCode}" field "${category}.${fieldName}" definition must be an object`,
              path: fieldPath,
              helpUri: SEP31_SPEC,
              suggestion:
                'Format the field definition as an object with description, optional, and choices properties.',
            });
          }
          continue;
        }

        // Must have string description
        if (typeof fieldDef.description !== 'string' || fieldDef.description.trim() === '') {
          const sev = severityFor(INVALID_KYC_FIELD_DEFINITION_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: INVALID_KYC_FIELD_DEFINITION_RULE,
              severity: sev,
              category: 'network',
              message: `Asset "${assetCode}" field "${category}.${fieldName}" is missing a required description string`,
              path: fieldPath,
              helpUri: SEP31_SPEC,
              suggestion: 'Provide a human-readable description string for the field.',
            });
          }
        }

        // Optional property must be boolean if present
        if ('optional' in fieldDef && typeof fieldDef.optional !== 'boolean') {
          const sev = severityFor(INVALID_KYC_FIELD_DEFINITION_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: INVALID_KYC_FIELD_DEFINITION_RULE,
              severity: sev,
              category: 'network',
              message: `Asset "${assetCode}" field "${category}.${fieldName}" property "optional" must be a boolean`,
              path: fieldPath,
              helpUri: SEP31_SPEC,
              suggestion: 'Set "optional" to true or false.',
            });
          }
        }

        // Choices property must be string array if present
        if (
          'choices' in fieldDef &&
          (!Array.isArray(fieldDef.choices) || fieldDef.choices.some((c) => typeof c !== 'string'))
        ) {
          const sev = severityFor(INVALID_KYC_FIELD_DEFINITION_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: INVALID_KYC_FIELD_DEFINITION_RULE,
              severity: sev,
              category: 'network',
              message: `Asset "${assetCode}" field "${category}.${fieldName}" property "choices" must be an array of strings`,
              path: fieldPath,
              helpUri: SEP31_SPEC,
              suggestion: 'Set "choices" to a JSON array of string values.',
            });
          }
        }

        // Conformance to SEP-9 financial client standard for sender and receiver KYC fields
        if (category === 'sender' || category === 'receiver') {
          if (!SEP9_KYC_FIELDS.has(fieldName)) {
            const sev = severityFor(INVALID_KYC_FIELD_DEFINITION_RULE, 'error', options.rules);
            if (sev) {
              diagnostics.push({
                rule: INVALID_KYC_FIELD_DEFINITION_RULE,
                severity: sev,
                category: 'network',
                message: `Asset "${assetCode}" KYC field "${category}.${fieldName}" does not conform to the SEP-9 standard`,
                path: fieldPath,
                helpUri: SEP9_SPEC,
                suggestion: `Use a standard SEP-9 field name (e.g., first_name, last_name, mobile_number, email_address).`,
              });
            }
          }
        }
      }
    }
  }

  return diagnostics;
}

/** Registered rules for SEP-31 KYC matrix validator */
export const sep31KycRules: Rule[] = [
  {
    id: INVALID_KYC_FIELD_DEFINITION_RULE,
    category: 'network',
    severity: 'error',
    description: 'DIRECT_PAYMENT_SERVER /info field definitions must be valid and conform to SEP-9',
    run() {},
  },
  {
    id: MISSING_SENDER_KYC_DECLARATION_RULE,
    category: 'network',
    severity: 'warning',
    description: 'DIRECT_PAYMENT_SERVER /info assets must declare sender KYC requirements',
    run() {},
  },
];

export const sep31KycRuleIds: readonly string[] = sep31KycRules.map((r) => r.id);
