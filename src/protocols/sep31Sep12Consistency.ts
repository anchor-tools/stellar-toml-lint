/**
 * Cross-protocol consistency engine for SEP-31 `/info` and SEP-12
 * `/customer`.
 *
 * A SEP-31 receiving anchor advertises its asset corridors in `GET /info`:
 * which customer types (if any) the sending anchor must KYC through SEP-12,
 * and, in the deprecated `fields.transaction` object, the extra fields a
 * sending anchor must collect for a payment. SEP-12 is where those fields are
 * actually defined, and a field that is required in one protocol but absent,
 * optional, or typed differently in the other breaks the sending anchor at
 * `POST /transactions` time.
 *
 * The engine fetches both documents and compares every corridor in both
 * directions:
 *
 *   SEP-31 -> SEP-12: every advertised transaction field must exist in the
 *   SEP-12 schema for the corridor's sender and receiver customer types, with
 *   the same optional/mandatory flag, description, choices and value type.
 *
 *   SEP-12 -> SEP-31: a required custom field that only SEP-12 knows about is
 *   reported as orphaned, because no sending anchor can discover it from
 *   `/info`. Standard SEP-9 KYC fields are exempt: SEP-9 fields are collected
 *   through SEP-12 by design and are not transaction fields.
 *
 * Type compatibility follows the SEP-9 field dictionary: `birth_date`,
 * `id_issue_date`, `id_expiration_date` and `card.expiration_date` are `date`,
 * photo/proof-of-address fields are `binary`, `occupation` and
 * `organization.number_of_shareholders` are `number`, and the rest are
 * `string`. A date declared as a `string` is reported as non-canonical (both
 * encodings carry an ISO 8601 value) rather than incompatible.
 *
 * The audit is opt-in and network-bound. `--domain` (or the
 * `verify-sep31-sep12` command) is the only way it runs; an ordinary offline
 * lint never opens a connection.
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { SEP9_KYC_FIELDS } from '../rules/sep12-schema.js';
import { errorMessage, fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const SEP31_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md';
const SEP12_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0012.md';
const SEP9_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0009.md';

/** Rule ids emitted by {@link Sep31Sep12ConsistencyEngine}. */
export const SEP31_SEP12_RULES = {
  infoUnavailable: 'sep31/info-unavailable',
  infoMalformed: 'sep31/info-malformed',
  fieldDescriptionMissing: 'sep31/field-description-missing',
  fieldOrphaned: 'sep31/field-orphaned',
  optionalFlagMismatch: 'sep31/optional-flag-mismatch',
  descriptionMismatch: 'sep31/description-mismatch',
  choicesMismatch: 'sep31/choices-mismatch',
  choicesMissing: 'sep31/choices-missing',
  customerTypeDescriptionMissing: 'sep31/customer-type-description-missing',
  deprecatedTypeNotAdvertised: 'sep31/deprecated-type-not-advertised',
  transactionFieldsWithoutType: 'sep31/transaction-fields-without-customer-type',
  orphanedSep12Field: 'sep31/orphaned-sep12-required-field',
  customerTypeNotFound: 'sep12/customer-type-not-found',
  customerSchemaUnauthorized: 'sep12/customer-schema-unauthorized',
  customerSchemaUnreachable: 'sep12/customer-schema-unreachable',
  customerSchemaMalformed: 'sep12/customer-schema-malformed',
  customerTypeMismatch: 'sep12/customer-type-mismatch',
  customerSchemaMissing: 'sep12/customer-schema-missing',
  fieldTypeMissing: 'sep12/field-type-missing',
  fieldTypeInvalid: 'sep12/field-type-invalid',
  fieldTypeIncompatible: 'sep12/field-type-incompatible',
  fieldTypeNoncanonical: 'sep12/field-type-noncanonical',
} as const;

const RULES = SEP31_SEP12_RULES;

export type CustomerRole = 'sender' | 'receiver';
export type DiscrepancyRole = CustomerRole | 'transaction';
export type Sep12FieldType = 'string' | 'binary' | 'number' | 'date';

const VALID_FIELD_TYPES = new Set<string>(['string', 'binary', 'number', 'date']);

/**
 * The SEP-9 fields whose canonical type is not `string`. Every other SEP-9
 * field is a string; a custom field has no canonical type at all.
 */
export const SEP9_FIELD_TYPES: Readonly<Record<string, Sep12FieldType>> = {
  birth_date: 'date',
  id_issue_date: 'date',
  id_expiration_date: 'date',
  'card.expiration_date': 'date',
  occupation: 'number',
  'organization.number_of_shareholders': 'number',
  photo_id_front: 'binary',
  photo_id_back: 'binary',
  notary_approval_of_photo_id: 'binary',
  photo_proof_residence: 'binary',
  proof_of_income: 'binary',
  proof_of_liveness: 'binary',
  'organization.photo_incorporation_doc': 'binary',
  'organization.photo_proof_address': 'binary',
};

/** The SEP-9 type for `field`, or `undefined` for a non-standard field name. */
export function canonicalSep9Type(field: string): Sep12FieldType | undefined {
  const explicit = SEP9_FIELD_TYPES[field];
  if (explicit !== undefined) return explicit;
  return SEP9_KYC_FIELDS.has(field) ? 'string' : undefined;
}

/** One field definition, as it appears in SEP-31 or SEP-12 responses. */
export interface FieldDefinition {
  type?: string;
  description?: string;
  optional?: boolean;
  choices?: string[];
}

/** A SEP-31 `/info` customer type entry. */
export interface Sep31CustomerType {
  type: string;
  description?: string;
}

/** One asset corridor from SEP-31 `/info`. */
export interface Sep31Corridor {
  asset: string;
  sender: Sep31CustomerType[];
  receiver: Sep31CustomerType[];
  deprecatedSenderType?: string;
  deprecatedReceiverType?: string;
  transactionFields: Record<string, FieldDefinition>;
}

/** A parsed SEP-12 `GET /customer` response for one customer type. */
export interface Sep12Schema {
  type?: string;
  status?: string;
  fields: Record<string, FieldDefinition>;
  providedFields: Record<string, FieldDefinition>;
  /** `true` when the response carried a `fields` object, even an empty one. */
  hasFields: boolean;
  /** `true` when the response carried a `provided_fields` object. */
  hasProvidedFields: boolean;
}

/** The outcome of one SEP-12 schema lookup, including fetch failures. */
export interface Sep12SchemaResult {
  schema?: Sep12Schema;
  error?: string;
  /** HTTP status, when the lookup failed with a response. */
  status?: number;
}

export type SchemaLookup =
  | ReadonlyMap<string, Sep12SchemaResult>
  | Record<string, Sep12SchemaResult>;

export interface ConsistencyServers {
  directPaymentServer: string;
  kycServer: string;
}

export interface ConsistencyEngineOptions {
  fetchImpl?: typeof fetch;
  rules?: RuleOverrides;
  timeoutMs?: number;
}

/** One contradiction between SEP-31 `/info` and SEP-12 `/customer`. */
export interface Discrepancy {
  rule: string;
  severity: Severity;
  asset: string;
  role: DiscrepancyRole;
  customerType?: string;
  field?: string;
  message: string;
  suggestion: string;
  path: string;
  helpUri: string;
  expected?: string;
  actual?: string;
}

/** Per-corridor summary, useful in JSON output and terminal reports. */
export interface CorridorSummary {
  asset: string;
  senderTypes: string[];
  receiverTypes: string[];
  transactionFields: string[];
}

export interface ConsistencyReport {
  ok: boolean;
  directPaymentServer?: string;
  kycServer?: string;
  corridors: CorridorSummary[];
  discrepancies: Discrepancy[];
  diagnostics: Diagnostic[];
  counts: Record<Severity, number>;
}

interface EmitInput {
  rule: string;
  fallback: 'error' | 'warning';
  message: string;
  asset: string;
  role: DiscrepancyRole;
  customerType?: string;
  field?: string;
  suggestion: string;
  helpUri: string;
  path: string;
  expected?: string;
  actual?: string;
}

function slashless(url: string): string {
  return url.replace(/\/+$/, '');
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function normalizeText(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

/** Compares choice lists as sets, so ordering is never a discrepancy. */
function sameChoices(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  const l = [...left].sort();
  const r = [...right].sort();
  return l.every((value, index) => value === r[index]);
}

function parseChoices(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter(isString);
}

/** Parses one field definition, ignoring malformed properties. */
function parseFieldDefinition(value: unknown): FieldDefinition | undefined {
  if (!isRecord(value)) return undefined;
  const field: FieldDefinition = {};
  if (isString(value.type)) field.type = value.type;
  if (isString(value.description)) field.description = value.description;
  if (typeof value.optional === 'boolean') field.optional = value.optional;
  const choices = parseChoices(value.choices);
  if (choices !== undefined) field.choices = choices;
  return field;
}

/**
 * Parses a `fields`/`provided_fields` object. SEP-12 defines these as objects
 * keyed by field name; some anchors publish a bare array of names, which is
 * accepted as `{ name: {} }` so the names are still compared.
 */
function parseFieldCollection(value: unknown): Record<string, FieldDefinition> | undefined {
  if (Array.isArray(value)) {
    const out: Record<string, FieldDefinition> = {};
    for (const name of value.filter(isString)) out[name] = {};
    return out;
  }
  if (!isRecord(value)) return undefined;

  const out: Record<string, FieldDefinition> = {};
  for (const [name, definition] of Object.entries(value)) {
    out[name] = parseFieldDefinition(definition) ?? {};
  }
  return out;
}

/**
 * Parses a SEP-12 `GET /customer` response. Responses that publish a `types`
 * map instead of a single type's schema are narrowed to `requestedType`.
 */
export function parseSep12CustomerSchema(
  body: unknown,
  requestedType?: string,
): Sep12Schema | undefined {
  if (!isRecord(body)) return undefined;

  let source = body;
  if (requestedType !== undefined && isRecord(body.types)) {
    const entry = body.types[requestedType];
    if (isRecord(entry)) source = entry;
  }

  const fields = parseFieldCollection(source.fields);
  const providedFields = parseFieldCollection(source.provided_fields);

  const schema: Sep12Schema = {
    fields: fields ?? {},
    providedFields: providedFields ?? {},
    hasFields: fields !== undefined,
    hasProvidedFields: providedFields !== undefined,
  };
  if (isString(source.type)) schema.type = source.type;
  if (isString(source.status)) schema.status = source.status;
  return schema;
}

/** Parses a `types` declaration from SEP-31 `/info` (object or array form). */
function parseCustomerTypes(value: unknown): Sep31CustomerType[] {
  const out: Sep31CustomerType[] = [];
  if (Array.isArray(value)) {
    for (const entry of value) {
      if (isString(entry)) {
        out.push({ type: entry });
      } else if (isRecord(entry) && isString(entry.type)) {
        const type: Sep31CustomerType = { type: entry.type };
        if (isString(entry.description)) type.description = entry.description;
        out.push(type);
      }
    }
    return out;
  }
  if (!isRecord(value)) return out;

  for (const [type, definition] of Object.entries(value)) {
    const entry: Sep31CustomerType = { type };
    if (isString(definition)) entry.description = definition;
    else if (isRecord(definition) && isString(definition.description)) {
      entry.description = definition.description;
    }
    out.push(entry);
  }
  return out;
}

function parseTransactionFields(value: unknown): Record<string, FieldDefinition> {
  if (!isRecord(value)) return {};
  const out: Record<string, FieldDefinition> = {};
  for (const [name, definition] of Object.entries(value)) {
    out[name] = parseFieldDefinition(definition) ?? {};
  }
  return out;
}

/**
 * Extracts every asset corridor from a SEP-31 `/info` body. Malformed entries
 * are skipped; {@link Sep31Sep12ConsistencyEngine.analyze} reports the ones
 * that make the response unusable.
 */
export function extractSep31Corridors(info: unknown): Sep31Corridor[] {
  if (!isRecord(info) || !isRecord(info.receive)) return [];

  const corridors: Sep31Corridor[] = [];
  for (const [asset, raw] of Object.entries(info.receive)) {
    if (!isRecord(raw)) continue;
    const sep12 = isRecord(raw.sep12) ? raw.sep12 : {};
    const sender = isRecord(sep12.sender) ? sep12.sender.types : undefined;
    const receiver = isRecord(sep12.receiver) ? sep12.receiver.types : undefined;
    const fields = isRecord(raw.fields) ? raw.fields : undefined;

    const corridor: Sep31Corridor = {
      asset,
      sender: parseCustomerTypes(sender),
      receiver: parseCustomerTypes(receiver),
      transactionFields: parseTransactionFields(fields?.transaction),
    };
    if (isString(raw.sender_sep12_type)) corridor.deprecatedSenderType = raw.sender_sep12_type;
    if (isString(raw.receiver_sep12_type)) corridor.deprecatedReceiverType = raw.receiver_sep12_type;
    corridors.push(corridor);
  }
  return corridors;
}

/** Every customer type advertised anywhere in `corridors`, deduplicated. */
export function collectCustomerTypes(corridors: readonly Sep31Corridor[]): string[] {
  const types = new Set<string>();
  for (const corridor of corridors) {
    for (const role of ['sender', 'receiver'] as const) {
      for (const entry of roleTypes(corridor, role)) types.add(entry.type);
    }
  }
  return [...types];
}

/** The types for one role, falling back to the deprecated single-type field. */
function roleTypes(corridor: Sep31Corridor, role: CustomerRole): Sep31CustomerType[] {
  const declared = corridor[role];
  if (declared.length > 0) return declared;
  const deprecated =
    role === 'sender' ? corridor.deprecatedSenderType : corridor.deprecatedReceiverType;
  return deprecated === undefined ? [] : [{ type: deprecated }];
}

function lookupResult(lookup: SchemaLookup, type: string): Sep12SchemaResult | undefined {
  if (lookup instanceof Map) return lookup.get(type);
  return hasOwn(lookup as Record<string, Sep12SchemaResult>, type)
    ? (lookup as Record<string, Sep12SchemaResult>)[type]
    : undefined;
}

function fieldPath(
  asset: string,
  role: DiscrepancyRole,
  customerType: string | undefined,
  field: string,
): string {
  const typePart = customerType === undefined ? '' : `sep12.${role}.types.${customerType}`;
  return `DIRECT_PAYMENT_SERVER.receive.${asset}${typePart === '' ? '' : `.${typePart}`}.fields.${field}`;
}

function emptyCounts(): Record<Severity, number> {
  return { error: 0, warning: 0, info: 0 };
}

function finalize(
  corridors: CorridorSummary[],
  discrepancies: Discrepancy[],
  counts: Record<Severity, number>,
): ConsistencyReport {
  return {
    ok: counts.error === 0,
    corridors,
    discrepancies,
    diagnostics: diagnosticsFor(discrepancies),
    counts,
  };
}

function diagnosticsFor(discrepancies: readonly Discrepancy[]): Diagnostic[] {
  return discrepancies.map((discrepancy) => ({
    rule: discrepancy.rule,
    severity: discrepancy.severity,
    category: 'sep12',
    message: discrepancy.message,
    path: discrepancy.path,
    helpUri: discrepancy.helpUri,
    suggestion: discrepancy.suggestion,
  }));
}

/**
 * Checks SEP-31 `/info` against the SEP-12 customer schemas the anchor serves.
 *
 * The engine is stateless between calls: `verify` fetches both documents, and
 * `analyze` runs the same comparison over already-parsed data, which keeps the
 * rules testable without a network.
 */
export class Sep31Sep12ConsistencyEngine {
  private readonly fetchImpl: typeof fetch;
  private readonly rules: RuleOverrides | undefined;
  private readonly timeoutMs: number;

  constructor(options: ConsistencyEngineOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.rules = options.rules;
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  /** Fetches SEP-31 `/info` and every advertised SEP-12 customer schema. */
  async verify(servers: ConsistencyServers): Promise<ConsistencyReport> {
    const directPaymentServer = slashless(servers.directPaymentServer);
    const kycServer = slashless(servers.kycServer);

    let info: unknown;
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${directPaymentServer}/info`,
        {},
        this.timeoutMs,
      );
      if (!response.ok) {
        return this.reportFetchFailure(
          directPaymentServer,
          kycServer,
          `SEP-31 GET /info returned HTTP ${response.status}`,
        );
      }
      info = (await response.json()) as unknown;
    } catch (error) {
      return this.reportFetchFailure(
        directPaymentServer,
        kycServer,
        `Could not reach SEP-31 GET /info at ${directPaymentServer}/info: ${errorMessage(error)}`,
      );
    }

    const corridors = extractSep31Corridors(info);
    const schemas = new Map<string, Sep12SchemaResult>();
    await Promise.all(
      collectCustomerTypes(corridors).map(async (type) => {
        schemas.set(type, await this.fetchCustomerSchema(kycServer, type));
      }),
    );

    const report = this.analyze(info, schemas);
    report.directPaymentServer = directPaymentServer;
    report.kycServer = kycServer;
    return report;
  }

  /** Convenience wrapper for the `stellar.toml` document. */
  async verifyDocument(doc: Record<string, unknown>): Promise<ConsistencyReport> {
    const direct = doc.DIRECT_PAYMENT_SERVER;
    const kyc = doc.KYC_SERVER;
    if (!isString(direct) || !isUrl(direct) || !isString(kyc) || !isUrl(kyc)) {
      return this.silentReport();
    }
    return this.verify({ directPaymentServer: direct, kycServer: kyc });
  }

  /**
   * Compares an already-fetched `/info` body with already-fetched schemas.
   *
   * `schemas` is keyed by customer type. A type with no entry is reported as a
   * missing schema, which is what a `GET /customer` 404 means to a sending
   * anchor.
   */
  analyze(info: unknown, schemas: SchemaLookup): ConsistencyReport {
    const discrepancies: Discrepancy[] = [];
    const corridors = extractSep31Corridors(info);

    if (!isRecord(info) || !isRecord(info.receive)) {
      this.emit(discrepancies, {
        rule: RULES.infoMalformed,
        fallback: 'warning',
        message: 'SEP-31 GET /info did not return an object with a receive map',
        asset: '*',
        role: 'transaction',
        suggestion: 'Return the JSON object SEP-31 defines, with one receive entry per asset.',
        helpUri: SEP31_SPEC,
        path: 'DIRECT_PAYMENT_SERVER/info',
      });
      return this.buildReport(corridors, discrepancies);
    }

    if (corridors.length === 0) {
      this.emit(discrepancies, {
        rule: RULES.infoMalformed,
        fallback: 'warning',
        message: 'SEP-31 GET /info advertises no usable asset corridors',
        asset: '*',
        role: 'transaction',
        suggestion: 'Add at least one asset to the receive map, or remove DIRECT_PAYMENT_SERVER.',
        helpUri: SEP31_SPEC,
        path: 'DIRECT_PAYMENT_SERVER/info.receive',
      });
      return this.buildReport(corridors, discrepancies);
    }

    for (const corridor of corridors) {
      this.analyzeCorridor(corridor, schemas, discrepancies);
    }
    return this.buildReport(corridors, discrepancies);
  }

  private analyzeCorridor(
    corridor: Sep31Corridor,
    schemas: SchemaLookup,
    discrepancies: Discrepancy[],
  ): void {
    const transactionFields = Object.keys(corridor.transactionFields);
    const hasTypes = corridor.sender.length > 0 || corridor.receiver.length > 0;

    if (
      transactionFields.length > 0 &&
      !hasTypes &&
      corridor.deprecatedSenderType === undefined &&
      corridor.deprecatedReceiverType === undefined
    ) {
      this.emit(discrepancies, {
        rule: RULES.transactionFieldsWithoutType,
        fallback: 'warning',
        message: `Corridor "${corridor.asset}" advertises transaction fields but no SEP-12 customer types`,
        asset: corridor.asset,
        role: 'transaction',
        suggestion:
          'Add sep12.sender.types / sep12.receiver.types so a sending anchor knows which schema applies.',
        helpUri: SEP31_SPEC,
        path: `DIRECT_PAYMENT_SERVER.receive.${corridor.asset}.fields.transaction`,
      });
    }

    for (const field of transactionFields) {
      const definition = corridor.transactionFields[field] as FieldDefinition;
      if (definition.description === undefined || definition.description.trim() === '') {
        this.emit(discrepancies, {
          rule: RULES.fieldDescriptionMissing,
          fallback: 'warning',
          message: `Transaction field "${field}" in corridor "${corridor.asset}" has no description`,
          asset: corridor.asset,
          role: 'transaction',
          field,
          suggestion:
            'Give the field a human-readable description; sending anchors show it to their customers.',
          helpUri: SEP31_SPEC,
          path: fieldPath(corridor.asset, 'transaction', undefined, field),
        });
      }
    }

    for (const role of ['sender', 'receiver'] as const) {
      const types = roleTypes(corridor, role);
      this.checkDeprecatedType(corridor, role, types, discrepancies);

      for (const entry of types) {
        if (entry.description === undefined || entry.description.trim() === '') {
          this.emit(discrepancies, {
            rule: RULES.customerTypeDescriptionMissing,
            fallback: 'warning',
            message: `Customer type "${entry.type}" for corridor "${corridor.asset}" has no description`,
            asset: corridor.asset,
            role,
            customerType: entry.type,
            suggestion: 'Add a description so a sending anchor can pick the right customer type.',
            helpUri: SEP31_SPEC,
            path: `DIRECT_PAYMENT_SERVER.receive.${corridor.asset}.sep12.${role}.types.${entry.type}`,
          });
        }

        this.checkCustomerType(corridor, role, entry.type, schemas, discrepancies);
      }
    }
  }

  private checkDeprecatedType(
    corridor: Sep31Corridor,
    role: CustomerRole,
    types: readonly Sep31CustomerType[],
    discrepancies: Discrepancy[],
  ): void {
    if (role === 'sender') {
      const deprecated = corridor.deprecatedSenderType;
      if (deprecated === undefined) return;
      if (corridor.sender.length === 0) return;
      if (types.some((entry) => entry.type === deprecated)) return;
      this.emit(discrepancies, {
        rule: RULES.deprecatedTypeNotAdvertised,
        fallback: 'warning',
        message: `Corridor "${corridor.asset}" deprecates sender_sep12_type "${deprecated}" but does not list it in sep12.sender.types`,
        asset: corridor.asset,
        role: 'sender',
        customerType: deprecated,
        suggestion: `Add "${deprecated}" to sep12.sender.types or remove sender_sep12_type.`,
        helpUri: SEP31_SPEC,
        path: `DIRECT_PAYMENT_SERVER.receive.${corridor.asset}.sender_sep12_type`,
      });
      return;
    }

    const deprecated = corridor.deprecatedReceiverType;
    if (deprecated === undefined) return;
    if (corridor.receiver.length === 0) return;
    if (types.some((entry) => entry.type === deprecated)) return;
    this.emit(discrepancies, {
      rule: RULES.deprecatedTypeNotAdvertised,
      fallback: 'warning',
      message: `Corridor "${corridor.asset}" deprecates receiver_sep12_type "${deprecated}" but does not list it in sep12.receiver.types`,
      asset: corridor.asset,
      role: 'receiver',
      customerType: deprecated,
      suggestion: `Add "${deprecated}" to sep12.receiver.types or remove receiver_sep12_type.`,
      helpUri: SEP31_SPEC,
      path: `DIRECT_PAYMENT_SERVER.receive.${corridor.asset}.receiver_sep12_type`,
    });
  }

  private checkCustomerType(
    corridor: Sep31Corridor,
    role: CustomerRole,
    type: string,
    schemas: SchemaLookup,
    discrepancies: Discrepancy[],
  ): void {
    const result = lookupResult(schemas, type);
    const basePath = `DIRECT_PAYMENT_SERVER.receive.${corridor.asset}.sep12.${role}.types.${type}`;

    if (result === undefined) {
      this.emit(discrepancies, {
        rule: RULES.customerSchemaMissing,
        fallback: 'error',
        message: `SEP-31 advertises customer type "${type}" for ${role} on "${corridor.asset}", but no SEP-12 schema was retrieved`,
        asset: corridor.asset,
        role,
        customerType: type,
        suggestion: `Implement GET KYC_SERVER/customer?type=${type}, or remove the type from /info.`,
        helpUri: SEP12_SPEC,
        path: basePath,
      });
      return;
    }

    if (result.schema === undefined) {
      this.reportLookupFailure(corridor, role, type, result, basePath, discrepancies);
      return;
    }

    const schema = result.schema;
    if (schema.type !== undefined && schema.type !== type) {
      this.emit(discrepancies, {
        rule: RULES.customerTypeMismatch,
        fallback: 'error',
        message: `SEP-12 returned type "${schema.type}" for a request for "${type}"`,
        asset: corridor.asset,
        role,
        customerType: type,
        suggestion: `Return the schema for "${type}", or omit the response's type field.`,
        helpUri: SEP12_SPEC,
        path: basePath,
        expected: type,
        actual: schema.type,
      });
    }

    if (!schema.hasFields && !schema.hasProvidedFields) {
      this.emit(discrepancies, {
        rule: RULES.customerSchemaMissing,
        fallback: 'error',
        message: `SEP-12 returned no fields or provided_fields schema for customer type "${type}"`,
        asset: corridor.asset,
        role,
        customerType: type,
        suggestion:
          'Return the fields a customer of this type must provide; an empty object means no KYC is needed.',
        helpUri: SEP12_SPEC,
        path: basePath,
      });
      return;
    }

    for (const [field, definition] of Object.entries(corridor.transactionFields)) {
      this.compareField(corridor, role, type, field, definition, schema, discrepancies);
    }

    // Type compatibility applies to every SEP-12 field, not only the fields
    // that happen to be mirrored in the deprecated SEP-31 transaction map: a
    // wallet reading `birth_date` as a string still breaks against a consumer
    // that expects a `date`.
    const compared = new Set(Object.keys(corridor.transactionFields));
    const seen = new Set<string>();
    for (const collection of [schema.fields, schema.providedFields]) {
      for (const [field, definition] of Object.entries(collection)) {
        if (compared.has(field) || seen.has(field)) continue;
        seen.add(field);
        this.validateFieldType(
          corridor,
          role,
          type,
          field,
          definition,
          fieldPath(corridor.asset, role, type, field),
          discrepancies,
        );
      }
    }

    // Reverse direction: a required custom field only SEP-12 knows about is
    // undiscoverable from /info. Standard SEP-9 fields are expected to live
    // only in SEP-12, so they are not orphans.
    if (schema.hasFields) {
      for (const [field, definition] of Object.entries(schema.fields)) {
        if (definition.optional === true) continue;
        if (SEP9_KYC_FIELDS.has(field)) continue;
        if (hasOwn(corridor.transactionFields, field)) continue;
        this.emit(discrepancies, {
          rule: RULES.orphanedSep12Field,
          fallback: 'warning',
          message: `SEP-12 requires "${field}" for ${role} type "${type}", but SEP-31 /info for "${corridor.asset}" does not advertise it`,
          asset: corridor.asset,
          role,
          customerType: type,
          field,
          suggestion:
            'Advertise the field in fields.transaction, or stop requiring it for this customer type.',
          helpUri: SEP31_SPEC,
          path: basePath,
        });
      }
    }
  }

  private reportLookupFailure(
    corridor: Sep31Corridor,
    role: CustomerRole,
    type: string,
    result: Sep12SchemaResult,
    basePath: string,
    discrepancies: Discrepancy[],
  ): void {
    if (result.status === 404) {
      this.emit(discrepancies, {
        rule: RULES.customerTypeNotFound,
        fallback: 'error',
        message: `SEP-31 advertises customer type "${type}" but SEP-12 GET /customer?type=${type} returned HTTP 404`,
        asset: corridor.asset,
        role,
        customerType: type,
        suggestion: `Return a schema for "${type}" (or an empty fields object), or remove the type from /info.`,
        helpUri: SEP12_SPEC,
        path: basePath,
      });
      return;
    }
    if (result.status === 401 || result.status === 403) {
      this.emit(discrepancies, {
        rule: RULES.customerSchemaUnauthorized,
        fallback: 'warning',
        message: `SEP-12 GET /customer?type=${type} requires authentication (HTTP ${result.status}); the schema could not be verified`,
        asset: corridor.asset,
        role,
        customerType: type,
        suggestion:
          'Re-run with a SEP-10 JWT for a sending anchor your server trusts, or allow unauthenticated schema discovery.',
        helpUri: SEP12_SPEC,
        path: basePath,
      });
      return;
    }
    if (result.status !== undefined) {
      this.emit(discrepancies, {
        rule: RULES.customerSchemaUnreachable,
        fallback: 'warning',
        message: `SEP-12 GET /customer?type=${type} returned HTTP ${result.status}`,
        asset: corridor.asset,
        role,
        customerType: type,
        suggestion: 'Confirm KYC_SERVER answers /customer with the JSON schema.',
        helpUri: SEP12_SPEC,
        path: basePath,
      });
      return;
    }
    this.emit(discrepancies, {
      rule: RULES.customerSchemaMalformed,
      fallback: 'warning',
      message: `SEP-12 GET /customer?type=${type} did not return a usable JSON schema${
        result.error === undefined ? '' : `: ${result.error}`
      }`,
      asset: corridor.asset,
      role,
      customerType: type,
      suggestion: 'Return a JSON object with a fields map, as SEP-12 defines.',
      helpUri: SEP12_SPEC,
      path: basePath,
    });
  }

  private compareField(
    corridor: Sep31Corridor,
    role: CustomerRole,
    type: string,
    field: string,
    sep31: FieldDefinition,
    schema: Sep12Schema,
    discrepancies: Discrepancy[],
  ): void {
    const requiredDefinition = schema.fields[field];
    const providedDefinition = schema.providedFields[field];
    const sep12 = requiredDefinition ?? providedDefinition;
    const path = fieldPath(corridor.asset, role, type, field);

    if (sep12 === undefined) {
      this.emit(discrepancies, {
        rule: RULES.fieldOrphaned,
        fallback: 'error',
        message: `Transaction field "${field}" is declared in SEP-31 /info for "${corridor.asset}" but is not defined by SEP-12 type "${type}"`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: `Add "${field}" to the SEP-12 schema for "${type}", or remove it from /info.`,
        helpUri: SEP12_SPEC,
        path,
      });
      return;
    }

    // Mandatory in SEP-31 but optional in SEP-12 means the anchor enforces a
    // weaker rule than it advertises; optional in SEP-31 but mandatory in
    // SEP-12 is the failure mode: the sending anchor may omit the field and
    // the anchor rejects the customer.
    if (requiredDefinition !== undefined) {
      const sep31Optional = sep31.optional === true;
      const sep12Optional = requiredDefinition.optional === true;
      if (sep31Optional !== sep12Optional) {
        this.emit(discrepancies, {
          rule: RULES.optionalFlagMismatch,
          fallback: 'error',
          message: `Field "${field}" for "${corridor.asset}" is ${sep31Optional ? 'optional' : 'required'} in SEP-31 /info but ${sep12Optional ? 'optional' : 'required'} in SEP-12 type "${type}"`,
          asset: corridor.asset,
          role,
          customerType: type,
          field,
          suggestion: 'Use the same optional flag in /info and in the SEP-12 schema.',
          helpUri: SEP12_SPEC,
          path,
          expected: `optional: ${sep12Optional}`,
          actual: `optional: ${sep31Optional}`,
        });
      }
    }

    this.compareFieldType(corridor, role, type, field, sep31, sep12, path, discrepancies);
    this.compareFieldMetadata(corridor, role, type, field, sep31, sep12, path, discrepancies);
  }

  private compareFieldType(
    corridor: Sep31Corridor,
    role: CustomerRole,
    type: string,
    field: string,
    sep31: FieldDefinition,
    sep12: FieldDefinition,
    path: string,
    discrepancies: Discrepancy[],
  ): void {
    const sep12Type = sep12.type;
    if (sep31.type !== undefined && sep12Type !== undefined && sep31.type !== sep12Type) {
      this.emit(discrepancies, {
        rule: RULES.fieldTypeIncompatible,
        fallback: 'error',
        message: `Field "${field}" is type "${sep31.type}" in SEP-31 /info but "${sep12Type}" in SEP-12`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: 'Use one value type for the field in both protocols.',
        helpUri: SEP12_SPEC,
        path,
        expected: sep31.type,
        actual: sep12Type,
      });
      return;
    }

    this.validateFieldType(corridor, role, type, field, sep12, path, discrepancies);
  }

  /**
   * Validates a SEP-12 field's type against the SEP-12 enum and, for a
   * standard SEP-9 field, against the SEP-9 dictionary.
   */
  private validateFieldType(
    corridor: Sep31Corridor,
    role: CustomerRole,
    type: string,
    field: string,
    sep12: FieldDefinition,
    path: string,
    discrepancies: Discrepancy[],
  ): void {
    const sep12Type = sep12.type;
    if (sep12Type === undefined) {
      this.emit(discrepancies, {
        rule: RULES.fieldTypeMissing,
        fallback: 'warning',
        message: `SEP-12 field "${field}" for "${corridor.asset}" has no type`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: 'Declare the field as string, binary, number, or date.',
        helpUri: SEP12_SPEC,
        path,
      });
      return;
    }

    if (!VALID_FIELD_TYPES.has(sep12Type)) {
      this.emit(discrepancies, {
        rule: RULES.fieldTypeInvalid,
        fallback: 'error',
        message: `SEP-12 field "${field}" uses type "${sep12Type}", which SEP-12 does not define`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: 'Use one of string, binary, number, or date.',
        helpUri: SEP12_SPEC,
        path,
        expected: 'string, binary, number, or date',
        actual: sep12Type,
      });
      return;
    }

    const canonical = canonicalSep9Type(field);
    if (canonical === undefined || canonical === sep12Type) return;

    // A date encoded as a string still carries ISO 8601 text; flag it as
    // non-canonical instead of failing an otherwise interoperable anchor.
    if (canonical === 'date' && sep12Type === 'string') {
      this.emit(discrepancies, {
        rule: RULES.fieldTypeNoncanonical,
        fallback: 'warning',
        message: `SEP-9 field "${field}" is declared as "string"; its canonical type is "date"`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: 'Declare the field as date and send an ISO 8601 date (YYYY-MM-DD).',
        helpUri: SEP9_SPEC,
        path,
        expected: 'date',
        actual: sep12Type,
      });
      return;
    }

    this.emit(discrepancies, {
      rule: RULES.fieldTypeIncompatible,
      fallback: 'error',
      message: `SEP-9 field "${field}" is declared as "${sep12Type}" but its canonical type is "${canonical}"`,
      asset: corridor.asset,
      role,
      customerType: type,
      field,
      suggestion: `Declare the field as ${canonical}.`,
      helpUri: SEP9_SPEC,
      path,
      expected: canonical,
      actual: sep12Type,
    });
  }

  private compareFieldMetadata(
    corridor: Sep31Corridor,
    role: CustomerRole,
    type: string,
    field: string,
    sep31: FieldDefinition,
    sep12: FieldDefinition,
    path: string,
    discrepancies: Discrepancy[],
  ): void {
    if (sep12.description === undefined || sep12.description.trim() === '') {
      this.emit(discrepancies, {
        rule: RULES.descriptionMismatch,
        fallback: 'warning',
        message: `SEP-12 field "${field}" for "${corridor.asset}" has no description`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: 'Describe the field in the SEP-12 schema, as /info does.',
        helpUri: SEP12_SPEC,
        path,
      });
    } else if (
      sep31.description !== undefined &&
      normalizeText(sep31.description) !== normalizeText(sep12.description)
    ) {
      this.emit(discrepancies, {
        rule: RULES.descriptionMismatch,
        fallback: 'warning',
        message: `Field "${field}" has a different description in SEP-31 /info and SEP-12`,
        asset: corridor.asset,
        role,
        customerType: type,
        field,
        suggestion: 'Use the same description in both protocols.',
        helpUri: SEP12_SPEC,
        path,
        expected: sep31.description,
        actual: sep12.description,
      });
    }

    if (sep31.choices !== undefined) {
      if (sep12.choices === undefined) {
        this.emit(discrepancies, {
          rule: RULES.choicesMissing,
          fallback: 'warning',
          message: `Field "${field}" lists choices in SEP-31 /info but not in SEP-12`,
          asset: corridor.asset,
          role,
          customerType: type,
          field,
          suggestion: 'Publish the same choices in the SEP-12 schema, or remove them from /info.',
          helpUri: SEP12_SPEC,
          path,
          expected: sep31.choices.join(', '),
        });
      } else if (!sameChoices(sep31.choices, sep12.choices)) {
        this.emit(discrepancies, {
          rule: RULES.choicesMismatch,
          fallback: 'error',
          message: `Field "${field}" allows different choices in SEP-31 /info and SEP-12`,
          asset: corridor.asset,
          role,
          customerType: type,
          field,
          suggestion: 'Use the same set of allowed values in both protocols.',
          helpUri: SEP12_SPEC,
          path,
          expected: sep31.choices.join(', '),
          actual: sep12.choices.join(', '),
        });
      }
    }
  }

  private emit(discrepancies: Discrepancy[], input: EmitInput): void {
    const severity = severityFor(input.rule, input.fallback, this.rules);
    if (severity === undefined) return;

    const discrepancy: Discrepancy = {
      rule: input.rule,
      severity,
      asset: input.asset,
      role: input.role,
      message: input.message,
      suggestion: input.suggestion,
      path: input.path,
      helpUri: input.helpUri,
    };
    if (input.customerType !== undefined) discrepancy.customerType = input.customerType;
    if (input.field !== undefined) discrepancy.field = input.field;
    if (input.expected !== undefined) discrepancy.expected = input.expected;
    if (input.actual !== undefined) discrepancy.actual = input.actual;
    discrepancies.push(discrepancy);
  }

  private buildReport(
    corridors: readonly Sep31Corridor[],
    discrepancies: Discrepancy[],
  ): ConsistencyReport {
    const counts = emptyCounts();
    for (const discrepancy of discrepancies) counts[discrepancy.severity] += 1;

    const summaries = corridors.map((corridor) => ({
      asset: corridor.asset,
      senderTypes: roleTypes(corridor, 'sender').map((entry) => entry.type),
      receiverTypes: roleTypes(corridor, 'receiver').map((entry) => entry.type),
      transactionFields: Object.keys(corridor.transactionFields),
    }));
    return finalize(summaries, discrepancies, counts);
  }

  private reportFetchFailure(
    directPaymentServer: string,
    kycServer: string,
    message: string,
  ): ConsistencyReport {
    const discrepancies: Discrepancy[] = [];
    this.emit(discrepancies, {
      rule: RULES.infoUnavailable,
      fallback: 'warning',
      message,
      asset: '*',
      role: 'transaction',
      suggestion:
        'Confirm DIRECT_PAYMENT_SERVER points at a live SEP-31 server whose /info endpoint answers JSON.',
      helpUri: SEP31_SPEC,
      path: 'DIRECT_PAYMENT_SERVER/info',
    });
    const counts = emptyCounts();
    for (const discrepancy of discrepancies) counts[discrepancy.severity] += 1;
    return {
      ...finalize([], discrepancies, counts),
      directPaymentServer,
      kycServer,
    };
  }

  private silentReport(): ConsistencyReport {
    return finalize([], [], emptyCounts());
  }

  private async fetchCustomerSchema(
    kycServer: string,
    type: string,
  ): Promise<Sep12SchemaResult> {
    const url = `${kycServer}/customer?type=${encodeURIComponent(type)}`;
    try {
      const response = await fetchWithTimeout(this.fetchImpl, url, {}, this.timeoutMs);
      if (!response.ok) return { error: `HTTP ${response.status}`, status: response.status };
      const body = (await response.json()) as unknown;
      const schema = parseSep12CustomerSchema(body, type);
      if (schema === undefined) return { error: 'response is not a JSON object' };
      return { schema };
    } catch (error) {
      return { error: errorMessage(error) };
    }
  }
}

/**
 * Runs the consistency audit for the servers a `stellar.toml` declares.
 * Silent when either `DIRECT_PAYMENT_SERVER` or `KYC_SERVER` is missing or not
 * a URL, so an ordinary lint run never opens a connection.
 */
export async function verifySep31Sep12(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Omit<ConsistencyEngineOptions, 'fetchImpl'> = {},
): Promise<ConsistencyReport> {
  const engine = new Sep31Sep12ConsistencyEngine({ ...options, fetchImpl });
  return engine.verifyDocument(doc);
}

/** Human-readable report for the CLI and `--format text`. */
export function renderSep31Sep12Report(report: ConsistencyReport): string {
  const lines: string[] = [];
  const left = report.directPaymentServer ?? 'SEP-31 /info';
  const right = report.kycServer ?? 'SEP-12 /customer';
  lines.push(`SEP-31 ↔ SEP-12 consistency: ${left} ↔ ${right}`);

  if (report.corridors.length === 0) {
    lines.push('No asset corridors could be inspected.');
  } else {
    lines.push(`Corridors: ${report.corridors.length}`);
    for (const corridor of report.corridors) {
      lines.push(`  ${corridor.asset}`);
      lines.push(
        `    sender: ${corridor.senderTypes.length === 0 ? '(none)' : corridor.senderTypes.join(', ')}`,
      );
      lines.push(
        `    receiver: ${corridor.receiverTypes.length === 0 ? '(none)' : corridor.receiverTypes.join(', ')}`,
      );
      if (corridor.transactionFields.length > 0) {
        lines.push(`    transaction fields: ${corridor.transactionFields.join(', ')}`);
      }
    }
  }

  if (report.discrepancies.length > 0) {
    lines.push(`Discrepancies: ${report.discrepancies.length}`);
    for (const discrepancy of report.discrepancies) {
      const scope = [
        discrepancy.asset,
        discrepancy.role,
        discrepancy.customerType,
        discrepancy.field,
      ]
        .filter((part): part is string => part !== undefined)
        .join(' / ');
      lines.push(`  [${discrepancy.severity}] ${discrepancy.rule} (${scope})`);
      lines.push(`    ${discrepancy.message}`);
      lines.push(`    fix: ${discrepancy.suggestion}`);
    }
  } else if (report.corridors.length > 0) {
    lines.push('No SEP-31 / SEP-12 discrepancies found.');
  }

  lines.push(
    `Summary: ${report.counts.error} error(s), ${report.counts.warning} warning(s), ${report.counts.info} info`,
  );
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep31Sep12Rules: Rule[] = [
  {
    id: RULES.infoUnavailable,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-31 GET /info should be reachable and answer JSON',
    run() {},
  },
  {
    id: RULES.infoMalformed,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-31 GET /info should advertise at least one usable asset corridor',
    run() {},
  },
  {
    id: RULES.fieldDescriptionMissing,
    category: 'sep12',
    severity: 'warning',
    description: 'Every SEP-31 transaction field should carry a description',
    run() {},
  },
  {
    id: RULES.fieldOrphaned,
    category: 'sep12',
    severity: 'error',
    description: 'Every field advertised in SEP-31 /info must exist in the SEP-12 schema',
    run() {},
  },
  {
    id: RULES.optionalFlagMismatch,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-31 /info and SEP-12 must agree on whether a field is optional',
    run() {},
  },
  {
    id: RULES.descriptionMismatch,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-31 /info and SEP-12 should describe a field the same way',
    run() {},
  },
  {
    id: RULES.choicesMismatch,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-31 /info and SEP-12 must allow the same field choices',
    run() {},
  },
  {
    id: RULES.choicesMissing,
    category: 'sep12',
    severity: 'warning',
    description: 'Choices advertised in SEP-31 /info should also appear in SEP-12',
    run() {},
  },
  {
    id: RULES.customerTypeDescriptionMissing,
    category: 'sep12',
    severity: 'warning',
    description: 'Every SEP-31 customer type should carry a description',
    run() {},
  },
  {
    id: RULES.deprecatedTypeNotAdvertised,
    category: 'sep12',
    severity: 'warning',
    description: 'A deprecated sender/receiver_sep12_type must also appear in sep12.types',
    run() {},
  },
  {
    id: RULES.transactionFieldsWithoutType,
    category: 'sep12',
    severity: 'warning',
    description: 'Corridors advertising transaction fields should declare SEP-12 customer types',
    run() {},
  },
  {
    id: RULES.orphanedSep12Field,
    category: 'sep12',
    severity: 'warning',
    description: 'A required custom SEP-12 field should be advertised in SEP-31 /info',
    run() {},
  },
  {
    id: RULES.customerTypeNotFound,
    category: 'sep12',
    severity: 'error',
    description: 'Every SEP-31 customer type must have a SEP-12 schema',
    run() {},
  },
  {
    id: RULES.customerSchemaUnauthorized,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-12 schema discovery should not require an unavailable JWT',
    run() {},
  },
  {
    id: RULES.customerSchemaUnreachable,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-12 GET /customer should be reachable',
    run() {},
  },
  {
    id: RULES.customerSchemaMalformed,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-12 GET /customer should return a JSON schema object',
    run() {},
  },
  {
    id: RULES.customerTypeMismatch,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-12 should return the customer type that was requested',
    run() {},
  },
  {
    id: RULES.customerSchemaMissing,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-12 must define fields for every advertised customer type',
    run() {},
  },
  {
    id: RULES.fieldTypeMissing,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-12 fields should declare a value type',
    run() {},
  },
  {
    id: RULES.fieldTypeInvalid,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-12 field types must be string, binary, number, or date',
    run() {},
  },
  {
    id: RULES.fieldTypeIncompatible,
    category: 'sep12',
    severity: 'error',
    description: 'Field types must be compatible with the SEP-9 dictionary',
    run() {},
  },
  {
    id: RULES.fieldTypeNoncanonical,
    category: 'sep12',
    severity: 'warning',
    description: 'A SEP-9 date field declared as string should use the date type',
    run() {},
  },
];

/** Rule ids emitted by the consistency engine. */
export const sep31Sep12RuleIds: readonly string[] = sep31Sep12Rules.map((rule) => rule.id);
