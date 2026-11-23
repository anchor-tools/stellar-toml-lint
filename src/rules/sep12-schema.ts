import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

/**
 * Opt-in validation of the SEP-12 customer type schemas an anchor declares.
 *
 * SEP-12 lets an anchor require different KYC data per customer type
 * (`sep31-sender`, `sep31-receiver`, `sep6-deposit`, …), and `GET
 * [KYC_SERVER]/customer` is where a client learns which fields each type
 * needs. Those field keys are supposed to be the standard names from SEP-9 —
 * a wallet that already holds `first_name` under the SEP-9 name cannot map it
 * to an anchor's ad-hoc `fname`, so every non-standard key silently degrades
 * the shared KYC experience.
 *
 * The check is deliberately network-bound: the schema lives at the KYC
 * server, not in `stellar.toml`, so it only runs when the caller asks for
 * `--check-network`. The rule objects registered alongside it exist so
 * `--list-rules` and `--off` know about the diagnostics the async audit
 * emits. Ordinary offline linting never opens a connection.
 */

const UNKNOWN_FIELD_RULE = 'sep12/unknown-kyc-field-name';
const TYPE_SYNTAX_RULE = 'sep12/invalid-customer-type-syntax';

const SEP12_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0012.md';
const SEP9_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0009.md';

/**
 * Every field name SEP-9 (Standard KYC Fields) defines, transcribed as data
 * so a newly-standardised field is a one-line change.
 *
 * Source: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0009.md
 */
export const SEP9_KYC_FIELDS: ReadonlySet<string> = new Set([
  // Natural person fields.
  'family_name',
  'last_name',
  'given_name',
  'first_name',
  'additional_name',
  'address_country_code',
  'state_or_province',
  'city',
  'postal_code',
  'address',
  'mobile_number',
  'mobile_number_format',
  'email_address',
  'birth_date',
  'birth_place',
  'birth_country_code',
  'tax_id',
  'tax_id_name',
  'occupation',
  'employer_name',
  'employer_address',
  'language_code',
  'id_type',
  'id_country_code',
  'id_issue_date',
  'id_expiration_date',
  'id_number',
  'photo_id_front',
  'photo_id_back',
  'notary_approval_of_photo_id',
  'ip_address',
  'photo_proof_residence',
  'sex',
  'proof_of_income',
  'proof_of_liveness',
  'referral_id',
  // Financial account fields.
  'bank_name',
  'bank_account_type',
  'bank_account_number',
  'bank_number',
  'bank_phone_number',
  'bank_branch_number',
  'external_transfer_memo',
  'clabe_number',
  'cbu_number',
  'cbu_alias',
  'mobile_money_number',
  'mobile_money_provider',
  'crypto_address',
  'crypto_memo',
  // Organization fields (SEP-9 dot notation, flat strings — not nested keys).
  'organization.name',
  'organization.VAT_number',
  'organization.registration_number',
  'organization.registration_date',
  'organization.registered_address',
  'organization.number_of_shareholders',
  'organization.shareholder_name',
  'organization.photo_incorporation_doc',
  'organization.photo_proof_address',
  'organization.address_country_code',
  'organization.state_or_province',
  'organization.city',
  'organization.postal_code',
  'organization.director_name',
  'organization.website',
  'organization.email',
  'organization.phone',
  // Card fields.
  'card.number',
  'card.expiration_date',
  'card.cvc',
  'card.holder_name',
  'card.network',
  'card.postal_code',
  'card.country_code',
  'card.state_or_province',
  'card.city',
  'card.address',
  'card.token',
]);

/**
 * SEP-12 leaves `type` values to the protocols that use it, but every value
 * in the wild is a lowercase identifier — `sep31-sender`, `sep6-deposit`,
 * `counterparty_organization`, `small-transaction-amount`. Uppercase,
 * spaces, or punctuation mean a transcription error that will 400 at the
 * worst moment: mid-transaction.
 */
const CUSTOMER_TYPE_PATTERN = /^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$/;

/** True when `type` is a well-formed SEP-12 customer type name. */
export function isValidCustomerType(type: string): boolean {
  return CUSTOMER_TYPE_PATTERN.test(type);
}

interface AuditOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function typeSyntaxDiagnostic(
  type: string,
  rules: RuleOverrides | undefined,
): Diagnostic | undefined {
  const severity = severityFor(TYPE_SYNTAX_RULE, 'error', rules);
  if (severity === undefined) return undefined;

  return {
    rule: TYPE_SYNTAX_RULE,
    severity,
    category: 'sep12',
    message: `Customer type "${type}" is not a valid SEP-12 type name`,
    path: 'KYC_SERVER',
    helpUri: `${SEP12_SPEC}#type-specification`,
    suggestion: 'Use a lowercase identifier such as sep31-sender, sep31-receiver, or sep6-deposit.',
  };
}

function unknownFieldDiagnostic(
  field: string,
  typeLabel: string | undefined,
  rules: RuleOverrides | undefined,
): Diagnostic | undefined {
  const severity = severityFor(UNKNOWN_FIELD_RULE, 'warning', rules);
  if (severity === undefined) return undefined;

  return {
    rule: UNKNOWN_FIELD_RULE,
    severity,
    category: 'sep12',
    message: typeLabel
      ? `Customer type "${typeLabel}" requires "${field}", which is not a SEP-9 field name`
      : `KYC_SERVER/customer requires "${field}", which is not a SEP-9 field name`,
    path: 'KYC_SERVER',
    helpUri: SEP9_SPEC,
    suggestion:
      'Rename it to the matching SEP-9 field (mobile_number, not phone_number), or keep the custom field and document it in its description.',
  };
}

/**
 * Validates one `fields` container: an object whose keys are field names
 * (the shape SEP-12 documents) or a bare array of names (the shape some
 * schema declarations use).
 */
function checkFieldNames(
  fields: unknown,
  typeLabel: string | undefined,
  rules: RuleOverrides | undefined,
  diagnostics: Diagnostic[],
): void {
  const names: string[] = [];
  if (Array.isArray(fields)) {
    names.push(...fields.filter(isString));
  } else if (typeof fields === 'object' && fields !== null && !Array.isArray(fields)) {
    names.push(...Object.keys(fields));
  } else {
    return;
  }

  for (const name of names) {
    if (SEP9_KYC_FIELDS.has(name)) continue;
    const diagnostic = unknownFieldDiagnostic(name, typeLabel, rules);
    if (diagnostic) diagnostics.push(diagnostic);
  }
}

function checkTypeSyntax(
  type: unknown,
  rules: RuleOverrides | undefined,
  diagnostics: Diagnostic[],
): string | undefined {
  if (!isString(type)) return undefined;
  if (isValidCustomerType(type)) return type;

  const diagnostic = typeSyntaxDiagnostic(type, rules);
  if (diagnostic) diagnostics.push(diagnostic);
  return type;
}

/**
 * Validates a multi-type schema declaration: the response may list the
 * anchor's customer types under `types`, either keyed by type name or as an
 * array of `{ type, fields }` entries.
 */
function checkTypeDeclarations(
  body: Record<string, unknown>,
  rules: RuleOverrides | undefined,
  diagnostics: Diagnostic[],
): void {
  const types = body.types;

  if (Array.isArray(types)) {
    for (const entry of types) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
      const schema = entry as Record<string, unknown>;
      const type = checkTypeSyntax(schema.type, rules, diagnostics);
      checkFieldNames(schema.fields, type, rules, diagnostics);
    }
    return;
  }

  if (typeof types !== 'object' || types === null || Array.isArray(types)) return;

  for (const [name, schema] of Object.entries(types)) {
    const type = checkTypeSyntax(name, rules, diagnostics);
    if (Array.isArray(schema)) {
      checkFieldNames(schema, type, rules, diagnostics);
    } else if (typeof schema === 'object' && schema !== null) {
      checkFieldNames((schema as Record<string, unknown>).fields, type, rules, diagnostics);
    }
  }
}

/**
 * GETs `KYC_SERVER/customer` and checks the customer type schemas the
 * anchor declares against SEP-9 and the SEP-12 type syntax.
 *
 * Silent when the file has no usable `KYC_SERVER`, or when the endpoint
 * cannot be read: an unreachable host, a 401 from the (expected) missing
 * SEP-10 JWT, or a non-JSON body are not schema findings, and inventing a
 * diagnostic for them would bury the two this check exists to report.
 */
export async function checkSep12Schema(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const kycServer = doc.KYC_SERVER;
  if (!isString(kycServer) || !isUrl(kycServer)) return [];

  const url = `${kycServer.replace(/\/+$/, '')}/customer`;

  let response: Response;
  try {
    response = await fetchImpl(url);
  } catch {
    return [];
  }
  if (!response.ok) return [];

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return [];
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return [];

  const schema = body as Record<string, unknown>;
  const diagnostics: Diagnostic[] = [];
  const rules = options.rules;

  checkTypeSyntax(schema.type, rules, diagnostics);
  checkFieldNames(
    schema.fields,
    isString(schema.type) ? schema.type : undefined,
    rules,
    diagnostics,
  );
  checkFieldNames(
    schema.provided_fields,
    isString(schema.type) ? schema.type : undefined,
    rules,
    diagnostics,
  );
  checkTypeDeclarations(schema, rules, diagnostics);

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep12Rules: Rule[] = [
  {
    id: UNKNOWN_FIELD_RULE,
    category: 'sep12',
    severity: 'warning',
    description: 'KYC_SERVER customer schemas should require SEP-9 field names',
    run() {},
  },
  {
    id: TYPE_SYNTAX_RULE,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-12 customer type names must be lowercase identifiers',
    run() {},
  },
];

/** Rule ids emitted by {@link checkSep12Schema}. */
export const sep12RuleIds: readonly string[] = sep12Rules.map((rule) => rule.id);
