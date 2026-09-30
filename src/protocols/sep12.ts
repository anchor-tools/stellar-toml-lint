/**
 * SEP-12 interactive KYC customer verification suite.
 *
 * Wallets must register customers, query verification status, and upload
 * identity documents to an anchor's `KYC_SERVER` (SEP-1) using SEP-12.
 * This suite exercises the three canonical endpoints against a live anchor
 * under `--check-network --verify-sep12`:
 *
 *   - GET  /customer?type=...       â€” declared customer types and status
 *   - PUT  /customer                â€” register / update a customer
 *   - PUT  /customer/verification   â€” multipart binary document upload
 *
 * The suite sends synthetic sandbox data only (RFC 2606 `.example` domains,
 * random UUIDs) and never transmits real PII.
 */
import { randomUUID } from 'node:crypto';

import type { Diagnostic, RuleCategory, RuleOverrides, Severity } from '../types.js';

export const INVALID_CUSTOMER_STATUS_RULE = 'sep12/invalid-customer-status';
export const MISSING_REQUIRED_KYC_FIELDS_RULE = 'sep12/missing-required-kyc-fields';
export const BINARY_UPLOAD_UNSUPPORTED_RULE = 'sep12/binary-upload-unsupported';

const SEP12_STATUSES = ['NEEDS_INFO', 'PROCESSING', 'ACCEPTED', 'REJECTED'] as const;
type Sep12Status = (typeof SEP12_STATUSES)[number];

const REQUIRED_KYC_FIELDS = ['first_name', 'last_name', 'email_address'] as const;

const DEFAULT_TIMEOUT_MS = 15_000;
const SEP12_HELP = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0012.md';

interface Sep12Options {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

interface KycField {
  type?: string;
  description?: string;
  optional?: boolean;
}

interface CustomerResponse {
  id?: string;
  status?: string;
  fields?: Record<string, KycField>;
  message?: string;
}

function severityOf(rule: string, fallback: Severity, overrides?: RuleOverrides): Severity | 'off' {
  const override = overrides?.[rule];
  if (override === undefined) return fallback;
  return override;
}

function makeDiagnostic(
  rule: string,
  category: RuleCategory,
  fallback: Severity,
  overrides: RuleOverrides | undefined,
  message: string,
  extras: Partial<Diagnostic> = {},
): Diagnostic | null {
  const severity = severityOf(rule, fallback, overrides);
  if (severity === 'off') return null;
  return {
    rule,
    severity,
    category,
    message,
    helpUri: SEP12_HELP,
    ...extras,
  };
}

async function fetchJson(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<{ status: number; body: unknown } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { ...init, signal: controller.signal });
    let body: unknown = null;
    const text = await response.text();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }
    return { status: response.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeKycServer(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
}

function syntheticCustomer(): Record<string, string> {
  const id = randomUUID();
  return {
    first_name: 'Lint',
    last_name: 'Suite',
    email_address: `kyc-${id}@example.com`,
    id_number: id,
    mobile_number: '+10000000000',
    address: '1 Test Street, Nowhere, XX 00000',
    birth_date: '1990-01-01',
  };
}

export async function verifySep12(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch,
  options: Sep12Options = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const kycServer = normalizeKycServer(doc.KYC_SERVER);
  if (!kycServer) return diagnostics;

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const overrides = options.rules;

  // ---- 1. GET /customer?type=<type> for declared customer types ----
  const customerTypes = ['sep12', 'sep31-sender', 'sep31-receiver', 'sep6-deposit', 'sep6-withdrawal'];
  let needsInfoResponse: CustomerResponse | null = null;

  for (const type of customerTypes) {
    const result = await fetchJson(
      fetchImpl,
      `${kycServer}/customer?type=${encodeURIComponent(type)}`,
      { method: 'GET', headers: { accept: 'application/json' } },
      timeoutMs,
    );
    if (!result || result.status === 404 || result.status === 403) continue;
    const body = result.body as CustomerResponse | null;
    if (!body || typeof body !== 'object') continue;

    if (body.status !== undefined) {
      if (!SEP12_STATUSES.includes(body.status as Sep12Status)) {
        const diag = makeDiagnostic(
          INVALID_CUSTOMER_STATUS_RULE,
          'sep12',
          'error',
          overrides,
          `SEP-12 GET /customer?type=${type} returned status "${body.status}", which is not one of ${SEP12_STATUSES.join(', ')}`,
          { suggestion: 'Return one of the SEP-12 defined status values or 404 when the customer is unknown' },
        );
        if (diag) diagnostics.push(diag);
      }
      if (body.status === 'NEEDS_INFO') {
        needsInfoResponse = body;
      }
    }
  }

  // ---- 2. Warnings when a NEEDS_INFO response omits canonical fields ----
  if (needsInfoResponse?.fields) {
    const missing = REQUIRED_KYC_FIELDS.filter((field) => !(field in needsInfoResponse!.fields!));
    if (missing.length > 0) {
      const diag = makeDiagnostic(
        MISSING_REQUIRED_KYC_FIELDS_RULE,
        'sep12',
        'warning',
        overrides,
        `SEP-12 NEEDS_INFO response does not describe required field(s): ${missing.join(', ')}`,
        {
          path: 'KYC_SERVER',
          suggestion: 'Describe every field the wallet must collect so clients can render the form',
        },
      );
      if (diag) diagnostics.push(diag);
    }
  }

  // ---- 3. PUT /customer with synthetic sandbox data ----
  const synthetic = syntheticCustomer();
  const registerResult = await fetchJson(
    fetchImpl,
    `${kycServer}/customer`,
    {
      method: 'PUT',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(synthetic),
    },
    timeoutMs,
  );

  if (registerResult && registerResult.status >= 200 && registerResult.status < 300) {
    const registered = registerResult.body as CustomerResponse | null;
    if (registered?.status !== undefined && !SEP12_STATUSES.includes(registered.status as Sep12Status)) {
      const diag = makeDiagnostic(
        INVALID_CUSTOMER_STATUS_RULE,
        'sep12',
        'error',
        overrides,
        `SEP-12 PUT /customer returned status "${registered.status}", which is not one of ${SEP12_STATUSES.join(', ')}`,
      );
      if (diag) diagnostics.push(diag);
    }
  }

  // ---- 4. PUT /customer/verification with a multipart binary body ----
  const pngBytes = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
  ]);

  const form = new FormData();
  form.append(
    'file',
    new Blob([pngBytes], { type: 'image/png' }),
    'identity-document.png',
  );

  const uploadResult = await fetchJson(
    fetchImpl,
    `${kycServer}/customer/verification`,
    { method: 'PUT', body: form, headers: { accept: 'application/json' } },
    timeoutMs,
  );

  if (uploadResult) {
    const unsupported = uploadResult.status === 415 || uploadResult.status === 400;
    const message =
      typeof uploadResult.body === 'object' && uploadResult.body !== null && 'error' in uploadResult.body
        ? String((uploadResult.body as { error: unknown }).error)
        : '';
    const rejectReason =
      unsupported &&
      (uploadResult.status === 415 ||
        /multipart|binary|content-type/i.test(message) ||
        /unsupported/i.test(message));

    if (rejectReason) {
      const diag = makeDiagnostic(
        BINARY_UPLOAD_UNSUPPORTED_RULE,
        'sep12',
        'error',
        overrides,
        `SEP-12 PUT /customer/verification rejected a valid multipart/form-data upload (HTTP ${uploadResult.status})${message ? `: ${message}` : ''}`,
        {
          suggestion: 'Accept multipart/form-data with binary identity documents as SEP-12 requires',
        },
      );
      if (diag) diagnostics.push(diag);
    }
  }

  return diagnostics;
}

export const sep12Rules = [
  {
    id: INVALID_CUSTOMER_STATUS_RULE,
    category: 'sep12' as RuleCategory,
    severity: 'error' as Severity,
    description: 'SEP-12 customer status must be one of NEEDS_INFO, PROCESSING, ACCEPTED, REJECTED',
  },
  {
    id: MISSING_REQUIRED_KYC_FIELDS_RULE,
    category: 'sep12' as RuleCategory,
    severity: 'warning' as Severity,
    description: 'SEP-12 NEEDS_INFO responses must describe the fields the wallet has to collect',
  },
  {
    id: BINARY_UPLOAD_UNSUPPORTED_RULE,
    category: 'sep12' as RuleCategory,
    severity: 'error' as Severity,
    description: 'SEP-12 PUT /customer/verification must accept multipart binary document uploads',
  },
] as const;
