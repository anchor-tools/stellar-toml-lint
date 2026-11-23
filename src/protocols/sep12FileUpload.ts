/**
 * SEP-12 customer verification upload security validator.
 *
 * Runs under opt-in `--test-sep12-upload` with a SEP-10 JWT.
 *
 * `PUT /customer/verification` accepts binary identity documents. An anchor
 * that trusts the filename, ignores the declared size, or accepts a spoofed
 * Content-Type turns a KYC upload into a file-execution or denial-of-service
 * surface. This validator discovers the advertised binary fields, then submits
 * synthetic multipart requests that an anchor must reject: an executable, an
 * oversized buffer, and a `.exe` wearing an image MIME type. It also checks
 * that rejections use the SEP-12 `{"error": "..."}` schema instead of a bare
 * stack trace or an empty body.
 *
 * Every payload is generated per request and dropped afterwards; nothing is
 * written to disk and no real identity data is transmitted.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const ACCEPTS_EXECUTABLE_RULE = 'sep12/unsafe-upload-executable';
const ACCEPTS_OVERSIZED_RULE = 'sep12/oversized-upload-accepted';
const MIME_SPOOFING_RULE = 'sep12/mime-type-spoofing';
const REJECTS_VALID_RULE = 'sep12/valid-format-rejected';
const ERROR_SCHEMA_RULE = 'sep12/upload-error-schema';
const SERVER_ERROR_RULE = 'sep12/upload-server-error';
const UNVERIFIABLE_RULE = 'sep12/upload-unverifiable';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0012.md';

/** Throwaway account used only to shape the request; no customer is created. */
const AUDIT_ACCOUNT = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

/** Default synthetic size for the oversized probe: 6 MiB. */
export const DEFAULT_OVERSIZED_BYTES = 6 * 1024 * 1024;

/** Fields to probe when `/customer` advertises no binary field names. */
export const FALLBACK_BINARY_FIELDS = ['photo_id_front', 'proof_of_address'] as const;

const PNG_MAGIC = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export interface Sep12FileUploadOptions {
  rules?: RuleOverrides;
  /** KYC server base; defaults to `KYC_SERVER`. */
  kycServer?: string;
  /** SEP-10 JWT authorising `/customer` and the verification upload. */
  token?: string;
  /** Account the audit poses as. Defaults to a throwaway key. */
  account?: string;
  /** Size of the oversized probe, in bytes. Defaults to 6 MiB. */
  oversizedBytes?: number;
  timeoutMs?: number;
}

export interface UploadProbe {
  name: string;
  field: string;
  filename: string;
  contentType: string;
  bytes: number;
  status: number;
  /** SEP-12 `error` message when the anchor rejected with the right schema. */
  error?: string;
}

export interface Sep12FileUploadResult {
  diagnostics: Diagnostic[];
  fields: string[];
  probes: UploadProbe[];
  summary: string;
}

function binaryFieldNames(body: unknown): string[] {
  if (!isRecord(body) || !isRecord(body.fields)) return [];
  return Object.entries(body.fields)
    .filter(([, field]) => isRecord(field) && field.type === 'binary')
    .map(([name]) => name);
}

interface UploadInit {
  account: string;
  token: string;
}

/**
 * Sends one synthetic document as multipart form data. Files are built inline
 * so a rejected payload is garbage-collected with the request.
 */
async function upload(
  base: string,
  field: string,
  filename: string,
  contentType: string,
  bytes: Uint8Array,
  init: UploadInit,
  fetchImpl: typeof fetch,
  timeoutMs?: number,
): Promise<{ status: number; body?: unknown }> {
  const form = new FormData();
  form.set('account', init.account);
  // Copy into an ArrayBuffer-backed view: Blob rejects a possibly-shared view.
  const payload = new Uint8Array(bytes.byteLength);
  payload.set(bytes);
  form.set(field, new Blob([payload], { type: contentType }), filename);
  const response = await fetchWithTimeout(
    fetchImpl,
    `${base}/customer/verification`,
    {
      method: 'PUT',
      headers: { authorization: `Bearer ${init.token}` },
      body: form,
    },
    timeoutMs,
  );
  const text = await response.text().catch(() => '');
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: response.status, body };
}

function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

function isClientError(status: number): boolean {
  return status >= 400 && status < 500;
}

export class Sep12FileUploadValidator {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Sep12FileUploadOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<Sep12FileUploadResult> {
    const server = this.options.kycServer ?? doc.KYC_SERVER;
    if (!isString(server) || !isHttpsUrl(server)) {
      return { diagnostics: [], fields: [], probes: [], summary: 'No usable KYC_SERVER to test.' };
    }
    if (this.options.token === undefined) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          'SEP-12 upload audit needs a SEP-10 token for PUT /customer/verification',
          'KYC_SERVER',
          'Pass --sep10-token <jwt> with --test-sep12-upload.',
        ),
        fields: [],
        probes: [],
        summary: 'No token supplied.',
      };
    }

    const base = server.replace(/\/+$/, '');
    const account = this.options.account ?? AUDIT_ACCOUNT;
    const revealed = await this.discoverFields(base, account);
    const fields = revealed.length > 0 ? revealed : [...FALLBACK_BINARY_FIELDS];
    const field = fields[0] as string;
    const oversizedBytes = Math.max(1, this.options.oversizedBytes ?? DEFAULT_OVERSIZED_BYTES);
    const init: UploadInit = { account, token: this.options.token };

    const probes: UploadProbe[] = [];
    const diagnostics: Diagnostic[] = [];

    const record = async (
      name: string,
      filename: string,
      contentType: string,
      bytes: Uint8Array,
    ): Promise<UploadProbe> => {
      const probe: UploadProbe = {
        name,
        field,
        filename,
        contentType,
        bytes: bytes.byteLength,
        status: 0,
      };
      try {
        const response = await upload(
          base,
          field,
          filename,
          contentType,
          bytes,
          init,
          this.fetchImpl,
          this.options.timeoutMs,
        );
        probe.status = response.status;
        if (
          isClientError(response.status) &&
          isRecord(response.body) &&
          isString(response.body.error)
        ) {
          probe.error = response.body.error;
        }
        if (response.status >= 500) {
          diagnostics.push(
            ...this.finding(
              SERVER_ERROR_RULE,
              'warning',
              `PUT /customer/verification returned HTTP ${response.status} for the ${name} probe`,
              'KYC_SERVER',
              'Answer malformed uploads with a 4xx SEP-12 error rather than a server failure.',
            ),
          );
        }
      } catch (error) {
        probe.status = 0;
        diagnostics.push(
          ...this.finding(
            UNVERIFIABLE_RULE,
            'info',
            `SEP-12 ${name} probe could not be sent (${error instanceof Error ? error.message : String(error)})`,
            'KYC_SERVER',
            'Confirm KYC_SERVER accepts authenticated multipart PUT requests.',
          ),
        );
      }
      probes.push(probe);
      return probe;
    };

    const valid = await record('valid-png', 'id.png', 'image/png', PNG_MAGIC);
    if (valid.status === 415) {
      diagnostics.push(
        ...this.finding(
          REJECTS_VALID_RULE,
          'warning',
          'A PNG identity document was rejected with HTTP 415 Unsupported Media Type',
          'KYC_SERVER',
          'Accept the formats the anchor advertises (PDF, JPEG, PNG); rejecting a valid PNG blocks onboarding.',
        ),
      );
    }

    const executable = await record(
      'executable',
      'payload.exe',
      'application/x-msdownload',
      new Uint8Array([0x4d, 0x5a]),
    );
    if (isSuccess(executable.status)) {
      diagnostics.push(
        ...this.finding(
          ACCEPTS_EXECUTABLE_RULE,
          'error',
          'PUT /customer/verification accepted a Windows executable as a verification document',
          'KYC_SERVER',
          'Reject executable extensions and non-image/document MIME types before storing the upload.',
        ),
      );
    }

    const spoofed = await record(
      'mime-spoofing',
      'payload.exe',
      'image/jpeg',
      new Uint8Array([0xff, 0xd8, 0xff, 0xe0]),
    );
    if (isSuccess(spoofed.status)) {
      diagnostics.push(
        ...this.finding(
          MIME_SPOOFING_RULE,
          'error',
          'PUT /customer/verification accepted a .exe filename declared as image/jpeg',
          'KYC_SERVER',
          'Derive the stored type from an allowlist and the file magic, not from the client-supplied Content-Type alone.',
        ),
      );
    }

    const oversized = await record(
      'oversized',
      'huge.png',
      'image/png',
      new Uint8Array(oversizedBytes),
    );
    if (isSuccess(oversized.status)) {
      diagnostics.push(
        ...this.finding(
          ACCEPTS_OVERSIZED_RULE,
          'error',
          `PUT /customer/verification accepted a ${(oversizedBytes / (1024 * 1024)).toFixed(1)} MiB upload`,
          'KYC_SERVER',
          'Enforce a documented maximum document size and reject larger bodies with 413 before reading them fully.',
        ),
      );
    }

    for (const probe of probes) {
      if (isClientError(probe.status) && probe.error === undefined && probe.status !== 0) {
        diagnostics.push(
          ...this.finding(
            ERROR_SCHEMA_RULE,
            'warning',
            `Rejected ${probe.name} probe (HTTP ${probe.status}) did not return a SEP-12 {"error": "..."} body`,
            'KYC_SERVER',
            'Return a JSON object with an error message so the wallet can tell the user what to fix.',
          ),
        );
      }
    }

    return {
      diagnostics,
      fields,
      probes,
      summary: `Probed ${probes.length} uploads against ${fields.length} advertised binary field(s).`,
    };
  }

  /** `GET /customer` for the probed account; binary field names only. */
  private async discoverFields(base: string, account: string): Promise<string[]> {
    const params = new URLSearchParams({ account });
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/customer?${params.toString()}`,
        { headers: { authorization: `Bearer ${this.options.token ?? ''}` } },
        this.options.timeoutMs,
      );
      const body: unknown = await response.json().catch(() => undefined);
      return binaryFieldNames(body);
    } catch {
      return [];
    }
  }

  private finding(
    rule: string,
    fallback: 'error' | 'warning' | 'info',
    message: string,
    path: string,
    suggestion: string,
  ): Diagnostic[] {
    const severity = severityFor(rule, fallback, this.options.rules);
    if (severity === undefined) return [];
    return [{ rule, severity, category: 'network', message, path, helpUri: SPEC, suggestion }];
  }
}

export async function testSep12FileUploads(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep12FileUploadOptions = {},
): Promise<Sep12FileUploadResult> {
  return new Sep12FileUploadValidator(fetchImpl, options).verify(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const sep12FileUploadRules: Rule[] = [
  def(ACCEPTS_EXECUTABLE_RULE, 'error', 'SEP-12 verification must reject executable uploads'),
  def(ACCEPTS_OVERSIZED_RULE, 'error', 'SEP-12 verification must reject oversized uploads'),
  def(MIME_SPOOFING_RULE, 'error', 'SEP-12 verification must not trust client-supplied MIME types'),
  def(
    REJECTS_VALID_RULE,
    'warning',
    'SEP-12 verification should accept advertised document formats',
  ),
  def(ERROR_SCHEMA_RULE, 'warning', 'SEP-12 upload errors must use the error schema'),
  def(SERVER_ERROR_RULE, 'warning', 'SEP-12 upload validation failures must not be 5xx'),
  def(UNVERIFIABLE_RULE, 'info', 'SEP-12 upload security should be verifiable'),
];

export const sep12FileUploadRuleIds: readonly string[] = sep12FileUploadRules.map(
  (rule) => rule.id,
);
