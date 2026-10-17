import { describe, expect, it } from 'vitest';
import {
  LEGAL_DOCUMENT_NOT_HTTPS,
  LEGAL_DOCUMENT_REDIRECTED,
  LEGAL_DOCUMENT_UNREACHABLE,
  LEGAL_HASH_MISMATCH,
  LEGAL_MISSING_DECLARATION,
  LEGAL_TIMESTAMP_MISMATCH,
  auditLegalDocument,
  checkLegalAgreements,
  formatLegalAuditReport,
  legalAgreementRules,
  legalDocumentsOf,
  normalizeLegalContent,
  normalizePublishedHash,
} from '../../src/validators/legalAgreements.js';
import { sha256Hex } from '../../src/validators/legalAgreements.js';

const TERMS_URL = 'https://anchor.example.com/legal/terms';
const PRIVACY_URL = 'https://anchor.example.com/legal/privacy';

const TERMS_BODY = 'Terms of service: the anchor holds your funds responsibly.\n';
const PRIVACY_BODY = 'Privacy policy: the anchor stores only what KYC requires.\n';

const TERMS_HASH = sha256Hex(new TextEncoder().encode(TERMS_BODY));

function documentResponse(
  body: string,
  options: { contentType?: string; status?: number; lastModified?: string } = {},
): Response {
  const headers = new Headers({ 'content-type': options.contentType ?? 'text/plain' });
  if (options.lastModified !== undefined) headers.set('last-modified', options.lastModified);
  return new Response(body, { status: options.status ?? 200, headers });
}

const rules = (diagnostics: { rule: string }[]): string[] => diagnostics.map((d) => d.rule);

describe('legalDocumentsOf', () => {
  it('reads documents and their companions from [DOCUMENTATION]', () => {
    const doc = {
      DOCUMENTATION: {
        ORG_TERMS_OF_SERVICE: TERMS_URL,
        ORG_TERMS_OF_SERVICE_HASH: TERMS_HASH,
        ORG_TERMS_OF_SERVICE_UPDATED: '2026-01-02T00:00:00.000Z',
        ORG_PRIVACY_POLICY: PRIVACY_URL,
        ORG_PRIVACY_POLICY_CHECKSUM: `sha256:${'a'.repeat(64)}`,
      },
    };

    expect(legalDocumentsOf(doc)).toEqual([
      {
        kind: 'terms-of-service',
        url: TERMS_URL,
        path: 'DOCUMENTATION.ORG_TERMS_OF_SERVICE',
        hash: TERMS_HASH,
        updated: '2026-01-02T00:00:00.000Z',
      },
      {
        kind: 'privacy-policy',
        url: PRIVACY_URL,
        path: 'DOCUMENTATION.ORG_PRIVACY_POLICY',
        hash: `sha256:${'a'.repeat(64)}`,
      },
    ]);
  });

  it('reads documents from the [DOCUMENTATION.ORG_LEGAL] sub-table', () => {
    const doc = {
      DOCUMENTATION: {
        ORG_NAME: 'Anchor',
        ORG_LEGAL: {
          ORG_TERMS_OF_SERVICE: TERMS_URL,
          ORG_PRIVACY_POLICY_SHA256: 'b'.repeat(64),
        },
      },
    };

    const documents = legalDocumentsOf(doc);
    expect(documents.map((d) => d.path)).toEqual(['DOCUMENTATION.ORG_LEGAL.ORG_TERMS_OF_SERVICE']);
    expect(documents[0]?.kind).toBe('terms-of-service');
  });

  it('is silent without a [DOCUMENTATION] table', () => {
    expect(legalDocumentsOf({})).toEqual([]);
    expect(legalDocumentsOf({ DOCUMENTATION: 'nope' })).toEqual([]);
  });
});

describe('auditLegalDocument', () => {
  const termsRef = {
    kind: 'terms-of-service' as const,
    url: TERMS_URL,
    path: 'DOCUMENTATION.ORG_TERMS_OF_SERVICE',
  };

  it('verifies a document that matches its published checksum', async () => {
    const fetchImpl = (async () => documentResponse(TERMS_BODY)) as unknown as typeof fetch;
    const audit = await auditLegalDocument({ ...termsRef, hash: TERMS_HASH }, fetchImpl);

    expect(audit.status).toBe('verified');
    expect(audit.computedHash).toBe(TERMS_HASH);
    expect(audit.diagnostics).toEqual([]);
  });

  it('flags a document that does not match its published checksum', async () => {
    const fetchImpl = (async () =>
      documentResponse(
        'Terms of service: completely different text.\n',
      )) as unknown as typeof fetch;

    const audit = await auditLegalDocument({ ...termsRef, hash: TERMS_HASH }, fetchImpl);
    expect(audit.status).toBe('hash-mismatch');
    expect(rules(audit.diagnostics)).toEqual([LEGAL_HASH_MISMATCH]);
    expect(audit.diagnostics[0]?.severity).toBe('error');
  });

  it('accepts a checksum computed over normalised rendered HTML', async () => {
    const html = [
      '<html><body>',
      '<p>Terms of service.</p>',
      '<!-- deploy 2026-01-01 -->',
      '<img src="/px.gif" width="1" height="1">',
      '</body></html>',
    ].join('\n');

    const normalizedHash = sha256Hex(
      normalizeLegalContent(new TextEncoder().encode(html), 'text/html'),
    );
    // The published checksum is over the normalised text, not the raw bytes.
    expect(normalizedHash).not.toBe(sha256Hex(new TextEncoder().encode(html)));

    const fetchImpl = (async () =>
      documentResponse(html, { contentType: 'text/html' })) as unknown as typeof fetch;
    const audit = await auditLegalDocument({ ...termsRef, hash: normalizedHash }, fetchImpl);
    expect(audit.status).toBe('verified');
    expect(audit.diagnostics).toEqual([]);
  });

  it('flags a published checksum that is not a SHA-256 digest', async () => {
    const fetchImpl = (async () => documentResponse(TERMS_BODY)) as unknown as typeof fetch;
    const audit = await auditLegalDocument({ ...termsRef, hash: 'not-a-hash' }, fetchImpl);
    expect(rules(audit.diagnostics)).toEqual([LEGAL_HASH_MISMATCH]);
    expect(audit.diagnostics[0]?.message).toContain('not a SHA-256 digest');
  });

  it('flags a stale revision timestamp', async () => {
    const fetchImpl = (async () =>
      documentResponse(TERMS_BODY, {
        lastModified: 'Wed, 01 Jan 2026 00:00:00 GMT',
      })) as unknown as typeof fetch;

    const audit = await auditLegalDocument(
      { ...termsRef, updated: '2026-03-01T00:00:00.000Z' },
      fetchImpl,
    );
    expect(rules(audit.diagnostics)).toEqual([LEGAL_TIMESTAMP_MISMATCH]);
    expect(audit.diagnostics[0]?.severity).toBe('warning');
    expect(audit.lastModified).toBe('2026-01-01T00:00:00.000Z');
  });

  it('accepts a timestamp that agrees with Last-Modified', async () => {
    const fetchImpl = (async () =>
      documentResponse(TERMS_BODY, {
        lastModified: 'Wed, 01 Jan 2026 00:00:00 GMT',
      })) as unknown as typeof fetch;

    const audit = await auditLegalDocument(
      { ...termsRef, updated: '2026-01-01T12:00:00.000Z' },
      fetchImpl,
    );
    expect(audit.diagnostics).toEqual([]);
    expect(audit.status).toBe('verified');
  });

  it('reads the document behind a redirect and warns about the bounce', async () => {
    const calls: string[] = [];
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url === TERMS_URL) {
        return new Response(null, {
          status: 301,
          headers: { location: '/legal/terms-v2' },
        });
      }
      return documentResponse(TERMS_BODY);
    }) as unknown as typeof fetch;

    const audit = await auditLegalDocument(termsRef, fetchImpl);
    expect(calls).toEqual([TERMS_URL, 'https://anchor.example.com/legal/terms-v2']);
    expect(audit.status).toBe('redirected');
    expect(audit.redirectLocation).toBe('https://anchor.example.com/legal/terms-v2');
    expect(rules(audit.diagnostics)).toEqual([LEGAL_DOCUMENT_REDIRECTED]);
  });

  it('flags a redirect with no usable Location header', async () => {
    const fetchImpl = (async () => new Response(null, { status: 302 })) as unknown as typeof fetch;
    const audit = await auditLegalDocument(termsRef, fetchImpl);
    expect(rules(audit.diagnostics)).toEqual([LEGAL_DOCUMENT_UNREACHABLE]);
  });

  it('flags a non-https link without opening a connection', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return documentResponse(TERMS_BODY);
    }) as unknown as typeof fetch;

    const audit = await auditLegalDocument(
      { ...termsRef, url: 'http://anchor.example.com/t' },
      fetchImpl,
    );
    expect(audit.status).toBe('not-https');
    expect(rules(audit.diagnostics)).toEqual([LEGAL_DOCUMENT_NOT_HTTPS]);
    expect(calls).toBe(0);
  });

  it('flags a value that is not a URL at all', async () => {
    const audit = await auditLegalDocument({ ...termsRef, url: 'javascript:alert(1)' }, fetch);
    expect(audit.status).toBe('not-a-url');
    expect(rules(audit.diagnostics)).toEqual([LEGAL_DOCUMENT_NOT_HTTPS]);
  });

  it('degrades an unreachable host and an error status to a finding', async () => {
    const offline = (async () => {
      throw new Error('getaddrinfo ENOTFOUND anchor.example.com');
    }) as unknown as typeof fetch;
    const unreachable = await auditLegalDocument(termsRef, offline);
    expect(unreachable.status).toBe('unreachable');
    expect(unreachable.diagnostics[0]?.message).toContain('ENOTFOUND');

    const notFound = (async () =>
      documentResponse('nope', { status: 404 })) as unknown as typeof fetch;
    const missing = await auditLegalDocument(termsRef, notFound);
    expect(missing.status).toBe('unreachable');
    expect(missing.httpStatus).toBe(404);
    expect(rules(missing.diagnostics)).toEqual([LEGAL_DOCUMENT_UNREACHABLE]);
  });

  it('honours --off and severity overrides', async () => {
    const fetchImpl = (async () =>
      documentResponse('different', { status: 200 })) as unknown as typeof fetch;

    expect(
      await auditLegalDocument({ ...termsRef, hash: TERMS_HASH }, fetchImpl, {
        rules: { [LEGAL_HASH_MISMATCH]: 'off' },
      }).then((a) => a.diagnostics),
    ).toEqual([]);

    const warn = await auditLegalDocument(
      { ...termsRef, hash: TERMS_HASH },
      (async () => documentResponse('different')) as unknown as typeof fetch,
      { rules: { [LEGAL_HASH_MISMATCH]: 'warning' } },
    );
    expect(warn.diagnostics[0]?.severity).toBe('warning');
  });
});

describe('checkLegalAgreements', () => {
  it('audits every declared document over the caller transport', async () => {
    const fetchImpl = (async (input: string | URL | Request) =>
      String(input) === TERMS_URL
        ? documentResponse(TERMS_BODY)
        : documentResponse(PRIVACY_BODY)) as unknown as typeof fetch;

    const result = await checkLegalAgreements(
      {
        DOCUMENTATION: {
          ORG_TERMS_OF_SERVICE: TERMS_URL,
          ORG_PRIVACY_POLICY: PRIVACY_URL,
        },
      },
      fetchImpl,
    );

    expect(result.documents).toHaveLength(2);
    expect(result.documents.every((audit) => audit.status === 'verified')).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });

  it('warns when [DOCUMENTATION] declares no legal documents', async () => {
    const result = await checkLegalAgreements({ DOCUMENTATION: { ORG_NAME: 'Anchor' } }, fetch);
    expect(rules(result.diagnostics)).toEqual([LEGAL_MISSING_DECLARATION]);
    expect(result.documents).toEqual([]);
  });

  it('stays silent when there is no [DOCUMENTATION] at all', async () => {
    expect(await checkLegalAgreements({}, fetch)).toEqual({ diagnostics: [], documents: [] });
  });

  it('collects one diagnostic per failing document', async () => {
    const fetchImpl = (async (input: string | URL | Request) =>
      String(input) === TERMS_URL
        ? documentResponse('wrong')
        : documentResponse(PRIVACY_BODY)) as unknown as typeof fetch;

    const result = await checkLegalAgreements(
      {
        DOCUMENTATION: {
          ORG_TERMS_OF_SERVICE: TERMS_URL,
          ORG_TERMS_OF_SERVICE_HASH: TERMS_HASH,
          ORG_PRIVACY_POLICY: PRIVACY_URL,
        },
      },
      fetchImpl,
    );
    expect(rules(result.diagnostics)).toEqual([LEGAL_HASH_MISMATCH]);
  });
});

describe('formatLegalAuditReport', () => {
  const audit = {
    ref: {
      kind: 'terms-of-service' as const,
      url: TERMS_URL,
      path: 'DOCUMENTATION.ORG_TERMS_OF_SERVICE',
    },
    status: 'verified' as const,
    computedHash: TERMS_HASH,
    diagnostics: [],
  };

  it('renders a console summary', () => {
    const report = formatLegalAuditReport([audit]);
    expect(report).toContain('Legal document audit');
    expect(report).toContain('Terms of service: ok');
    expect(report).toContain(`sha256 ${TERMS_HASH}`);
  });

  it('renders a markdown table for a step summary', () => {
    const report = formatLegalAuditReport([audit], { markdown: true });
    expect(report).toContain('### Legal document audit');
    expect(report).toContain('| Document | URL | Status | SHA-256 |');
    expect(report).toContain('| Terms of service |');
  });

  it('is empty with nothing to report', () => {
    expect(formatLegalAuditReport([])).toBe('');
  });
});

describe('helpers', () => {
  it('normalises the published hash spellings', () => {
    expect(normalizePublishedHash(TERMS_HASH)).toBe(TERMS_HASH);
    expect(normalizePublishedHash(`  sha256:${TERMS_HASH.toUpperCase()}  `)).toBe(TERMS_HASH);
    expect(normalizePublishedHash(`sha256=${TERMS_HASH}`)).toBe(TERMS_HASH);
    expect(normalizePublishedHash('deadbeef')).toBeUndefined();
  });

  it('leaves binary content untouched', () => {
    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    expect(normalizeLegalContent(pdf, 'application/pdf')).toBe(pdf);
  });

  it('registers the rule ids', () => {
    expect(legalAgreementRules.map((rule) => rule.id)).toEqual([
      LEGAL_DOCUMENT_UNREACHABLE,
      LEGAL_DOCUMENT_NOT_HTTPS,
      LEGAL_DOCUMENT_REDIRECTED,
      LEGAL_HASH_MISMATCH,
      LEGAL_TIMESTAMP_MISMATCH,
      LEGAL_MISSING_DECLARATION,
    ]);
  });
});
