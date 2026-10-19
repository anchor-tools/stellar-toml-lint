import { describe, expect, it } from 'vitest';
import {
  auditCorpHeaders,
  SECURITY_MISSING_CORP_HEADER,
  SECURITY_MISSING_NOSNIFF_HEADER,
  SECURITY_MISSING_OPENER_POLICY,
} from '../../src/security/corp-auditor.js';

describe('auditCorpHeaders', () => {
  it('accepts the expected isolation headers', () => {
    const headers = new Headers({
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'X-Content-Type-Options': 'nosniff',
    });

    expect(auditCorpHeaders(headers)).toEqual([]);
  });

  it('reports missing nosniff and opener policy as warnings', () => {
    const diagnostics = auditCorpHeaders(new Headers());

    expect(diagnostics.map(({ rule, severity }) => [rule, severity])).toEqual([
      [SECURITY_MISSING_CORP_HEADER, 'warning'],
      [SECURITY_MISSING_OPENER_POLICY, 'warning'],
      [SECURITY_MISSING_NOSNIFF_HEADER, 'warning'],
    ]);
  });

  it('warns when CORP blocks cross-site wallet reads', () => {
    const diagnostics = auditCorpHeaders(
      new Headers({
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'X-Content-Type-Options': 'nosniff',
      }),
    );

    expect(diagnostics.map(({ rule }) => rule)).toEqual([SECURITY_MISSING_CORP_HEADER]);
  });

  it('honours rule overrides', () => {
    expect(
      auditCorpHeaders(new Headers(), {
        [SECURITY_MISSING_CORP_HEADER]: 'off',
        [SECURITY_MISSING_OPENER_POLICY]: 'error',
      }).map(({ rule, severity }) => [rule, severity]),
    ).toEqual([
      [SECURITY_MISSING_OPENER_POLICY, 'error'],
      [SECURITY_MISSING_NOSNIFF_HEADER, 'warning'],
    ]);
  });
});
