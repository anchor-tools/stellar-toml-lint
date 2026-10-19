import { describe, expect, it } from 'vitest';
import { evaluateGitOpsAdmission } from '../../src/integrations/gitops/webhook.js';

describe('GitOps admission webhook', () => {
  it('allows valid stellar.toml content and preserves the request UID', () => {
    const result = evaluateGitOpsAdmission({
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      request: {
        uid: 'request-1',
        object: { data: { 'stellar.toml': 'VERSION = "2.0.0"\n' } },
      },
    });

    expect(result.response.allowed).toBe(true);
    expect(result.response.uid).toBe('request-1');
  });

  it('denies malformed TOML with a diagnostic', () => {
    const result = evaluateGitOpsAdmission({
      kind: 'AdmissionReview',
      request: { uid: 'request-2', object: { stellarToml: 'VERSION = [' } },
    });

    expect(result.response.allowed).toBe(false);
    expect(result.response.status?.message).toContain('error:');
  });
});
