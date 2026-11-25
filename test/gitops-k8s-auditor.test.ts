import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  K8sIngressCertManagerAuditor,
  auditK8sManifests,
  gitopsRules,
} from '../src/gitops/k8sIngressAuditor.js';
import { parseYamlDocuments } from '../src/gitops/yaml.js';
import type { LintResult } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => join(here, 'fixtures', 'k8s', name);
const read = (name: string): string => readFileSync(fixture(name), 'utf8');
const run = promisify(execFile);

const COMPLIANT = read('compliant.yaml');
const MISCONFIGURED = read('misconfigured.yaml');

const auditor = new K8sIngressCertManagerAuditor();

function rules(result: LintResult): string[] {
  return result.diagnostics.map((diagnostic) => diagnostic.rule);
}

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [join(here, '..', 'dist', 'cli.js'), ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return {
      code: failure.code ?? 1,
      stdout: failure.stdout ?? '',
      stderr: failure.stderr ?? '',
    };
  }
}

describe('K8sIngressCertManagerAuditor', () => {
  it('passes a compliant Ingress, Certificate, and ClusterIssuer', () => {
    const result = auditor.audit(COMPLIANT);

    expect(result.diagnostics.map((d) => `${d.severity} ${d.rule}: ${d.message}`)).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.counts).toEqual({ error: 0, warning: 0, info: 0 });
  });

  it('passes the compliant fixture in strict mode', () => {
    expect(auditor.audit(COMPLIANT, { strict: true }).ok).toBe(true);
  });

  it('flags the misconfigured fixture with actionable diagnostics', () => {
    const result = auditor.audit(MISCONFIGURED);
    const ids = rules(result);

    expect(result.ok).toBe(false);
    expect(ids).toEqual(
      expect.arrayContaining([
        'gitops/acme-issuer',
        'gitops/acme-email-expired',
        'gitops/acme-solver',
        'gitops/ingress-annotation',
        'gitops/ingress-tls-secret',
        'gitops/ingress-acme-challenge-route',
        'gitops/ingress-stellar-toml-route',
      ]),
    );
    for (const diagnostic of result.diagnostics) {
      expect(diagnostic.category).toBe('gitops');
      expect(diagnostic.message.length).toBeGreaterThan(0);
      expect(diagnostic.suggestion?.length).toBeGreaterThan(0);
    }
  });

  it('reports invalid YAML without throwing', () => {
    const result = auditor.audit(
      'kind: Ingress\nmetadata:\n    name: anchor\n  namespace: anchors\n',
    );

    expect(rules(result)).toContain('gitops/k8s-yaml-parse');
    expect(result.ok).toBe(false);
  });

  it('requires a route for the ACME HTTP-01 challenge', () => {
    const result = auditor.audit(
      COMPLIANT.replace('          - path: /\n', '          - path: /.well-known/stellar.toml\n'),
    );

    expect(rules(result)).toContain('gitops/ingress-acme-challenge-route');
    expect(rules(result)).not.toContain('gitops/ingress-stellar-toml-route');
  });

  it('requires a route for stellar.toml', () => {
    const result = auditor.audit(
      COMPLIANT.replace(
        '          - path: /\n',
        '          - path: /.well-known/acme-challenge/\n',
      ),
    );

    expect(rules(result)).toContain('gitops/ingress-stellar-toml-route');
    expect(rules(result)).not.toContain('gitops/ingress-acme-challenge-route');
  });

  it('flags a missing CORS annotation on the stellar.toml route', () => {
    const withoutCors = COMPLIANT.replace(
      /^.*nginx\.ingress\.kubernetes\.io\/(?:enable-cors|cors-allow-origin):.*\n/gm,
      '',
    );

    expect(rules(auditor.audit(withoutCors))).toContain('gitops/ingress-cors');
  });

  it('flags an Ingress TLS secret that no Certificate declares', () => {
    const mismatched = COMPLIANT.replace(
      '  secretName: anchor-tls\n  issuerRef:',
      '  secretName: other-tls\n  issuerRef:',
    );

    expect(rules(auditor.audit(mismatched))).toContain('gitops/ingress-tls-secret');
  });

  it('flags a Certificate that omits secretName', () => {
    const result = auditor.audit(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: anchor-tls
  namespace: anchors
spec:
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - anchor.example.com
`);

    expect(rules(result)).toContain('gitops/certificate-secret');
  });

  it('flags an invalid ACME account email', () => {
    const result = auditor.audit(
      COMPLIANT.replace('email: devops@anchor.example.com', 'email: not-an-email'),
    );

    expect(rules(result)).toContain('gitops/acme-email');
  });

  it('flags a placeholder or retired ACME account email', () => {
    const result = auditor.audit(
      COMPLIANT.replace('email: devops@anchor.example.com', 'email: expired@example.com'),
    );

    expect(rules(result)).toContain('gitops/acme-email-expired');
  });

  it('flags an ACME issuer with no solvers', () => {
    const result = auditor.audit(`apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: devops@anchor.example.com
    privateKeySecretRef:
      name: letsencrypt-prod
`);

    expect(rules(result)).toContain('gitops/acme-solver');
  });

  it('honours rule overrides', () => {
    const result = auditor.audit(MISCONFIGURED, {
      rules: { 'gitops/ingress-cors': 'off', 'gitops/acme-solver': 'off' },
    });

    expect(rules(result)).not.toContain('gitops/acme-solver');
  });
});

describe('Kubernetes YAML reader', () => {
  it('parses multi-document manifests, flow collections, and block scalars', () => {
    const parsed = parseYamlDocuments(`---
apiVersion: v1
kind: ConfigMap
metadata:
  name: example
  annotations: {owner: "platform", enabled: true}
data:
  script: |
    line one
    line two
---
apiVersion: v1
kind: Secret
metadata:
  name: second
`);

    expect(parsed.errors).toEqual([]);
    expect(parsed.documents).toHaveLength(2);
    expect(parsed.documents[0]?.value).toMatchObject({
      metadata: { annotations: { owner: 'platform', enabled: true } },
      data: { script: 'line one\nline two\n' },
    });
    expect(parsed.documents[1]?.value).toMatchObject({ metadata: { name: 'second' } });
  });

  it('records syntax errors with a line number', () => {
    const parsed = parseYamlDocuments(
      'kind: Ingress\nmetadata:\n    name: anchor\n  namespace: x\n',
    );

    expect(parsed.errors.length).toBeGreaterThan(0);
    expect(parsed.errors[0]?.line).toBeGreaterThanOrEqual(1);
  });
});

describe('gitopsRules', () => {
  it('registers every rule id the auditor can emit', () => {
    const ids = gitopsRules.map((rule) => rule.id);

    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(
      expect.arrayContaining([
        'gitops/k8s-yaml-parse',
        'gitops/ingress-acme-challenge-route',
        'gitops/ingress-stellar-toml-route',
        'gitops/ingress-tls-secret',
        'gitops/ingress-cors',
        'gitops/acme-email-expired',
      ]),
    );
    expect(auditK8sManifests(COMPLIANT).ok).toBe(true);
  });
});

describe('--audit-k8s-manifests CLI flag', () => {
  it('exits 0 for compliant manifests', async () => {
    const { code, stdout } = await cli(['--audit-k8s-manifests', fixture('compliant.yaml')]);

    expect(code).toBe(0);
    expect(stdout).toContain('No SEP-1 issues found');
  });

  it('exits 1 and reports findings for misconfigured manifests', async () => {
    const { code, stdout } = await cli([
      '--audit-k8s-manifests',
      fixture('misconfigured.yaml'),
      '--format',
      'json',
    ]);

    expect(code).toBe(1);
    const parsed = JSON.parse(stdout) as { ok: boolean; diagnostics: { rule: string }[] };
    expect(parsed.ok).toBe(false);
    expect(parsed.diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      'gitops/ingress-acme-challenge-route',
    );
  });

  it('walks a directory of manifests', async () => {
    const { code } = await cli([
      '--audit-k8s-manifests',
      join(here, 'fixtures', 'k8s'),
      '--format',
      'json',
    ]);

    expect(code).toBe(1);
  });
});
