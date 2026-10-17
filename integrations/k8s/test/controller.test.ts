import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

/** A permissive OpenAPI v3 schema node, narrow enough for the assertions below. */
interface OpenAPISchemaNode {
  type?: string;
  required?: string[];
  properties?: Record<string, OpenAPISchemaNode>;
  items?: OpenAPISchemaNode;
  enum?: string[];
  minLength?: number;
  maxLength?: number;
  [key: string]: unknown;
}

import {
  buildCondition,
  buildConfigMap,
  buildIngress,
  contentChecksum,
  defaultConfigMapName,
  formatValidationMessage,
  GROUP,
  reconcile,
  validateToml,
  type ConfigMapObject,
  type IngressObject,
  type KubeApi,
  type StatusCondition,
  type StellarInfoFile,
} from '../controller.js';

const here = dirname(fileURLToPath(import.meta.url));
const sampleDir = join(here, '..', 'samples');
const crdPath = join(here, '..', 'crds', 'stellarinfofile.yaml');

function loadSample(name: string): StellarInfoFile {
  const cr = parse(readFileSync(join(sampleDir, name), 'utf8')) as StellarInfoFile;
  // The API server defaults a namespaced object's namespace and assigns a
  // generation on admission; the fixture manifests omit both, so stand in
  // for that behavior here.
  cr.metadata.namespace ??= 'default';
  cr.metadata.generation ??= 1;
  return cr;
}

/** In-memory KubeApi double that records writes and can be told to fail. */
class FakeKubeApi implements KubeApi {
  configMaps = new Map<string, ConfigMapObject>();
  ingresses = new Map<string, IngressObject>();
  statuses = new Map<string, StellarInfoFile['status']>();
  failConfigMapWrite: string | undefined;

  private key(namespace: string, name: string): string {
    return `${namespace}/${name}`;
  }

  async getConfigMap(namespace: string, name: string): Promise<ConfigMapObject | null> {
    return this.configMaps.get(this.key(namespace, name)) ?? null;
  }

  async createConfigMap(cm: ConfigMapObject): Promise<void> {
    if (this.failConfigMapWrite) throw new Error(this.failConfigMapWrite);
    this.configMaps.set(this.key(cm.metadata.namespace!, cm.metadata.name), cm);
  }

  async updateConfigMap(cm: ConfigMapObject): Promise<void> {
    if (this.failConfigMapWrite) throw new Error(this.failConfigMapWrite);
    this.configMaps.set(this.key(cm.metadata.namespace!, cm.metadata.name), cm);
  }

  async getIngress(namespace: string, name: string): Promise<IngressObject | null> {
    return this.ingresses.get(this.key(namespace, name)) ?? null;
  }

  async createIngress(ingress: IngressObject): Promise<void> {
    this.ingresses.set(this.key(ingress.metadata.namespace!, ingress.metadata.name), ingress);
  }

  async updateIngress(ingress: IngressObject): Promise<void> {
    this.ingresses.set(this.key(ingress.metadata.namespace!, ingress.metadata.name), ingress);
  }

  async patchStatus(
    namespace: string,
    name: string,
    status: StellarInfoFile['status'],
  ): Promise<void> {
    this.statuses.set(this.key(namespace, name), status);
  }
}

function condition(
  conditions: StatusCondition[] | undefined,
  type: string,
): StatusCondition | undefined {
  return conditions?.find((c) => c.type === type);
}

describe('CRD manifest', () => {
  const crd = parse(readFileSync(crdPath, 'utf8')) as {
    apiVersion: string;
    kind: string;
    metadata: { name: string };
    spec: {
      group: string;
      scope: string;
      names: { plural: string; kind: string; shortNames: string[] };
      versions: Array<{
        name: string;
        served: boolean;
        storage: boolean;
        subresources: Record<string, unknown>;
        additionalPrinterColumns: Array<{ name: string; jsonPath: string }>;
        schema: { openAPIV3Schema: OpenAPISchemaNode };
      }>;
    };
  };

  it('is an apiextensions.k8s.io/v1 CustomResourceDefinition', () => {
    expect(crd.apiVersion).toBe('apiextensions.k8s.io/v1');
    expect(crd.kind).toBe('CustomResourceDefinition');
    expect(crd.metadata.name).toBe('stellarinfofiles.stellar.anchor-tools.io');
  });

  it('declares the StellarInfoFile names the controller relies on', () => {
    expect(crd.spec.group).toBe(GROUP);
    expect(crd.spec.scope).toBe('Namespaced');
    expect(crd.spec.names.kind).toBe('StellarInfoFile');
    expect(crd.spec.names.plural).toBe('stellarinfofiles');
    expect(crd.spec.names.shortNames).toContain('sif');
  });

  it('serves one storage version with a status subresource', () => {
    const version = crd.spec.versions[0]!;
    expect(version.name).toBe('v1alpha1');
    expect(version.served).toBe(true);
    expect(version.storage).toBe(true);
    expect(version.subresources).toHaveProperty('status');
  });

  it('requires spec.toml as a bounded string (OpenAPI v3)', () => {
    const schema = crd.spec.versions[0]!.schema.openAPIV3Schema;
    const spec = schema.properties!.spec!;
    expect(spec.required!).toContain('toml');
    expect(spec.properties!.toml!.type).toBe('string');
    expect(spec.properties!.toml!.minLength).toBe(1);
    expect(spec.properties!.toml!.maxLength).toBe(100 * 1024);
  });

  it('exposes exactly the Valid and SyncError condition types in status', () => {
    const schema = crd.spec.versions[0]!.schema.openAPIV3Schema;
    const status = schema.properties!.status!;
    const conditionSchema = status.properties!.conditions!.items!;
    expect(conditionSchema.properties!.type!.enum).toEqual(['Valid', 'SyncError']);
    expect(conditionSchema.properties!.status!.enum).toEqual(['True', 'False']);
    // metav1 condition list must be a map keyed by type for merge semantics
    expect(status.properties!.conditions!['x-kubernetes-list-map-keys']).toEqual(['type']);
  });

  it('prints Domain/Valid/SyncError/ConfigMap columns', () => {
    const columns = crd.spec.versions[0]!.additionalPrinterColumns.map((c) => c.name);
    expect(columns).toEqual(
      expect.arrayContaining(['Domain', 'Valid', 'SyncError', 'ConfigMap', 'Age']),
    );
  });
});

describe('validateToml', () => {
  it("accepts the valid sample CR's TOML", () => {
    const cr = loadSample('stellarinfofile.yaml');
    const result = validateToml(cr.spec.toml, { domain: cr.spec.domain });
    expect(result.valid).toBe(true);
    expect(result.counts.error).toBe(0);
  });

  it("rejects the invalid sample CR's TOML with a parse diagnostic", () => {
    const cr = loadSample('stellarinfofile-invalid.yaml');
    const result = validateToml(cr.spec.toml, {});
    expect(result.valid).toBe(false);
    expect(result.counts.error).toBeGreaterThan(0);
    expect(result.diagnostics.some((d) => d.rule === 'file/parse')).toBe(true);
  });

  it('strict mode fails warnings', () => {
    // The valid sample still emits warnings (e.g. missing ORG_LOGO); strict
    // must flip it to invalid.
    const cr = loadSample('stellarinfofile.yaml');
    const lenient = validateToml(cr.spec.toml, { domain: cr.spec.domain });
    const strict = validateToml(cr.spec.toml, { domain: cr.spec.domain, strict: true });
    expect(lenient.valid).toBe(true);
    expect(lenient.counts.warning).toBeGreaterThan(0);
    expect(strict.valid).toBe(false);
  });

  it('passes the domain through for same-domain checks', () => {
    const source =
      'VERSION = "2.7.0"\n[DOCUMENTATION]\nORG_NAME = "X"\nORG_URL = "https://other.example.net"\n';
    const withoutDomain = validateToml(source, {});
    const withDomain = validateToml(source, { domain: 'example.com' });
    // Domain mismatch may be a warning or error depending on rule config, but
    // it must at least add a diagnostic the domain-less run does not have.
    expect(withDomain.diagnostics.length).toBeGreaterThan(withoutDomain.diagnostics.length);
  });
});

describe('formatValidationMessage', () => {
  it('summarises a passing run', () => {
    const cr = loadSample('stellarinfofile.yaml');
    const message = formatValidationMessage(validateToml(cr.spec.toml, {}));
    expect(message).toMatch(
      /^stellar\.toml passed SEP-1 validation \(0 errors, \d+ warnings?, \d+ info\)$/,
    );
  });

  it('truncates a failing run and counts the rest', () => {
    // Synthesise more diagnostics than the message shows; a parse error would
    // short-circuit the real linter to a single diagnostic.
    const diagnostics = Array.from({ length: 5 }, (_, i) => ({
      rule: `rule/${i}`,
      severity: 'error' as const,
      category: 'file' as const,
      message: `problem ${i}`,
    }));
    const message = formatValidationMessage({
      valid: false,
      counts: { error: 5, warning: 0, info: 0 },
      diagnostics,
    });
    expect(message).toContain('failed SEP-1 validation');
    expect(message).toContain('rule/0: problem 0');
    expect(message).toContain('rule/2: problem 2');
    expect(message).not.toContain('rule/3');
    expect(message).toMatch(/\(\+2 more\)$/);
  });
});

describe('builders', () => {
  const cr = loadSample('stellarinfofile.yaml');

  it('builds a ConfigMap named <resource>-stellar-toml carrying the TOML', () => {
    const cm = buildConfigMap(cr);
    expect(cm.kind).toBe('ConfigMap');
    expect(cm.metadata.name).toBe(defaultConfigMapName(cr));
    expect(cm.metadata.namespace).toBe(cr.metadata.namespace);
    expect(cm.data?.['stellar.toml']).toBe(cr.spec.toml);
  });

  it('labels and checksums managed ConfigMaps', () => {
    const cm = buildConfigMap(cr);
    expect(cm.metadata.labels?.['app.kubernetes.io/managed-by']).toBe('stellar-toml-lint');
    expect(cm.metadata.annotations?.['stellar.toml.lint/checksum-sha256']).toBe(
      contentChecksum(cr.spec.toml),
    );
  });

  it('attaches an owner reference only when a uid is present', () => {
    expect(
      buildConfigMap({ ...cr, metadata: { ...cr.metadata, uid: undefined } }).metadata
        .ownerReferences,
    ).toBeUndefined();
    expect(
      buildConfigMap({ ...cr, metadata: { ...cr.metadata, uid: 'uid-123' } }).metadata
        .ownerReferences,
    ).toEqual([
      expect.objectContaining({
        kind: 'StellarInfoFile',
        name: 'example-anchor',
        uid: 'uid-123',
        controller: true,
      }),
    ]);
  });

  it('builds the Ingress from spec.publish.ingress', () => {
    const ingress = buildIngress(cr);
    expect(ingress?.kind).toBe('Ingress');
    expect(ingress?.spec.rules[0]?.host).toBe('example.com');
    const path = ingress?.spec.rules[0]?.http.paths[0];
    expect(path?.path).toBe('/.well-known/stellar.toml');
    expect(path?.backend.service).toEqual({ name: 'example-anchor-web', port: { number: 80 } });
  });

  it('returns null when no ingress is requested', () => {
    const { publish: _publish, ...noPublish } = cr.spec;
    expect(buildIngress({ ...cr, spec: noPublish })).toBeNull();
  });
});

describe('buildCondition', () => {
  const now1 = () => new Date('2026-01-01T00:00:00Z');
  const now2 = () => new Date('2026-02-02T00:00:00Z');

  it('sets lastTransitionTime on first sighting', () => {
    const c = buildCondition(
      undefined,
      { type: 'Valid', status: 'False', reason: 'LintFailed', message: 'nope' },
      now1,
    );
    expect(c.lastTransitionTime).toBe('2026-01-01T00:00:00.000Z');
  });

  it('keeps lastTransitionTime while status is unchanged', () => {
    const previous = buildCondition(
      undefined,
      { type: 'Valid', status: 'False', reason: 'LintFailed', message: 'nope' },
      now1,
    );
    const next = buildCondition(
      previous,
      { type: 'Valid', status: 'False', reason: 'LintFailed', message: 'still nope' },
      now2,
    );
    expect(next.lastTransitionTime).toBe('2026-01-01T00:00:00.000Z');
  });

  it('advances lastTransitionTime when status flips', () => {
    const previous = buildCondition(
      undefined,
      { type: 'Valid', status: 'False', reason: 'LintFailed', message: 'nope' },
      now1,
    );
    const next = buildCondition(
      previous,
      { type: 'Valid', status: 'True', reason: 'LintPassed', message: 'ok' },
      now2,
    );
    expect(next.lastTransitionTime).toBe('2026-02-02T00:00:00.000Z');
  });
});

describe('reconcile — applying the sample CRDs', () => {
  it('publishes the valid sample to a ConfigMap and Ingress, Valid=True', async () => {
    const cr = loadSample('stellarinfofile.yaml');
    const api = new FakeKubeApi();
    const outcome = await reconcile(api, cr);

    // Validation output
    expect(outcome.validation.valid).toBe(true);
    expect(condition(outcome.conditions, 'Valid')).toMatchObject({
      status: 'True',
      reason: 'LintPassed',
    });
    expect(condition(outcome.conditions, 'SyncError')).toMatchObject({
      status: 'False',
      reason: 'Published',
    });

    // ConfigMap contents mirror the CR spec exactly
    const cm = await api.getConfigMap('default', 'example-anchor-stellar-toml');
    expect(cm?.data?.['stellar.toml']).toBe(cr.spec.toml);

    // Ingress published too
    const ingress = await api.getIngress('default', 'example-anchor-stellar-toml');
    expect(ingress?.spec.rules[0]?.host).toBe('example.com');

    // Status recorded
    const status = api.statuses.get('default/example-anchor');
    expect(status?.observedGeneration).toBe(cr.metadata.generation);
    expect(status?.published?.configMapName).toBe('example-anchor-stellar-toml');
    expect(status?.published?.ingressName).toBe('example-anchor-stellar-toml');
    expect(status?.lint).toEqual({
      errors: 0,
      warnings: expect.any(Number),
      infos: expect.any(Number),
    });
  });

  it('refuses to publish the invalid sample, Valid=False with parse error', async () => {
    const cr = loadSample('stellarinfofile-invalid.yaml');
    const api = new FakeKubeApi();
    const outcome = await reconcile(api, cr);

    expect(outcome.validation.valid).toBe(false);
    expect(condition(outcome.conditions, 'Valid')).toMatchObject({
      status: 'False',
      reason: 'LintFailed',
    });
    expect(condition(outcome.conditions, 'Valid')?.message).toContain('file/parse');
    expect(condition(outcome.conditions, 'SyncError')).toMatchObject({
      status: 'False',
      reason: 'Skipped',
    });

    // Nothing was published for the broken resource
    expect(api.configMaps.size).toBe(0);
    expect(api.ingresses.size).toBe(0);
  });

  it('keeps the last published ConfigMap when a spec stops validating', async () => {
    const valid = loadSample('stellarinfofile.yaml');
    const api = new FakeKubeApi();
    await reconcile(api, valid);
    const published = api.configMaps.get('default/example-anchor-stellar-toml');
    expect(published).toBeDefined();

    // Now the anchor edits their TOML badly; the old ConfigMap must survive.
    const broken: StellarInfoFile = {
      ...valid,
      spec: { ...valid.spec, toml: 'VERSION = https://oops.example.com\n' },
    };
    const outcome = await reconcile(api, broken);
    expect(outcome.validation.valid).toBe(false);
    expect(api.configMaps.get('default/example-anchor-stellar-toml')).toEqual(published);
  });

  it('creates, then updates, the ConfigMap with resourceVersion', async () => {
    const cr = loadSample('stellarinfofile.yaml');
    const api = new FakeKubeApi();
    await reconcile(api, cr);
    // Simulate the server assigning a resourceVersion on read
    const existing = api.configMaps.get('default/example-anchor-stellar-toml')!;
    existing.metadata.resourceVersion = '42';

    const observed: Array<string | undefined> = [];
    const originalUpdate = api.updateConfigMap.bind(api);
    api.updateConfigMap = async (cm) => {
      observed.push(cm.metadata.resourceVersion);
      return originalUpdate(cm);
    };
    await reconcile(api, cr);
    expect(observed).toEqual(['42']);
  });

  it('reports SyncError=True when the ConfigMap write fails', async () => {
    const cr = loadSample('stellarinfofile.yaml');
    const api = new FakeKubeApi();
    api.failConfigMapWrite = 'etcdserver: request timed out';
    const outcome = await reconcile(api, cr);

    // Validation still passes — the content is fine, the write is not.
    expect(condition(outcome.conditions, 'Valid')).toMatchObject({ status: 'True' });
    expect(condition(outcome.conditions, 'SyncError')).toMatchObject({
      status: 'True',
      reason: 'PublishFailed',
    });
    expect(condition(outcome.conditions, 'SyncError')?.message).toContain('etcdserver');
    expect(outcome.syncError).toContain('etcdserver');
  });

  it('carries observedGeneration into both conditions', async () => {
    const cr = loadSample('stellarinfofile.yaml');
    const outcome = await reconcile(new FakeKubeApi(), cr);
    for (const c of outcome.conditions) {
      expect(c.observedGeneration).toBe(cr.metadata.generation);
    }
  });
});
