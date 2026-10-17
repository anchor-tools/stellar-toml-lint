/**
 * Reconciliation core for the StellarInfoFile operator.
 *
 * This module is deliberately free of any `@kubernetes/client-node` import:
 * everything that talks to the API server sits behind {@link KubeApi}, so the
 * validation and status logic can be unit-tested hermetically (and by the
 * repository's root vitest run, which does not install the Kubernetes SDK).
 * `client.ts` is the only file that knows the SDK exists.
 */

import { createHash } from 'node:crypto';

import { lint } from '../../src/lint.js';
import type { Diagnostic } from '../../src/types.js';

/** API group/version every resource in this integration lives under. */
export const GROUP = 'stellar.anchor-tools.io';
export const VERSION = 'v1alpha1';
export const PLURAL = 'stellarinfofiles';

/** Condition types the controller maintains, mirroring the CRD enum. */
export type ConditionType = 'Valid' | 'SyncError';

/**
 * A metav1.Condition-shaped status entry. `lastTransitionTime` only moves
 * when `status` flips, so periodic re-reconciles do not churn the object.
 */
export interface StatusCondition {
  type: ConditionType;
  status: 'True' | 'False';
  reason: string;
  message: string;
  lastTransitionTime: string;
  observedGeneration?: number;
}

export interface StellarInfoFileSpec {
  /** Raw stellar.toml source. */
  toml: string;
  /** Domain the file is served from, without scheme. */
  domain?: string;
  /** Treat warnings as errors when computing Valid. */
  strict?: boolean;
  publish?: {
    configMap?: {
      name?: string;
      key?: string;
      labels?: Record<string, string>;
    };
    ingress?: {
      host: string;
      path?: string;
      pathType?: 'Prefix' | 'Exact' | 'ImplementationSpecific';
      ingressClassName?: string;
      serviceName: string;
      servicePort?: number | string;
    };
  };
}

export interface StellarInfoFile {
  apiVersion?: string;
  kind?: string;
  metadata: {
    name: string;
    namespace: string;
    uid?: string;
    generation?: number;
    [key: string]: unknown;
  };
  spec: StellarInfoFileSpec;
  status?: {
    observedGeneration?: number;
    conditions?: StatusCondition[];
    lint?: { errors: number; warnings: number; infos: number };
    published?: {
      configMapName?: string;
      ingressName?: string;
      lastSyncedTime?: string;
    };
    [key: string]: unknown;
  };
}

/** Minimal ObjectMeta so tests and the SDK adapter share one shape. */
export interface ObjectMeta {
  name: string;
  namespace?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  resourceVersion?: string;
  ownerReferences?: Array<{
    apiVersion: string;
    kind: string;
    name: string;
    uid: string;
    controller?: boolean;
    blockOwnerDeletion?: boolean;
  }>;
}

export interface ConfigMapObject {
  apiVersion: 'v1';
  kind: 'ConfigMap';
  metadata: ObjectMeta;
  data?: Record<string, string>;
}

export interface IngressObject {
  apiVersion: 'networking.k8s.io/v1';
  kind: 'Ingress';
  metadata: ObjectMeta;
  spec: {
    ingressClassName?: string;
    rules: Array<{
      host?: string;
      http: {
        paths: Array<{
          path: string;
          pathType: string;
          backend: {
            service: {
              name: string;
              port: { number?: number; name?: string };
            };
          };
        }>;
      };
    }>;
  };
}

/**
 * The slice of the Kubernetes API the reconciler needs. Implemented for real
 * in `client.ts` and faked in the tests.
 */
export interface KubeApi {
  getConfigMap(namespace: string, name: string): Promise<ConfigMapObject | null>;
  createConfigMap(cm: ConfigMapObject): Promise<void>;
  updateConfigMap(cm: ConfigMapObject): Promise<void>;
  getIngress(namespace: string, name: string): Promise<IngressObject | null>;
  createIngress(ingress: IngressObject): Promise<void>;
  updateIngress(ingress: IngressObject): Promise<void>;
  /** Patches the /status subresource wholesale. */
  patchStatus(namespace: string, name: string, status: StellarInfoFile['status']): Promise<void>;
}

/** Outcome of linting one stellar.toml source. */
export interface ValidationResult {
  valid: boolean;
  counts: { error: number; warning: number; info: number };
  diagnostics: Diagnostic[];
}

/**
 * Lints a stellar.toml source the same way the CLI does, offline.
 *
 * Network probes (`--check-network`) are intentionally not wired in: an
 * operator that reached the reconcile loop already has the file in hand, and
 * a transient Horizon outage must not flip a resource's Valid condition.
 */
export function validateToml(
  source: string,
  options: { domain?: string; strict?: boolean } = {},
): ValidationResult {
  const { domain, strict } = options;
  const result = lint(source, { ...(domain ? { domain } : {}), ...(strict ? { strict } : {}) });
  return {
    valid: result.ok,
    counts: result.counts,
    diagnostics: result.diagnostics,
  };
}

/** Cap on diagnostics echoed into a condition message. */
const MAX_REPORTED_DIAGNOSTICS = 3;
const MAX_DIAGNOSTIC_MESSAGE = 200;

/**
 * Renders a validation verdict as a single-line condition message, e.g.
 * `2 errors, 1 warning: file/parse: Invalid TOML: ... (+2 more)`.
 *
 * Condition messages land in `kubectl describe` output and etcd, so they are
 * deliberately truncated: the full report belongs to the CLI, not the apiserver.
 */
export function formatValidationMessage(validation: ValidationResult): string {
  const { error, warning, info } = validation.counts;
  const counts = `${error} error${error === 1 ? '' : 's'}, ${warning} warning${
    warning === 1 ? '' : 's'
  }, ${info} info`;
  if (validation.valid) {
    return `stellar.toml passed SEP-1 validation (${counts})`;
  }
  const shown = validation.diagnostics.slice(0, MAX_REPORTED_DIAGNOSTICS).map((d) => {
    const message =
      d.message.length > MAX_DIAGNOSTIC_MESSAGE
        ? `${d.message.slice(0, MAX_DIAGNOSTIC_MESSAGE)}…`
        : d.message;
    return `${d.rule}: ${message}`;
  });
  const remaining = validation.diagnostics.length - shown.length;
  const suffix = remaining > 0 ? ` (+${remaining} more)` : '';
  return `stellar.toml failed SEP-1 validation (${counts}): ${shown.join('; ')}${suffix}`;
}

/** Default ConfigMap name for a StellarInfoFile. */
export function defaultConfigMapName(cr: StellarInfoFile): string {
  return `${cr.metadata.name}-stellar-toml`;
}

/** Default Ingress name for a StellarInfoFile. */
export function defaultIngressName(cr: StellarInfoFile): string {
  return `${cr.metadata.name}-stellar-toml`;
}

/** SHA-256 of the TOML, hex-encoded — lets consumers detect changes. */
export function contentChecksum(toml: string): string {
  return createHash('sha256').update(toml, 'utf8').digest('hex');
}

/** Labels/annotations every object the controller owns carries. */
function commonMetadata(
  cr: StellarInfoFile,
): Pick<ObjectMeta, 'labels' | 'annotations' | 'ownerReferences'> {
  const labels: Record<string, string> = {
    'app.kubernetes.io/managed-by': 'stellar-toml-lint',
    'stellar.anchor-tools.io/kind': 'StellarInfoFile',
  };
  // The resource name goes in an annotation rather than a label: CR names can
  // be up to 253 characters, label values are capped at 63.
  const annotations: Record<string, string> = {
    'stellar.anchor-tools.io/resource': `${cr.metadata.namespace}/${cr.metadata.name}`,
    'stellar.toml.lint/checksum-sha256': contentChecksum(cr.spec.toml),
  };
  // Without a uid (synthetic objects in tests) an owner reference would be
  // rejected by the API server, so only attach it when we have one.
  const ownerReferences = cr.metadata.uid
    ? [
        {
          apiVersion: `${GROUP}/${VERSION}`,
          kind: 'StellarInfoFile',
          name: cr.metadata.name,
          uid: cr.metadata.uid,
          controller: true,
          blockOwnerDeletion: true,
        },
      ]
    : undefined;
  return {
    labels: { ...labels, ...cr.spec.publish?.configMap?.labels },
    annotations,
    ...(ownerReferences ? { ownerReferences } : {}),
  };
}

/** Renders the ConfigMap that carries the validated TOML. */
export function buildConfigMap(cr: StellarInfoFile): ConfigMapObject {
  const key = cr.spec.publish?.configMap?.key ?? 'stellar.toml';
  return {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: cr.spec.publish?.configMap?.name ?? defaultConfigMapName(cr),
      namespace: cr.metadata.namespace,
      ...commonMetadata(cr),
    },
    data: { [key]: cr.spec.toml },
  };
}

/** Renders the Ingress when the spec asks for one, else `null`. */
export function buildIngress(cr: StellarInfoFile): IngressObject | null {
  const ingress = cr.spec.publish?.ingress;
  if (!ingress) return null;
  const port = ingress.servicePort ?? 80;
  return {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'Ingress',
    metadata: {
      name: defaultIngressName(cr),
      namespace: cr.metadata.namespace,
      ...commonMetadata(cr),
    },
    spec: {
      ...(ingress.ingressClassName ? { ingressClassName: ingress.ingressClassName } : {}),
      rules: [
        {
          host: ingress.host,
          http: {
            paths: [
              {
                path: ingress.path ?? '/.well-known/stellar.toml',
                pathType: ingress.pathType ?? 'Prefix',
                backend: {
                  service: {
                    name: ingress.serviceName,
                    port: typeof port === 'string' ? { name: port } : { number: port },
                  },
                },
              },
            ],
          },
        },
      ],
    },
  };
}

/**
 * Builds a condition, preserving `lastTransitionTime` while `status` is
 * unchanged (metav1.Condition semantics). */
export function buildCondition(
  previous: StatusCondition | undefined,
  next: Omit<StatusCondition, 'lastTransitionTime'>,
  now: () => Date,
): StatusCondition {
  const unchanged = previous !== undefined && previous.status === next.status;
  return {
    ...next,
    lastTransitionTime: unchanged ? previous.lastTransitionTime : now().toISOString(),
  };
}

function findCondition(
  conditions: StatusCondition[] | undefined,
  type: ConditionType,
): StatusCondition | undefined {
  return conditions?.find((c) => c.type === type);
}

/** Everything one reconcile pass produced, for logging and tests. */
export interface ReconcileOutcome {
  namespace: string;
  name: string;
  validation: ValidationResult;
  conditions: StatusCondition[];
  published: { configMapName?: string; ingressName?: string; lastSyncedTime?: string };
  /** Sync failure message, if the API server rejected a write. */
  syncError?: string;
}

/** Extracts a readable message from an SDK/API error. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    // ApiException stringifies headers too; prefer the structured body when present.
    const body = (err as { body?: unknown }).body;
    if (typeof body === 'string') {
      try {
        const parsed: unknown = JSON.parse(body);
        if (
          typeof parsed === 'object' &&
          parsed !== null &&
          'message' in parsed &&
          typeof (parsed as { message: unknown }).message === 'string'
        ) {
          return (parsed as { message: string }).message;
        }
      } catch {
        // fall through to err.message
      }
    }
    return err.message;
  }
  return String(err);
}

/** Create-or-replace helper: the API server rejects creates that race a
 * stale read, so updates carry the freshly-read resourceVersion. */
async function applyConfigMap(api: KubeApi, desired: ConfigMapObject): Promise<void> {
  const existing = await api.getConfigMap(desired.metadata.namespace!, desired.metadata.name);
  if (existing === null) {
    await api.createConfigMap(desired);
  } else {
    await api.updateConfigMap({
      ...desired,
      metadata: {
        ...desired.metadata,
        ...(existing.metadata.resourceVersion
          ? { resourceVersion: existing.metadata.resourceVersion }
          : {}),
      },
    });
  }
}

async function applyIngress(api: KubeApi, desired: IngressObject): Promise<void> {
  const existing = await api.getIngress(desired.metadata.namespace!, desired.metadata.name);
  if (existing === null) {
    await api.createIngress(desired);
  } else {
    await api.updateIngress({
      ...desired,
      metadata: {
        ...desired.metadata,
        ...(existing.metadata.resourceVersion
          ? { resourceVersion: existing.metadata.resourceVersion }
          : {}),
      },
    });
  }
}

/**
 * Reconciles one StellarInfoFile:
 *
 * 1. lint `spec.toml` (offline, deterministic);
 * 2. publish validated content to a ConfigMap — and an Ingress when
 *    `spec.publish.ingress` is set — never publishing content that failed;
 * 3. patch `/status` with the `Valid` and `SyncError` conditions.
 *
 * A spec that stops validating leaves the last published ConfigMap alone: a
 * typo in a CR must not take down a running anchor's well-known file.
 */
export async function reconcile(
  api: KubeApi,
  cr: StellarInfoFile,
  options: { now?: () => Date } = {},
): Promise<ReconcileOutcome> {
  const now = options.now ?? (() => new Date());
  const generation = cr.metadata.generation;
  const previous = cr.status?.conditions;

  const validation = validateToml(cr.spec.toml, {
    ...(cr.spec.domain !== undefined ? { domain: cr.spec.domain } : {}),
    ...(cr.spec.strict !== undefined ? { strict: cr.spec.strict } : {}),
  });

  const published: ReconcileOutcome['published'] = { ...cr.status?.published };
  let syncError: string | undefined;

  if (validation.valid) {
    try {
      await applyConfigMap(api, buildConfigMap(cr));
      published.configMapName = buildConfigMap(cr).metadata.name;
      const ingress = buildIngress(cr);
      if (ingress) {
        await applyIngress(api, ingress);
        published.ingressName = ingress.metadata.name;
      }
      published.lastSyncedTime = now().toISOString();
    } catch (err) {
      syncError = errorMessage(err);
    }
  }

  const validCondition = buildCondition(
    findCondition(previous, 'Valid'),
    {
      type: 'Valid',
      status: validation.valid ? 'True' : 'False',
      reason: validation.valid ? 'LintPassed' : 'LintFailed',
      message: formatValidationMessage(validation),
      ...(generation !== undefined ? { observedGeneration: generation } : {}),
    },
    now,
  );

  const syncCondition = buildCondition(
    findCondition(previous, 'SyncError'),
    syncError !== undefined
      ? {
          type: 'SyncError',
          status: 'True',
          reason: 'PublishFailed',
          message: `failed to publish: ${syncError}`,
          ...(generation !== undefined ? { observedGeneration: generation } : {}),
        }
      : {
          type: 'SyncError',
          status: 'False',
          reason: validation.valid ? 'Published' : 'Skipped',
          message: validation.valid
            ? `ConfigMap ${published.configMapName ?? defaultConfigMapName(cr)} is up to date`
            : 'sync skipped until the spec passes validation',
          ...(generation !== undefined ? { observedGeneration: generation } : {}),
        },
    now,
  );

  const conditions = [validCondition, syncCondition];
  const status: StellarInfoFile['status'] = {
    ...(generation !== undefined ? { observedGeneration: generation } : {}),
    conditions,
    lint: {
      errors: validation.counts.error,
      warnings: validation.counts.warning,
      infos: validation.counts.info,
    },
    published,
  };

  // A status patch failure is worth surfacing but must not swallow the
  // validation outcome the caller is about to log.
  try {
    await api.patchStatus(cr.metadata.namespace, cr.metadata.name, status);
  } catch (err) {
    syncError = syncError ?? `status patch failed: ${errorMessage(err)}`;
  }

  return {
    namespace: cr.metadata.namespace,
    name: cr.metadata.name,
    validation,
    conditions,
    published,
    ...(syncError !== undefined ? { syncError } : {}),
  };
}
