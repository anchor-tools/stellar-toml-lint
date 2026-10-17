/**
 * The only file that imports `@kubernetes/client-node`.
 *
 * Adapts the SDK to the {@link KubeApi} interface the reconciler consumes,
 * so the rest of the integration (and every test) stays SDK-free.
 */

import * as k8s from '@kubernetes/client-node';

import {
  GROUP,
  PLURAL,
  VERSION,
  type ConfigMapObject,
  type IngressObject,
  type KubeApi,
  type StellarInfoFile,
} from './controller.js';

/** Error shape the generated client throws; keeps us off `any`. */
interface ApiError {
  code?: number;
  body?: unknown;
}

function apiErrorCode(err: unknown): number | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const { code } = err as ApiError;
    if (typeof code === 'number') return code;
  }
  return undefined;
}

/**
 * The generated CustomObjectsApi sends PATCH bodies as `application/json`,
 * which the API server then decodes as a JSON Patch (RFC 6902) array — a
 * bare `{status: ...}` object comes back as
 * `cannot unmarshal object into Go value of type []handlers.jsonPatchOp`.
 *
 * Passing a one-op JSON Patch array works and is what we do here; the
 * alternative (merge-patch content-type) requires a middleware the SDK's
 * `makeApiClient` does not forward in v2.
 */
function statusPatchBody(status: StellarInfoFile['status']): Array<{
  op: string;
  path: string;
  value: unknown;
}> {
  return [{ op: 'replace', path: '/status', value: status ?? {} }];
}

/**
 * Builds a {@link KubeApi} backed by `@kubernetes/client-node`.
 *
 * Loads `KUBECONFIG`/`~/.kube/config` by default; pass a config explicitly
 * (e.g. from `k8s.loadFromCluster()` in-cluster) when needed.
 */
export function createKubeApi(kubeConfig?: k8s.KubeConfig): KubeApi {
  const kc = kubeConfig ?? new k8s.KubeConfig();
  if (!kubeConfig) kc.loadFromDefault();

  const customObjects = kc.makeApiClient(k8s.CustomObjectsApi);
  const core = kc.makeApiClient(k8s.CoreV1Api);
  const networking = kc.makeApiClient(k8s.NetworkingV1Api);

  const crRef = { group: GROUP, version: VERSION, plural: PLURAL } as const;

  return {
    async getConfigMap(namespace, name) {
      try {
        return (await core.readNamespacedConfigMap({ name, namespace })) as ConfigMapObject;
      } catch (err) {
        if (apiErrorCode(err) === 404) return null;
        throw err;
      }
    },

    async createConfigMap(cm) {
      await core.createNamespacedConfigMap({ namespace: cm.metadata.namespace!, body: cm });
    },

    async updateConfigMap(cm) {
      await core.replaceNamespacedConfigMap({
        name: cm.metadata.name,
        namespace: cm.metadata.namespace!,
        body: cm,
      });
    },

    async getIngress(namespace, name) {
      try {
        return (await networking.readNamespacedIngress({ name, namespace })) as IngressObject;
      } catch (err) {
        if (apiErrorCode(err) === 404) return null;
        throw err;
      }
    },

    async createIngress(ingress) {
      await networking.createNamespacedIngress({
        namespace: ingress.metadata.namespace!,
        body: ingress,
      });
    },

    async updateIngress(ingress) {
      await networking.replaceNamespacedIngress({
        name: ingress.metadata.name,
        namespace: ingress.metadata.namespace!,
        body: ingress,
      });
    },

    async patchStatus(namespace, name, status) {
      await customObjects.patchNamespacedCustomObjectStatus({
        ...crRef,
        namespace,
        name,
        body: statusPatchBody(status),
      });
    },
  };
}

/**
 * Loads kubeconfig the way an operator should: in-cluster service account
 * when running inside the cluster, user kubeconfig otherwise.
 */
export function loadKubeConfig(): k8s.KubeConfig {
  const kc = new k8s.KubeConfig();
  if (process.env.KUBERNETES_SERVICE_HOST && process.env.KUBERNETES_SERVICE_PORT) {
    kc.loadFromCluster();
  } else {
    kc.loadFromDefault();
  }
  return kc;
}

export type { StellarInfoFile } from './controller.js';

/** Lists every StellarInfoFile in the cluster (used by the resync loop). */
export async function listStellarInfoFiles(kc: k8s.KubeConfig): Promise<StellarInfoFile[]> {
  const api = kc.makeApiClient(k8s.CustomObjectsApi);
  const res = (await api.listClusterCustomObject({
    group: GROUP,
    version: VERSION,
    plural: PLURAL,
  })) as { items?: StellarInfoFile[] };
  return res.items ?? [];
}

/**
 * Watches StellarInfoFile events, invoking `onEvent` for each ADDED /
 * MODIFIED / DELETED notification. Resolves when the watch ends; callers
 * decide whether to re-establish it.
 */
export async function watchStellarInfoFiles(
  kc: k8s.KubeConfig,
  onEvent: (type: string, cr: StellarInfoFile) => void,
): Promise<() => void> {
  const watch = new k8s.Watch(kc);
  const abort = await watch.watch(
    `/apis/${GROUP}/${VERSION}/${PLURAL}`,
    {},
    (phase, obj) => {
      if (phase === 'ADDED' || phase === 'MODIFIED' || phase === 'DELETED') {
        onEvent(phase, obj as StellarInfoFile);
      }
    },
    (err) => {
      if (err) {
        // The watch died; surface it so the caller can log and reconnect.
        process.stderr.write(`stellar-toml-lint: watch ended: ${String(err)}\n`);
      }
    },
  );
  return () => abort.abort();
}
