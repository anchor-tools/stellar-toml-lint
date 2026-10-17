# Kubernetes operator for StellarInfoFile

Declaratively sync an anchor's `stellar.toml` to Kubernetes: declare the file
as a `StellarInfoFile` Custom Resource and the controller lints it, publishes
it to a ConfigMap (and optional Ingress), and records `Valid`/`SyncError`
status conditions.

## Custom Resource Definition

Apply the CRD once per cluster:

```bash
kubectl apply -f crds/stellarinfofile.yaml
```

## Example resource

```bash
kubectl apply -f samples/stellarinfofile.yaml
kubectl get sif -w
kubectl get configmap example-anchor-stellar-toml -o yaml
```

An invalid spec is refused: `Valid=False` with reason `LintFailed`, and the
last published ConfigMap is left untouched.

## Operator

```bash
npm install
npm run build           # tsc --noEmit (typecheck) then emits dist/
npm test                # vitest
npm run typecheck
node dist/main.js       # watches StellarInfoFiles; picks up KUBECONFIG or the in-cluster service account
```

## Project layout

- `crds/stellarinfofile.yaml` — OpenAPI v3 CustomResourceDefinition (`stellar.anchor-tools.io/v1alpha1`)
- `samples/` — valid and invalid `StellarInfoFile` manifests
- `controller.ts` — reconciliation core (lint → publish → status; SDK-free, unit-tested)
- `client.ts` — `@kubernetes/client-node` adapter behind the `KubeApi` interface
- `main.ts` — operator entrypoint: watch + resync loop
- `log.ts` — structured reconcile-outcome logging
- `test/controller.test.ts` — CRD schema assertions plus reconciliation against the sample CRs

License: Apache-2.0
