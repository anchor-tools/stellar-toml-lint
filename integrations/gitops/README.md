# GitOps admission validation

The validating webhook accepts Kubernetes `AdmissionReview` requests containing
`stellar.toml` under `data`, `binaryData`, or `stellarToml`. Invalid TOML or SEP-1
errors are denied with diagnostics in the response status.

Build the package and run the listener on port 8080:

```bash
npm run build
PORT=8443 node dist/integrations/gitops/server.js
```

The webhook expects HTTPS and should be exposed behind a Kubernetes Service with
a serving certificate trusted by the API server. `PORT` may be set to change
the listener port. The request body is limited to 1 MiB.

`samples/validating-webhook.yaml` shows the API-server admission registration.
`samples/argocd-presync-job.yaml` validates during Argo CD's PreSync phase, and
`samples/flux-configmap.yaml` demonstrates a labeled object that the validating
webhook intercepts; a denied create/update fails the Flux reconciliation.

The evaluator is also exported as `evaluateGitOpsAdmission` for controllers and
tests that already own their HTTP server.
