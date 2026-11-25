import type {
  Diagnostic,
  LintResult,
  Rule,
  RuleCategory,
  RuleOverrides,
  Severity,
} from '../types.js';
import { parseYamlDocuments } from './yaml.js';

/**
 * Audits the Kubernetes objects that keep an anchor's TLS certificate alive.
 *
 * cert-manager renewals fail in ways that are invisible until the certificate
 * actually expires: an Ingress that no longer routes the ACME HTTP-01 path, a
 * TLS secret that does not match the Certificate that owns it, an issuer
 * annotation pointing at a renamed ClusterIssuer, or a missing CORS annotation
 * that makes the renewed stellar.toml unreadable to browser wallets. This
 * module checks all of those from the manifests themselves, with no cluster
 * access and no native YAML parser.
 */

const CATEGORY: RuleCategory = 'gitops';

const PARSE_RULE = 'gitops/k8s-yaml-parse';
const SCHEMA_RULE = 'gitops/k8s-schema';
const INGRESS_ACME_ROUTE_RULE = 'gitops/ingress-acme-challenge-route';
const INGRESS_STELLAR_ROUTE_RULE = 'gitops/ingress-stellar-toml-route';
const INGRESS_TLS_SECRET_RULE = 'gitops/ingress-tls-secret';
const INGRESS_ANNOTATION_RULE = 'gitops/ingress-annotation';
const INGRESS_CORS_RULE = 'gitops/ingress-cors';
const CERTIFICATE_SECRET_RULE = 'gitops/certificate-secret';
const CERTIFICATE_ISSUER_RULE = 'gitops/certificate-issuer';
const CERTIFICATE_DNS_RULE = 'gitops/certificate-dns-names';
const CERTIFICATE_EXPIRED_RULE = 'gitops/certificate-expired';
const ACME_ISSUER_RULE = 'gitops/acme-issuer';
const ACME_EMAIL_RULE = 'gitops/acme-email';
const ACME_EMAIL_EXPIRED_RULE = 'gitops/acme-email-expired';
const ACME_SOLVER_RULE = 'gitops/acme-solver';

const LETS_ENCRYPT_PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory';
const LETS_ENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

const CERT_MANAGER_ISSUER_ANNOTATION = 'cert-manager.io/issuer';
const CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION = 'cert-manager.io/cluster-issuer';
const HTTP01_INGRESS_CLASS_ANNOTATION = 'acme.cert-manager.io/http01-ingress-class';

const ACME_CHALLENGE_PATH = '/.well-known/acme-challenge/';
const STELLAR_TOML_PATH = '/.well-known/stellar.toml';

type Obj = Record<string, unknown>;

interface Resource {
  kind: 'Ingress' | 'Certificate' | 'ClusterIssuer' | 'Issuer';
  apiVersion: string;
  name: string;
  namespace: string;
  metadata: Obj;
  spec: Obj;
  status: Obj;
  annotations: Record<string, string>;
  line: number;
}

interface AuditOptions {
  /** Severity overrides, keyed by rule id, matching the rest of the linter. */
  rules?: RuleOverrides;
  /** Treat warnings as errors when computing {@link LintResult.ok}. */
  strict?: boolean;
  /** Injectable clock so certificate-expiry tests do not depend on today. */
  now?: Date;
}

type Emit = (
  rule: string,
  fallback: Severity,
  finding: Omit<Diagnostic, 'rule' | 'severity' | 'category'>,
) => void;

const SEVERITY_RANK: Record<Severity, number> = { error: 0, warning: 1, info: 2 };

export class K8sIngressCertManagerAuditor {
  audit(source: string, options: AuditOptions = {}): LintResult {
    const parsed = parseYamlDocuments(source);
    const diagnostics: Diagnostic[] = [];
    const emit = makeEmitter(diagnostics, options.rules);

    for (const error of parsed.errors) {
      emit(PARSE_RULE, 'error', {
        message: `Invalid Kubernetes YAML: ${error.message}`,
        position: { line: error.line, column: error.column },
        suggestion: 'Fix the YAML syntax; the affected objects were only partially audited.',
      });
    }

    const resources: Resource[] = [];
    for (const document of parsed.documents) {
      collectResources(document.value, document.line, resources, emit);
    }

    validateIssuers(resources, emit);
    validateCertificates(resources, emit, options);
    validateIngresses(resources, emit);

    return finish(diagnostics, options);
  }
}

/** Convenience wrapper for callers that do not need the class. */
export function auditK8sManifests(source: string, options: AuditOptions = {}): LintResult {
  return new K8sIngressCertManagerAuditor().audit(source, options);
}

function makeEmitter(diagnostics: Diagnostic[], rules: RuleOverrides | undefined): Emit {
  return (rule, fallback, finding) => {
    const override = rules?.[rule];
    if (override === 'off') return;

    const severity =
      override === 'error' || override === 'warning' || override === 'info' ? override : fallback;

    diagnostics.push({ rule, severity, category: CATEGORY, ...finding });
  };
}

function finish(diagnostics: Diagnostic[], options: AuditOptions): LintResult {
  const sorted = [...diagnostics].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    const lineA = a.position?.line ?? Number.MAX_SAFE_INTEGER;
    const lineB = b.position?.line ?? Number.MAX_SAFE_INTEGER;
    if (lineA !== lineB) return lineA - lineB;
    const colA = a.position?.column ?? 0;
    const colB = b.position?.column ?? 0;
    if (colA !== colB) return colA - colB;
    return a.rule.localeCompare(b.rule);
  });

  const counts: Record<Severity, number> = { error: 0, warning: 0, info: 0 };
  for (const diagnostic of sorted) counts[diagnostic.severity]++;

  const ok = options.strict ? counts.error === 0 && counts.warning === 0 : counts.error === 0;
  return { diagnostics: sorted, ok, counts };
}

function collectResources(value: unknown, line: number, resources: Resource[], emit: Emit): void {
  if (value === null || value === undefined) return;

  if (Array.isArray(value)) {
    for (const entry of value) collectResources(entry, line, resources, emit);
    return;
  }

  if (!isObject(value)) {
    emit(SCHEMA_RULE, 'error', {
      message: 'Kubernetes document is not a mapping',
      position: { line, column: 1 },
      suggestion: 'Each YAML document should describe one Kubernetes object.',
    });
    return;
  }

  const kind = stringOf(value.kind);
  if (kind === 'List') {
    if (Array.isArray(value.items)) {
      for (const entry of value.items) collectResources(entry, line, resources, emit);
    } else {
      emit(SCHEMA_RULE, 'error', {
        message: 'Kubernetes List is missing an items array',
        position: { line, column: 1 },
        suggestion: 'Use `items:` with a sequence of Kubernetes objects.',
      });
    }
    return;
  }

  if (!kind) {
    emit(SCHEMA_RULE, 'error', {
      message: 'Kubernetes document is missing kind',
      position: { line, column: 1 },
      suggestion: 'Set `kind` to Ingress, Certificate, Issuer, or ClusterIssuer.',
    });
    return;
  }

  if (!isAuditedKind(kind)) return;

  const apiVersion = stringOf(value.apiVersion);
  if (!apiVersion) {
    emit(SCHEMA_RULE, 'error', {
      message: `${kind} is missing apiVersion`,
      position: { line, column: 1 },
      suggestion: 'Add the apiVersion for the object, e.g. networking.k8s.io/v1.',
    });
  }

  const metadata = objectOf(value.metadata) ?? {};
  const name = stringOf(metadata.name) ?? '';
  const namespace = stringOf(metadata.namespace) ?? 'default';
  const annotations = readAnnotations(metadata.annotations);

  if (!name) {
    emit(SCHEMA_RULE, 'error', {
      message: `${kind} is missing metadata.name`,
      position: { line, column: 1 },
      suggestion: 'Give the object a stable name so references can be resolved.',
    });
  }

  resources.push({
    kind,
    apiVersion: apiVersion ?? '',
    name,
    namespace,
    metadata,
    spec: objectOf(value.spec) ?? {},
    status: objectOf(value.status) ?? {},
    annotations,
    line,
  });
}

function isAuditedKind(kind: string): kind is Resource['kind'] {
  return (
    kind === 'Ingress' || kind === 'Certificate' || kind === 'ClusterIssuer' || kind === 'Issuer'
  );
}

function validateIssuers(resources: Resource[], emit: Emit): void {
  for (const resource of resources) {
    if (resource.kind !== 'ClusterIssuer' && resource.kind !== 'Issuer') continue;

    const acme = objectOf(resource.spec.acme);
    if (!acme) continue; // CA, self-signed, and Vault issuers have no ACME fields.

    const path = resourcePath(resource);

    const server = stringOf(acme.server);
    if (!server) {
      emit(ACME_ISSUER_RULE, 'error', {
        message: `${path} does not set spec.acme.server`,
        path: `${path}.spec.acme.server`,
        suggestion: `Use ${LETS_ENCRYPT_PRODUCTION} for production certificates.`,
      });
    } else if (!isHttpsUrl(server)) {
      emit(ACME_ISSUER_RULE, 'error', {
        message: `${path} ACME server is not an https URL: ${server}`,
        path: `${path}.spec.acme.server`,
        suggestion: `Use ${LETS_ENCRYPT_PRODUCTION} or the Let's Encrypt staging directory.`,
      });
    } else if (/acme-v01\.api\.letsencrypt\.org/i.test(server)) {
      emit(ACME_ISSUER_RULE, 'warning', {
        message: `${path} uses the retired Let's Encrypt ACME v1 endpoint`,
        path: `${path}.spec.acme.server`,
        suggestion: `Move to ${LETS_ENCRYPT_PRODUCTION}; ACME v1 no longer issues certificates.`,
      });
    } else if (
      /letsencrypt\.org/i.test(server) &&
      server !== LETS_ENCRYPT_PRODUCTION &&
      server !== LETS_ENCRYPT_STAGING
    ) {
      emit(ACME_ISSUER_RULE, 'warning', {
        message: `${path} uses an unrecognised Let's Encrypt directory: ${server}`,
        path: `${path}.spec.acme.server`,
        suggestion: `Use ${LETS_ENCRYPT_PRODUCTION} or ${LETS_ENCRYPT_STAGING}.`,
      });
    }

    const email = stringOf(acme.email);
    if (!email) {
      emit(ACME_EMAIL_RULE, 'error', {
        message: `${path} does not set spec.acme.email, so expiry notices have nowhere to go`,
        path: `${path}.spec.acme.email`,
        suggestion: 'Set a monitored team mailbox for ACME account and certificate expiry notices.',
      });
    } else if (!isEmail(email)) {
      emit(ACME_EMAIL_RULE, 'error', {
        message: `${path} ACME account email is not a valid address: ${email}`,
        path: `${path}.spec.acme.email`,
        suggestion: 'Use a real, monitored mailbox such as devops@example.com.',
      });
    } else if (isExpiredOrPlaceholderEmail(email)) {
      emit(ACME_EMAIL_EXPIRED_RULE, 'warning', {
        message: `${path} ACME account email uses a placeholder or expired address: ${email}`,
        path: `${path}.spec.acme.email`,
        suggestion:
          'Point spec.acme.email at a monitored team mailbox that will receive renewal notices.',
      });
    }

    const privateKeySecretRef = objectOf(acme.privateKeySecretRef);
    if (!privateKeySecretRef || !stringOf(privateKeySecretRef.name)) {
      emit(ACME_ISSUER_RULE, 'error', {
        message: `${path} does not set spec.acme.privateKeySecretRef.name`,
        path: `${path}.spec.acme.privateKeySecretRef.name`,
        suggestion: 'Give the ACME account private key a stable Secret name.',
      });
    }

    const solvers = Array.isArray(acme.solvers) ? acme.solvers : [];
    if (solvers.length === 0) {
      emit(ACME_SOLVER_RULE, 'error', {
        message: `${path} declares no ACME solvers, so no challenge can be completed`,
        path: `${path}.spec.acme.solvers`,
        suggestion:
          'Add an http01 ingress solver (or a dns01 solver) so cert-manager can prove domain control.',
      });
    } else if (!solvers.some(isUsableSolver)) {
      emit(ACME_SOLVER_RULE, 'error', {
        message: `${path} has no http01 or dns01 solver`,
        path: `${path}.spec.acme.solvers`,
        suggestion: 'Use an http01 ingress solver or a dns01 provider solver.',
      });
    }
  }
}

function isUsableSolver(value: unknown): boolean {
  if (!isObject(value)) return false;
  return objectOf(value.http01) !== undefined || objectOf(value.dns01) !== undefined;
}

function validateCertificates(resources: Resource[], emit: Emit, options: AuditOptions): void {
  const issuers = resources.filter(
    (resource) => resource.kind === 'ClusterIssuer' || resource.kind === 'Issuer',
  );
  const now = options.now ?? new Date();

  for (const resource of resources) {
    if (resource.kind !== 'Certificate') continue;

    const path = resourcePath(resource);
    const secretName = stringOf(resource.spec.secretName);
    if (!secretName) {
      emit(CERTIFICATE_SECRET_RULE, 'error', {
        message: `${path} does not set spec.secretName`,
        path: `${path}.spec.secretName`,
        suggestion: 'Set the Secret name the Ingress TLS block expects, e.g. anchor-tls.',
      });
    }

    const issuerRef = objectOf(resource.spec.issuerRef);
    const issuerName = issuerRef ? stringOf(issuerRef.name) : undefined;
    const issuerKind = (issuerRef ? stringOf(issuerRef.kind) : undefined) ?? 'Issuer';

    if (!issuerRef || !issuerName) {
      emit(CERTIFICATE_ISSUER_RULE, 'error', {
        message: `${path} does not set spec.issuerRef.name`,
        path: `${path}.spec.issuerRef.name`,
        suggestion: 'Reference the Issuer or ClusterIssuer that should sign this certificate.',
      });
    } else if (issuerKind !== 'Issuer' && issuerKind !== 'ClusterIssuer') {
      emit(CERTIFICATE_ISSUER_RULE, 'error', {
        message: `${path} references unsupported issuer kind ${issuerKind}`,
        path: `${path}.spec.issuerRef.kind`,
        suggestion:
          'Use kind Issuer for a namespaced issuer or ClusterIssuer for a cluster issuer.',
      });
    } else {
      const match = issuers.find(
        (issuer) =>
          issuer.kind === issuerKind &&
          issuer.name === issuerName &&
          (issuerKind === 'ClusterIssuer' || issuer.namespace === resource.namespace),
      );
      if (!match) {
        emit(CERTIFICATE_ISSUER_RULE, 'warning', {
          message: `${path} references ${issuerKind} ${issuerName}, which is not in the audited manifests`,
          path: `${path}.spec.issuerRef.name`,
          suggestion:
            'Include the issuer manifest in the audit path, or confirm the reference is intentional.',
        });
      }
    }

    const dnsNames = stringArrayOf(resource.spec.dnsNames);
    const commonName = stringOf(resource.spec.commonName);
    if (dnsNames.length === 0 && !commonName) {
      emit(CERTIFICATE_DNS_RULE, 'error', {
        message: `${path} declares neither spec.dnsNames nor spec.commonName`,
        path: `${path}.spec.dnsNames`,
        suggestion: 'List every hostname the certificate must cover, e.g. anchor.example.com.',
      });
    }

    const notAfter = stringOf(resource.status.notAfter);
    if (notAfter) {
      const expiry = new Date(notAfter);
      if (!Number.isNaN(expiry.getTime()) && expiry.getTime() < now.getTime()) {
        emit(CERTIFICATE_EXPIRED_RULE, 'warning', {
          message: `${path} expired on ${notAfter}`,
          path: `${path}.status.notAfter`,
          suggestion:
            'Renew the certificate and check why cert-manager did not renew it before expiry.',
        });
      }
    }
  }
}

function validateIngresses(resources: Resource[], emit: Emit): void {
  const certificates = resources.filter((resource) => resource.kind === 'Certificate');
  const issuers = resources.filter(
    (resource) => resource.kind === 'ClusterIssuer' || resource.kind === 'Issuer',
  );

  for (const resource of resources) {
    if (resource.kind !== 'Ingress') continue;

    const path = resourcePath(resource);
    const annotations = resource.annotations;

    const clusterIssuer = annotations[CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION];
    const namespacedIssuer = annotations[CERT_MANAGER_ISSUER_ANNOTATION];
    const hasCertManagerAnnotation = clusterIssuer !== undefined || namespacedIssuer !== undefined;

    if (clusterIssuer !== undefined && namespacedIssuer !== undefined) {
      emit(INGRESS_ANNOTATION_RULE, 'error', {
        message: `${path} sets both cert-manager.io/cluster-issuer and cert-manager.io/issuer`,
        path: `${path}.metadata.annotations`,
        suggestion: 'Keep one issuer annotation so cert-manager knows which issuer to use.',
      });
    }

    const referencedIssuer = clusterIssuer ?? namespacedIssuer;
    const referencedKind = clusterIssuer !== undefined ? 'ClusterIssuer' : 'Issuer';
    if (referencedIssuer !== undefined) {
      if (referencedIssuer.trim() === '') {
        emit(INGRESS_ANNOTATION_RULE, 'error', {
          message: `${path} has an empty ${referencedKind === 'ClusterIssuer' ? CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION : CERT_MANAGER_ISSUER_ANNOTATION} annotation`,
          path: `${path}.metadata.annotations`,
          suggestion:
            'Set the annotation to the name of the issuer that should sign the certificate.',
        });
      } else {
        const match = issuers.find(
          (issuer) =>
            issuer.kind === referencedKind &&
            issuer.name === referencedIssuer &&
            (referencedKind === 'ClusterIssuer' || issuer.namespace === resource.namespace),
        );
        if (!match) {
          emit(INGRESS_ANNOTATION_RULE, 'error', {
            message: `${path} references ${referencedKind} ${referencedIssuer}, which is not in the audited manifests`,
            path: `${path}.metadata.annotations.${referencedKind === 'ClusterIssuer' ? CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION : CERT_MANAGER_ISSUER_ANNOTATION}`,
            suggestion:
              'Point the annotation at a declared issuer, or include that issuer in the audit path.',
          });
        }
      }
    }

    const tlsEntries = Array.isArray(resource.spec.tls) ? resource.spec.tls : [];
    if (resource.spec.tls !== undefined && !Array.isArray(resource.spec.tls)) {
      emit(SCHEMA_RULE, 'error', {
        message: `${path}.spec.tls must be a sequence`,
        path: `${path}.spec.tls`,
        suggestion: 'Use a list of tls entries, each with hosts and a secretName.',
      });
    }

    const tlsHosts = new Set<string>();
    for (const [index, entry] of tlsEntries.entries()) {
      if (!isObject(entry)) {
        emit(SCHEMA_RULE, 'error', {
          message: `${path}.spec.tls[${index}] is not a mapping`,
          path: `${path}.spec.tls[${index}]`,
          suggestion: 'Each tls entry needs a secretName and a hosts list.',
        });
        continue;
      }

      const secretName = stringOf(entry.secretName);
      const hosts = stringArrayOf(entry.hosts);
      for (const host of hosts) tlsHosts.add(host);

      if (!secretName) {
        emit(INGRESS_TLS_SECRET_RULE, 'error', {
          message: `${path}.spec.tls[${index}] does not set secretName`,
          path: `${path}.spec.tls[${index}].secretName`,
          suggestion: 'Set the TLS Secret name so the Ingress and Certificate agree.',
        });
        continue;
      }

      const matches = certificates.filter(
        (certificate) =>
          certificate.namespace === resource.namespace &&
          stringOf(certificate.spec.secretName) === secretName,
      );

      if (matches.length === 0) {
        emit(INGRESS_TLS_SECRET_RULE, hasCertManagerAnnotation ? 'warning' : 'error', {
          message: hasCertManagerAnnotation
            ? `${path} references TLS Secret ${secretName}, but no Certificate declares it`
            : `${path} references TLS Secret ${secretName}, but no Certificate declares it and no cert-manager issuer annotation is set`,
          path: `${path}.spec.tls[${index}].secretName`,
          suggestion:
            'Add a Certificate with the same spec.secretName, or let cert-manager ingress-shim create it and include the generated object in review.',
        });
        continue;
      }

      const certificate = matches[0];
      if (!certificate) continue;
      const certificatePath = resourcePath(certificate);
      const covered = certificateNames(certificate);
      for (const host of hosts) {
        if (!covered.some((name) => hostnameMatches(host, name))) {
          emit(INGRESS_TLS_SECRET_RULE, 'error', {
            message: `${path} TLS host ${host} is not listed on ${certificatePath}`,
            path: `${path}.spec.tls[${index}].hosts`,
            suggestion: `Add ${host} to the Certificate spec.dnsNames so the certificate covers it.`,
          });
        }
      }
    }

    const managed = tlsEntries.length > 0 || hasCertManagerAnnotation;
    if (!managed) continue;

    const acmeRouteRequired = requiresHttp01Route(resource, certificates, issuers);
    const hasDefaultBackend = objectOf(resource.spec.defaultBackend) !== undefined;
    const rules = Array.isArray(resource.spec.rules) ? resource.spec.rules : [];
    const ruleHosts = new Set<string>();
    for (const rule of rules) {
      if (!isObject(rule)) continue;
      const host = stringOf(rule.host);
      if (host) ruleHosts.add(host);
    }

    const hosts = new Set<string>([...tlsHosts, ...ruleHosts]);
    if (hosts.size === 0) hosts.add('');

    for (const host of hosts) {
      const paths = pathsForHost(rules, host);
      const acmeCovered =
        hasDefaultBackend ||
        paths.some((entry) => routeCovers(entry.path, entry.pathType, ACME_CHALLENGE_PATH));
      const stellarCovered =
        hasDefaultBackend ||
        paths.some((entry) => routeCovers(entry.path, entry.pathType, STELLAR_TOML_PATH));

      if (acmeRouteRequired && !acmeCovered) {
        emit(INGRESS_ACME_ROUTE_RULE, 'error', {
          message: `${path} has no route for ${ACME_CHALLENGE_PATH}${host ? ` on ${host}` : ''}`,
          path: `${path}.spec.rules`,
          suggestion:
            'Route /.well-known/acme-challenge/ to the cert-manager HTTP-01 solver (a prefix path of / covers it).',
        });
      }

      if (!stellarCovered) {
        emit(INGRESS_STELLAR_ROUTE_RULE, 'error', {
          message: `${path} has no route for ${STELLAR_TOML_PATH}${host ? ` on ${host}` : ''}`,
          path: `${path}.spec.rules`,
          suggestion:
            'Route /.well-known/stellar.toml (a prefix path of / covers it) so wallets can read the info file.',
        });
      } else {
        const problem = corsProblem(annotations);
        if (problem) {
          emit(INGRESS_CORS_RULE, 'error', {
            message: `${path} serves ${STELLAR_TOML_PATH} without usable CORS annotations (${problem})`,
            path: `${path}.metadata.annotations`,
            suggestion:
              'Enable CORS for the anchor host, e.g. nginx.ingress.kubernetes.io/enable-cors: "true" with cors-allow-origin: "*".',
          });
        }
      }
    }

    checkHttp01Annotation(resource, annotations, emit);
  }
}

/**
 * HTTP-01 needs a public challenge route; a DNS-01-only issuer does not. When
 * the referenced issuer cannot be resolved, err on the side of checking.
 */
function requiresHttp01Route(
  ingress: Resource,
  certificates: Resource[],
  issuers: Resource[],
): boolean {
  const clusterIssuer = ingress.annotations[CERT_MANAGER_CLUSTER_ISSUER_ANNOTATION];
  const namespacedIssuer = ingress.annotations[CERT_MANAGER_ISSUER_ANNOTATION];

  let issuer: Resource | undefined;
  if (clusterIssuer !== undefined) {
    issuer = issuers.find(
      (candidate) => candidate.kind === 'ClusterIssuer' && candidate.name === clusterIssuer,
    );
  } else if (namespacedIssuer !== undefined) {
    issuer = issuers.find(
      (candidate) =>
        candidate.kind === 'Issuer' &&
        candidate.name === namespacedIssuer &&
        candidate.namespace === ingress.namespace,
    );
  } else {
    const tlsSecrets = new Set(
      (Array.isArray(ingress.spec.tls) ? ingress.spec.tls : [])
        .map((entry) => (isObject(entry) ? stringOf(entry.secretName) : undefined))
        .filter((name): name is string => name !== undefined),
    );
    const certificate = certificates.find(
      (candidate) =>
        candidate.namespace === ingress.namespace &&
        tlsSecrets.has(stringOf(candidate.spec.secretName) ?? ''),
    );
    const issuerRef = certificate ? objectOf(certificate.spec.issuerRef) : undefined;
    const issuerName = issuerRef ? stringOf(issuerRef.name) : undefined;
    const issuerKind = (issuerRef ? stringOf(issuerRef.kind) : undefined) ?? 'Issuer';
    if (issuerName) {
      issuer = issuers.find(
        (candidate) =>
          candidate.kind === issuerKind &&
          candidate.name === issuerName &&
          (issuerKind === 'ClusterIssuer' || candidate.namespace === ingress.namespace),
      );
    }
  }

  if (!issuer) return true;
  const acme = objectOf(issuer.spec.acme);
  if (!acme) return true;

  const solvers = Array.isArray(acme.solvers) ? acme.solvers : [];
  const hasHttp01 = solvers.some(
    (solver) => isObject(solver) && objectOf(solver.http01) !== undefined,
  );
  const hasDns01 = solvers.some(
    (solver) => isObject(solver) && objectOf(solver.dns01) !== undefined,
  );

  return !(hasDns01 && !hasHttp01);
}

function checkHttp01Annotation(
  resource: Resource,
  annotations: Record<string, string>,
  emit: Emit,
): void {
  const http01Class = annotations[HTTP01_INGRESS_CLASS_ANNOTATION];
  if (http01Class === undefined) return;

  const ingressClass = stringOf(resource.spec.ingressClassName);
  if (http01Class.trim() === '') {
    emit(INGRESS_ANNOTATION_RULE, 'error', {
      message: `${resourcePath(resource)} has an empty ${HTTP01_INGRESS_CLASS_ANNOTATION} annotation`,
      path: `${resourcePath(resource)}.metadata.annotations.${HTTP01_INGRESS_CLASS_ANNOTATION}`,
      suggestion: 'Set the ingress class cert-manager should use for the HTTP-01 solver.',
    });
  } else if (ingressClass && http01Class !== ingressClass) {
    emit(INGRESS_ANNOTATION_RULE, 'warning', {
      message: `${resourcePath(resource)} HTTP-01 ingress class "${http01Class}" differs from spec.ingressClassName "${ingressClass}"`,
      path: `${resourcePath(resource)}.metadata.annotations.${HTTP01_INGRESS_CLASS_ANNOTATION}`,
      suggestion:
        'Use the same ingress class for the anchor Ingress and the cert-manager HTTP-01 solver.',
    });
  }
}

interface IngressPath {
  path: string;
  pathType: string;
}

function pathsForHost(rules: unknown[], host: string): IngressPath[] {
  const result: IngressPath[] = [];

  for (const rule of rules) {
    if (!isObject(rule)) continue;
    const ruleHost = stringOf(rule.host) ?? '';
    if (ruleHost !== '' && ruleHost !== host) continue;

    const http = objectOf(rule.http);
    const paths = http && Array.isArray(http.paths) ? http.paths : [];
    for (const entry of paths) {
      if (!isObject(entry)) continue;
      const path = stringOf(entry.path);
      if (!path) continue;
      result.push({ path, pathType: stringOf(entry.pathType) ?? 'Prefix' });
    }
  }

  return result;
}

function routeCovers(routePath: string, pathType: string, target: string): boolean {
  const route = normalizePath(routePath);
  const wanted = normalizePath(target);

  if (!route.startsWith('/')) return false;

  if (pathType === 'Exact') return route === wanted;
  if (route === '/') return true;
  if (route === wanted) return true;
  if (wanted.startsWith(route.endsWith('/') ? route : `${route}/`)) return true;

  // ImplementationSpecific paths are often regexes. Only accept the ones that
  // clearly name the route they are meant to serve, rather than guessing.
  if (pathType === 'ImplementationSpecific') {
    if (target === ACME_CHALLENGE_PATH && /acme-challenge/.test(routePath)) return true;
    if (target === STELLAR_TOML_PATH && /stellar\.toml/.test(routePath)) return true;
  }

  return false;
}

function normalizePath(value: string): string {
  const withoutQuery = value.split(/[?#]/, 1)[0] ?? value;
  if (withoutQuery === '') return '/';
  const prefixed = withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
  return prefixed.length > 1 ? prefixed.replace(/\/+$/, '') : prefixed;
}

function corsProblem(annotations: Record<string, string>): string | undefined {
  const nginxEnabled = annotations['nginx.ingress.kubernetes.io/enable-cors'];
  const nginxOrigin = annotations['nginx.ingress.kubernetes.io/cors-allow-origin'];

  if (nginxEnabled !== undefined) {
    if (!isTruthy(nginxEnabled)) return `enable-cors is "${nginxEnabled}"`;
    if (nginxOrigin !== undefined && nginxOrigin.trim() !== '*') {
      return `cors-allow-origin is "${nginxOrigin}" instead of "*"`;
    }
    return undefined;
  }

  if (nginxOrigin !== undefined) {
    return nginxOrigin.trim() === '*'
      ? undefined
      : `cors-allow-origin is "${nginxOrigin}" instead of "*"`;
  }

  const traefik = annotations['traefik.ingress.kubernetes.io/router.middlewares'];
  if (traefik && /(?:^|[,@\s-])cors(?:[@,;\s-]|$)/i.test(traefik)) return undefined;

  if (isTruthy(annotations['haproxy-ingress.github.io/cors-enable'] ?? '')) return undefined;

  for (const [key, value] of Object.entries(annotations)) {
    if (/cors/i.test(key) && !/^(?:false|off|0|no|disabled)$/i.test(value.trim())) return undefined;
  }

  return 'no CORS annotation';
}

function certificateNames(certificate: Resource): string[] {
  const names = stringArrayOf(certificate.spec.dnsNames);
  const commonName = stringOf(certificate.spec.commonName);
  if (commonName && !names.includes(commonName)) names.push(commonName);
  return names;
}

/** RFC 6125-style wildcard matching, limited to a single leftmost label. */
function hostnameMatches(host: string, pattern: string): boolean {
  const normalisedHost = host.toLowerCase().replace(/\.$/, '');
  const normalisedPattern = pattern.toLowerCase().replace(/\.$/, '');
  if (normalisedHost === normalisedPattern) return true;
  if (!normalisedPattern.startsWith('*.')) return false;

  const suffix = normalisedPattern.slice(1);
  return normalisedHost.endsWith(suffix) && !normalisedHost.slice(0, -suffix.length).includes('.');
}

function isExpiredOrPlaceholderEmail(email: string): boolean {
  const [local = '', domain = ''] = email.toLowerCase().split('@');
  const placeholderDomains = new Set(['example', 'invalid', 'localhost', 'test']);

  if (placeholderDomains.has(domain)) return true;
  if (/\.(?:invalid|example|test|localhost)$/.test(domain)) return true;

  // Teams sometimes leave a dated or retired mailbox behind after a migration.
  return /(?:^|[._-])(?:expired|retired|deprecated|old)(?:[._-]|$)/i.test(local);
}

function readAnnotations(value: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  if (!isObject(value)) return result;

  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string') result[key] = entry;
    else if (typeof entry === 'number' || typeof entry === 'boolean') result[key] = String(entry);
  }
  return result;
}

function resourcePath(resource: Resource): string {
  if (resource.kind === 'ClusterIssuer') return `ClusterIssuer/${resource.name}`;
  return `${resource.kind}/${resource.namespace}/${resource.name}`;
}

function isObject(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function objectOf(value: unknown): Obj | undefined {
  return isObject(value) ? value : undefined;
}

function stringOf(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function stringArrayOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string');
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

function isEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(value);
}

function isTruthy(value: string): boolean {
  return /^(?:true|yes|on|1)$/i.test(value.trim());
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const gitopsRules: Rule[] = [
  {
    id: PARSE_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Kubernetes manifests must be valid YAML',
    run() {},
  },
  {
    id: SCHEMA_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Kubernetes objects must have the schema fields the auditor needs',
    run() {},
  },
  {
    id: INGRESS_ACME_ROUTE_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Ingress must route /.well-known/acme-challenge/ for HTTP-01 renewal',
    run() {},
  },
  {
    id: INGRESS_STELLAR_ROUTE_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Ingress must route /.well-known/stellar.toml',
    run() {},
  },
  {
    id: INGRESS_TLS_SECRET_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Ingress TLS secrets must match a Certificate declaration',
    run() {},
  },
  {
    id: INGRESS_ANNOTATION_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Ingress cert-manager annotations must reference a declared issuer',
    run() {},
  },
  {
    id: INGRESS_CORS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Ingress serving stellar.toml must enable CORS',
    run() {},
  },
  {
    id: CERTIFICATE_SECRET_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Certificate must declare the Secret its TLS key pair is stored in',
    run() {},
  },
  {
    id: CERTIFICATE_ISSUER_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Certificate must reference an Issuer or ClusterIssuer',
    run() {},
  },
  {
    id: CERTIFICATE_DNS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Certificate must declare the DNS names it covers',
    run() {},
  },
  {
    id: CERTIFICATE_EXPIRED_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'Certificate must not already be expired',
    run() {},
  },
  {
    id: ACME_ISSUER_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'ACME issuer must have a valid server and account key secret',
    run() {},
  },
  {
    id: ACME_EMAIL_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'ACME issuer must have a valid account email',
    run() {},
  },
  {
    id: ACME_EMAIL_EXPIRED_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'ACME account email must not be a placeholder or retired mailbox',
    run() {},
  },
  {
    id: ACME_SOLVER_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'ACME issuer must declare a usable http01 or dns01 solver',
    run() {},
  },
];
