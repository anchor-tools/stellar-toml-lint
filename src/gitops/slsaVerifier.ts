/**
 * Build artifact provenance and SLSA compliance verifier.
 *
 * A release workflow publishes an npm package, a binary, or a Docker image.
 * SLSA asks three questions of the paperwork that accompanies it: does a
 * provenance document exist, was it signed by the builder it names, and does it
 * describe *this* artifact built from *this* commit by a trusted builder?
 *
 * The verifier reads in-toto statements, DSSE envelopes, and Sigstore bundles
 * (including the `.intoto.jsonl` files produced by
 * `actions/attest-build-provenance`), checks the DSSE signature over the exact
 * payload with the embedded X.509 certificate or a caller-pinned public key,
 * compares the artifact digest against the signed subject, and grades the
 * result against SLSA Build levels 1–3.
 *
 * Trust is anchored offline. A bundle's embedded certificate proves possession
 * of a key, not that Sigstore's Fulcio issued it, so pass
 * {@link SlsaVerificationOptions.trustedPublicKeys} or
 * `trustedCertificateSha256` (from your `cosign verify-attestation` policy) to
 * make the signer accountable. Without a pinned root the report says the
 * signature cryptographically verifies but the signer is untrusted, which caps
 * the level at 2 instead of silently claiming level 3.
 */

import { X509Certificate, createHash, createPublicKey, verify as verifyCrypto } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

export type SlsaLevel = 0 | 1 | 2 | 3;
export type AttestationFormat = 'dsse-envelope' | 'sigstore-bundle' | 'in-toto-statement';
export type SlsaSeverity = 'error' | 'warning' | 'info';

export type SlsaFindingCode =
  | 'provenance/parse-error'
  | 'provenance/missing'
  | 'provenance/predicate-unrecognised'
  | 'provenance/subject-missing'
  | 'provenance/digest-mismatch'
  | 'provenance/signature-missing'
  | 'provenance/signature-invalid'
  | 'provenance/verification-material-missing'
  | 'provenance/certificate-expired'
  | 'provenance/untrusted-signer'
  | 'provenance/trust-root-unconfigured'
  | 'provenance/builder-mismatch'
  | 'provenance/source-mismatch'
  | 'provenance/commit-mismatch'
  | 'provenance/trigger-mismatch'
  | 'provenance/untrusted-trigger'
  | 'provenance/level-below-required';

export interface SlsaFinding {
  code: SlsaFindingCode;
  severity: SlsaSeverity;
  message: string;
  recommendation: string;
  /** Statement field that triggered the finding, e.g. `predicate.builder.id`. */
  field?: string;
}

export interface DsseSignature {
  keyid?: string;
  sig: string;
}

export interface DsseEnvelope {
  payloadType: string;
  payload: string;
  signatures: DsseSignature[];
}

export interface SigstoreBundle {
  mediaType?: string;
  verificationMaterial?: {
    x509CertificateChain?: { certificates?: { rawBytes?: string }[] };
    publicKey?: { hint?: string; pem?: string; rawBytes?: string };
    tlogEntries?: unknown[];
  };
  messageSignature?: {
    messageDigest?: { algorithm?: string; digest?: string };
    signature?: string;
  };
  dsseEnvelope?: DsseEnvelope;
}

export interface ProvenanceSubject {
  name?: string;
  digest: Record<string, string>;
}

export interface ProvenanceMaterial {
  uri: string;
  digest?: Record<string, string>;
}

export interface NormalizedProvenance {
  predicateType: string;
  buildType: string;
  builderId: string;
  sourceRepository?: string;
  sourceCommit?: string;
  workflowTrigger?: string;
  workflowPath?: string;
  invocationId?: string;
  materials: ProvenanceMaterial[];
}

export interface SignatureVerification {
  method: 'dsse' | 'none';
  verified: boolean;
  /** True only when the signer matches a caller-pinned key or certificate. */
  trusted: boolean;
  keyId?: string;
  certificateSubject?: string;
  certificateIssuer?: string;
  /** SHA-256 fingerprint of the signing certificate, hex encoded. */
  certificateSha256?: string;
  certificateValid?: boolean;
  error?: string;
}

export interface SlsaVerificationOptions {
  /** e.g. `https://github.com/actions/runner/github-hosted` */
  expectedBuilderId?: string;
  /** `https://github.com/org/repo`, `org/repo`, or `git+…` are all accepted. */
  expectedSourceRepository?: string;
  expectedCommitSha?: string;
  expectedWorkflowTrigger?: string;
  /** PEM-encoded public keys trusted to sign provenance. */
  trustedPublicKeys?: string[];
  /** Hex SHA-256 fingerprints of trusted signing certificates. */
  trustedCertificateSha256?: string[];
  /**
   * PEM-encoded root CA certificates (for example the Sigstore Fulcio root)
   * that a bundle's X.509 chain must terminate in.
   */
  trustedRootCertificates?: string[];
  /** Lowest acceptable SLSA level. Default 1 (provenance must exist). */
  requiredLevel?: SlsaLevel;
  /**
   * Name of the artifact, matched against `subject[].name`. Defaults to the
   * basename supplied by the CLI.
   */
  artifactName?: string;
}

export interface SlsaSecurityAttestation {
  slsaLevel: SlsaLevel;
  predicateType: string;
  builderId: string;
  sourceRepository?: string;
  sourceCommit?: string;
  workflowTrigger?: string;
  subjectDigests: Record<string, string>;
  artifactSha256: string;
  digestMatches: boolean;
  signatureVerified: boolean;
  signerTrusted: boolean;
  /** Machine-readable checks that backed the awarded level. */
  controls: string[];
}

export interface SlsaVerificationReport {
  ok: boolean;
  level: SlsaLevel;
  requiredLevel: SlsaLevel;
  format: AttestationFormat;
  artifact: { name?: string; sha256: string; size: number };
  signature: SignatureVerification;
  predicateType?: string;
  provenance?: NormalizedProvenance;
  subject: ProvenanceSubject[];
  findings: SlsaFinding[];
  attestation: SlsaSecurityAttestation;
}

export class SlsaProvenanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SlsaProvenanceError';
  }
}

const SLSA_PREDICATE = 'slsa.dev/provenance';
const TRUSTED_TRIGGERS = new Set([
  'push',
  'release',
  'workflow_dispatch',
  'schedule',
  'workflow_call',
]);

/** Builder identities recognized as hosted, reproducible build services. */
export const HOSTED_BUILDER_PATTERNS: readonly RegExp[] = [
  /github\.com\/actions\//i,
  /actions\.githubusercontent\.com/i,
  /slsa-framework/i,
  /cloudbuild/i,
  /buildkite/i,
  /gitlab\.com\/runner/i,
];

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function stringRecord(value: unknown): Record<string, string> {
  const record = asRecord(value);
  if (record === undefined) return {};
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry === 'string') out[key] = entry;
  }
  return out;
}

function hashSha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function normalizeArtifact(artifact: string | Uint8Array): Uint8Array {
  return typeof artifact === 'string' ? Buffer.from(artifact, 'utf8') : artifact;
}

function decodeBase64(value: string): Buffer {
  return Buffer.from(value, 'base64');
}

/**
 * DSSE Pre-Authentication Encoding. Signatures cover the serialized payload,
 * not merely the JSON object, so whitespace changes invalidate them — which is
 * exactly the property that stops a re-serialized payload from being swapped in.
 */
export function dssePae(payloadType: string, payload: Uint8Array): Buffer {
  const prefix = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `,
    'utf8',
  );
  return Buffer.concat([prefix, Buffer.from(payload)]);
}

function rawStatement(value: unknown): Record<string, unknown> | undefined {
  const record = asRecord(value);
  if (record === undefined) return undefined;
  const predicateType = asString(record.predicateType) ?? asString(record.predicate_type);
  const predicate = record.predicate ?? record.predicateType;
  if (predicateType === undefined && predicate === undefined) return undefined;
  return record;
}

export interface ParsedAttestation {
  format: AttestationFormat;
  statement: Record<string, unknown>;
  envelope?: DsseEnvelope;
  bundle?: SigstoreBundle;
}

/**
 * Parses a single attestation document: a DSSE envelope, a Sigstore bundle, or
 * a bare in-toto statement.
 */
export function parseAttestationDocument(value: unknown): ParsedAttestation | undefined {
  const record = asRecord(value);
  if (record === undefined) return undefined;

  const bundle =
    asRecord(record.dsseEnvelope) !== undefined ? (record as SigstoreBundle) : undefined;
  if (bundle?.dsseEnvelope !== undefined) {
    const statement = decodeEnvelopeStatement(bundle.dsseEnvelope);
    if (statement === undefined) return undefined;
    return { format: 'sigstore-bundle', statement, envelope: bundle.dsseEnvelope, bundle };
  }

  if (
    asString(record.payloadType) !== undefined &&
    asString(record.payload) !== undefined &&
    Array.isArray(record.signatures)
  ) {
    const envelope = record as unknown as DsseEnvelope;
    const statement = decodeEnvelopeStatement(envelope);
    if (statement === undefined) return undefined;
    return { format: 'dsse-envelope', statement, envelope };
  }

  // A messageSignature bundle signs an artifact but carries no in-toto
  // statement, so it cannot express SLSA provenance. It is rejected here rather
  // than being graded as if a predicate existed.
  const statement = rawStatement(record);
  if (statement === undefined) return undefined;
  return { format: 'in-toto-statement', statement };
}

function decodeEnvelopeStatement(envelope: DsseEnvelope): Record<string, unknown> | undefined {
  try {
    return rawStatement(JSON.parse(decodeBase64(envelope.payload).toString('utf8')));
  } catch {
    return undefined;
  }
}

/** Parses a `.intoto.jsonl` file (a JSON array, one JSON document per line, or a single object). */
export function parseProvenanceDocuments(text: string): ParsedAttestation[] {
  const trimmed = text.trim();
  if (trimmed === '') throw new SlsaProvenanceError('Provenance file is empty.');

  const documents: unknown[] = [];
  if (trimmed.startsWith('[')) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) documents.push(...parsed);
    } catch (error) {
      throw new SlsaProvenanceError(`Provenance file is not valid JSON: ${messageOf(error)}`);
    }
  } else {
    for (const line of trimmed.split('\n')) {
      const candidate = line.trim();
      if (candidate === '') continue;
      try {
        documents.push(JSON.parse(candidate) as unknown);
      } catch (error) {
        throw new SlsaProvenanceError(
          `Provenance line ${documents.length + 1} is not valid JSON: ${messageOf(error)}`,
        );
      }
    }
  }

  const parsed = documents
    .map((document) => parseAttestationDocument(document))
    .filter((entry): entry is ParsedAttestation => entry !== undefined);
  if (parsed.length === 0) {
    throw new SlsaProvenanceError(
      'No in-toto statement, DSSE envelope, or Sigstore bundle found in the provenance file.',
    );
  }
  return parsed;
}

export function predicateTypeOf(statement: Record<string, unknown>): string | undefined {
  return asString(statement.predicateType) ?? asString(statement.predicate_type);
}

export function subjectsOf(statement: Record<string, unknown>): ProvenanceSubject[] {
  const subjects = statement.subject;
  if (!Array.isArray(subjects)) return [];
  return subjects.flatMap((entry) => {
    const record = asRecord(entry);
    if (record === undefined) return [];
    const name = asString(record.name);
    return [{ ...(name !== undefined ? { name } : {}), digest: stringRecord(record.digest) }];
  });
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    const string = asString(value);
    if (string !== undefined) return string;
  }
  return undefined;
}

function repositoryFromUri(uri: string | undefined): string | undefined {
  if (uri === undefined) return undefined;
  let value = uri.trim().replace(/^git\+/, '');
  value = value.replace(/^git@([^:]+):/, '$1/');
  value = value.replace(/^https?:\/\//, '');
  value = value.replace(/\/+$/, '');
  value = value.replace(/\.git$/i, '');
  value = value.split('@')[0] as string;
  return value === '' ? undefined : value;
}

function materialFrom(entry: unknown): ProvenanceMaterial | undefined {
  const record = asRecord(entry);
  if (record === undefined) return undefined;
  const uri = asString(record.uri);
  if (uri === undefined) return undefined;
  return { uri, digest: stringRecord(record.digest) };
}

/**
 * Normalizes SLSA v0.2 (`builder`, `invocation`) and v1 (`buildDefinition`,
 * `runDetails`) predicates into one shape.
 */
export function normalizeProvenance(
  statement: Record<string, unknown>,
): NormalizedProvenance | undefined {
  const predicateType = predicateTypeOf(statement);
  const predicate = asRecord(statement.predicate);
  if (predicateType === undefined || predicate === undefined) return undefined;

  const buildDefinition = asRecord(predicate.buildDefinition);
  const runDetails = asRecord(predicate.runDetails);
  const builder = asRecord(predicate.builder);
  const invocation = asRecord(predicate.invocation);
  const configSource = asRecord(invocation?.configSource);
  const externalParameters = asRecord(buildDefinition?.externalParameters);
  const workflow = asRecord(externalParameters?.workflow);
  const internalParameters = asRecord(buildDefinition?.internalParameters);
  const github = asRecord(internalParameters?.github);
  const source = asRecord(externalParameters?.source);

  const resolvedDependencies = buildDefinition?.resolvedDependencies;
  const materialsRaw = Array.isArray(resolvedDependencies)
    ? resolvedDependencies
    : Array.isArray(predicate.materials)
      ? predicate.materials
      : [];
  const materials = materialsRaw
    .map((entry) => materialFrom(entry))
    .filter((entry): entry is ProvenanceMaterial => entry !== undefined);

  const sourceRepository =
    repositoryFromUri(firstString(workflow?.repository, source?.uri)) ??
    materials.map((material) => repositoryFromUri(material.uri)).find((uri) => uri !== undefined) ??
    repositoryFromUri(firstString(configSource?.uri));

  const gitMaterial = materials.find(
    (material) =>
      material.uri.startsWith('git+') ||
      material.digest?.gitCommit !== undefined ||
      material.digest?.sha1 !== undefined,
  );

  const sourceCommit = firstString(
    workflow?.commit,
    source?.digest !== undefined ? stringRecord(source.digest).gitCommit : undefined,
    gitMaterial?.digest?.gitCommit,
    gitMaterial?.digest?.sha1,
    configSource?.digest !== undefined
      ? firstString(
          stringRecord(configSource.digest).gitCommit,
          stringRecord(configSource.digest).sha1,
        )
      : undefined,
  );

  const workflowTrigger = firstString(
    github?.event_name,
    workflow?.event_name,
    asRecord(invocation?.parameters)?.event_name,
    asRecord(predicate.metadata)?.event_name,
  );

  return {
    predicateType,
    buildType: firstString(buildDefinition?.buildType, predicate.buildType) ?? 'unknown',
    builderId:
      firstString(
        runDetails?.builder !== undefined ? asRecord(runDetails.builder)?.id : undefined,
        builder?.id,
      ) ?? 'unknown',
    ...(sourceRepository !== undefined ? { sourceRepository } : {}),
    ...(sourceCommit !== undefined ? { sourceCommit } : {}),
    ...(workflowTrigger !== undefined ? { workflowTrigger } : {}),
    ...(firstString(workflow?.path, configSource?.entryPoint) !== undefined
      ? { workflowPath: firstString(workflow?.path, configSource?.entryPoint) as string }
      : {}),
    ...(firstString(
      runDetails?.metadata !== undefined ? asRecord(runDetails.metadata)?.invocationId : undefined,
      invocation?.metadata !== undefined
        ? asRecord(invocation.metadata)?.buildInvocationID
        : undefined,
    ) !== undefined
      ? {
          invocationId: firstString(
            runDetails?.metadata !== undefined
              ? asRecord(runDetails.metadata)?.invocationId
              : undefined,
            invocation?.metadata !== undefined
              ? asRecord(invocation.metadata)?.buildInvocationID
              : undefined,
          ) as string,
        }
      : {}),
    materials,
  };
}

// ── Signature verification ───────────────────────────────────────────────────

function verifyBytes(data: Uint8Array, signature: Uint8Array, key: KeyObject): boolean {
  try {
    if (key.asymmetricKeyType === 'ed25519') {
      return verifyCrypto(null, data, key, signature);
    }
    return verifyCrypto('sha256', data, key, signature);
  } catch {
    return false;
  }
}

function publicKeyFromPem(pem: string): KeyObject | undefined {
  try {
    return createPublicKey(pem);
  } catch {
    return undefined;
  }
}

function certificateFrom(value: string | undefined): X509Certificate | undefined {
  if (value === undefined) return undefined;
  try {
    if (value.includes('BEGIN CERTIFICATE')) return new X509Certificate(value);
    return new X509Certificate(decodeBase64(value));
  } catch {
    return undefined;
  }
}

function spkiPem(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'pem' }).toString();
}

function normaliseFingerprint(value: string): string {
  return value.replace(/:/g, '').toLowerCase();
}

function certificateValidNow(certificate: X509Certificate): boolean {
  const notBefore = Date.parse(certificate.validFrom);
  const notAfter = Date.parse(certificate.validTo);
  const now = Date.now();
  if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) return true;
  return now >= notBefore && now <= notAfter;
}

function certificateSignedBy(certificate: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

/**
 * Walks the bundle's certificate chain to see whether it terminates in one of
 * the caller-pinned roots. A self-signed leaf only matches a pinned root when
 * the exact certificate is pinned; otherwise it is untrusted.
 */
export function certificateChainTrusted(
  certificates: readonly X509Certificate[],
  roots: readonly X509Certificate[],
): boolean {
  let current: X509Certificate | undefined = certificates[0];
  const seen = new Set<string>();

  for (let depth = 0; depth < 10 && current !== undefined; depth++) {
    const certificate = current;
    const fingerprint = certificate.fingerprint256;
    if (seen.has(fingerprint)) return false;
    seen.add(fingerprint);

    if (
      roots.some(
        (root) => root.raw.equals(certificate.raw) || certificateSignedBy(certificate, root),
      )
    ) {
      return true;
    }

    current = certificates
      .slice(1)
      .find((candidate) => certificateSignedBy(certificate, candidate));
  }
  return false;
}

interface SignerMaterial {
  key?: KeyObject;
  certificate?: X509Certificate;
  certificates: X509Certificate[];
  error?: string;
}

function signerMaterialFor(
  envelope: DsseEnvelope | undefined,
  bundle: SigstoreBundle | undefined,
  options: SlsaVerificationOptions,
): SignerMaterial {
  const chain = (bundle?.verificationMaterial?.x509CertificateChain?.certificates ?? [])
    .map((entry) => certificateFrom(entry.rawBytes))
    .filter((certificate): certificate is X509Certificate => certificate !== undefined);
  const leaf = chain[0];
  if (leaf !== undefined) return { key: leaf.publicKey, certificate: leaf, certificates: chain };

  const bundlePem = bundle?.verificationMaterial?.publicKey?.pem;
  if (bundlePem !== undefined) {
    const key = publicKeyFromPem(bundlePem);
    if (key !== undefined) return { key, certificates: [] };
  }

  const keyId = envelope?.signatures.find((signature) => signature.keyid !== undefined)?.keyid;
  if (keyId !== undefined && keyId.includes('BEGIN PUBLIC KEY')) {
    const key = publicKeyFromPem(keyId);
    if (key !== undefined) return { key, certificates: [] };
  }

  for (const pem of options.trustedPublicKeys ?? []) {
    const key = publicKeyFromPem(pem);
    if (key !== undefined) return { key, certificates: [] };
  }

  return {
    certificates: [],
    error:
      'No verification material: the attestation has no X.509 chain, no embedded public key, and no --trusted-key was supplied.',
  };
}

/**
 * Verifies a DSSE envelope's signature and, when configured, that the signer is
 * one the caller pinned.
 */
export function verifyEnvelopeSignature(
  envelope: DsseEnvelope,
  bundle: SigstoreBundle | undefined,
  options: SlsaVerificationOptions = {},
): SignatureVerification {
  const material = signerMaterialFor(envelope, bundle, options);
  const signature = envelope.signatures[0];
  const keyId =
    signature?.keyid !== undefined && signature.keyid !== '' && !signature.keyid.includes('BEGIN')
      ? signature.keyid
      : undefined;

  if (signature === undefined) {
    return {
      method: 'dsse',
      verified: false,
      trusted: false,
      ...(keyId !== undefined ? { keyId } : {}),
      error: 'DSSE envelope has no signatures.',
    };
  }

  if (material.key === undefined) {
    return {
      method: 'dsse',
      verified: false,
      trusted: false,
      ...(keyId !== undefined ? { keyId } : {}),
      ...(material.error !== undefined ? { error: material.error } : {}),
    };
  }

  const payload = decodeBase64(envelope.payload);
  const signatureBytes = decodeBase64(signature.sig);
  const verified = verifyBytes(
    dssePae(envelope.payloadType, payload),
    signatureBytes,
    material.key,
  );
  return signatureReport(material, options, verified, keyId, 'dsse');
}

function signatureReport(
  material: SignerMaterial,
  options: SlsaVerificationOptions,
  verified: boolean,
  keyId: string | undefined,
  method: 'dsse',
): SignatureVerification {
  const certificate = material.certificate;
  const fingerprint =
    certificate === undefined
      ? undefined
      : createHash('sha256').update(certificate.raw).digest('hex');

  const pinnedKey =
    material.key !== undefined &&
    (options.trustedPublicKeys ?? []).some((pem) => {
      const candidate = publicKeyFromPem(pem);
      return candidate !== undefined && spkiPem(candidate) === spkiPem(material.key as KeyObject);
    });
  const pinnedCertificate =
    fingerprint !== undefined &&
    (options.trustedCertificateSha256 ?? []).some(
      (value) => normaliseFingerprint(value) === fingerprint,
    );
  const roots = (options.trustedRootCertificates ?? [])
    .map((pem) => certificateFrom(pem))
    .filter((root): root is X509Certificate => root !== undefined);
  const chainedToRoot = roots.length > 0 && certificateChainTrusted(material.certificates, roots);

  return {
    method,
    verified,
    trusted: verified && (pinnedKey || pinnedCertificate || chainedToRoot),
    ...(keyId !== undefined ? { keyId } : {}),
    ...(certificate !== undefined
      ? {
          certificateSubject: certificate.subject.replace(/\n/g, ', '),
          certificateIssuer: certificate.issuer.replace(/\n/g, ', '),
          certificateSha256: fingerprint,
          certificateValid: certificateValidNow(certificate),
        }
      : {}),
    ...(verified ? {} : { error: 'Signature does not verify over the DSSE payload.' }),
  };
}

// ── Verifier ─────────────────────────────────────────────────────────────────

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hostedBuilder(builderId: string): boolean {
  return HOSTED_BUILDER_PATTERNS.some((pattern) => pattern.test(builderId));
}

function normalizedRepository(value: string): string {
  return (repositoryFromUri(value) ?? value).toLowerCase().replace(/\/+$/, '');
}

function sameRepository(actual: string, expected: string): boolean {
  const a = normalizedRepository(actual);
  const b = normalizedRepository(expected);
  return a === b || a.endsWith(`/${b}`) || b.endsWith(`/${a}`);
}

function digestMatches(subject: ProvenanceSubject[], sha256: string): boolean {
  return subject.some((entry) => {
    const digest = entry.digest.sha256 ?? entry.digest.SHA256;
    return digest !== undefined && digest.toLowerCase() === sha256;
  });
}

export class SlsaProvenanceVerifier {
  verify(
    artifact: string | Uint8Array,
    provenanceText: string,
    options: SlsaVerificationOptions = {},
  ): SlsaVerificationReport {
    const bytes = normalizeArtifact(artifact);
    const sha256 = hashSha256(bytes);
    const documents = parseProvenanceDocuments(provenanceText);
    const slsaDocuments = documents.filter((document) => {
      const predicateType = predicateTypeOf(document.statement);
      return predicateType !== undefined && predicateType.toLowerCase().includes(SLSA_PREDICATE);
    });

    const findings: SlsaFinding[] = [];
    const push = (finding: SlsaFinding): void => {
      findings.push(finding);
    };

    if (slsaDocuments.length === 0) {
      const first = documents[0];
      const predicateType = first === undefined ? undefined : predicateTypeOf(first.statement);
      push({
        code: 'provenance/predicate-unrecognised',
        severity: 'error',
        message: `Provenance predicate ${predicateType ?? 'unknown'} is not an SLSA provenance predicate`,
        field: 'predicateType',
        recommendation:
          'Attest SLSA provenance (https://slsa.dev/provenance/v1) instead of a custom predicate.',
      });
      push({
        code: 'provenance/missing',
        severity: 'error',
        message: 'No SLSA provenance attestation was found for this artifact',
        recommendation:
          'Generate provenance with `slsa-github-generator` or `actions/attest-build-provenance`.',
      });
      return this.emptyReport(
        sha256,
        bytes.byteLength,
        first?.format ?? 'in-toto-statement',
        findings,
        options,
      );
    }

    // A `.intoto.jsonl` may carry one attestation per artifact; prefer the one
    // whose signed subject actually names this artifact.
    const matching =
      slsaDocuments.find((document) => digestMatches(subjectsOf(document.statement), sha256)) ??
      slsaDocuments[0];
    const document = matching as ParsedAttestation;
    const subject = subjectsOf(document.statement);
    const predicateType = predicateTypeOf(document.statement) ?? 'unknown';
    const provenance = normalizeProvenance(document.statement);

    if (!digestMatches(subject, sha256)) {
      push({
        code: 'provenance/digest-mismatch',
        severity: 'error',
        message: `Artifact SHA-256 ${sha256} does not match any signed subject digest`,
        field: 'subject[].digest.sha256',
        recommendation:
          'Verify the artifact you downloaded is the one the attestation describes; a mismatch means tampering or the wrong file.',
      });
    }
    if (subject.length === 0) {
      push({
        code: 'provenance/subject-missing',
        severity: 'warning',
        message: 'Attestation has no subject, so it does not bind to an artifact',
        field: 'subject',
        recommendation: 'Generate provenance with a subject digest for the published artifact.',
      });
    }

    let signature: SignatureVerification;
    if (document.envelope !== undefined) {
      signature = verifyEnvelopeSignature(document.envelope, document.bundle, options);
    } else {
      signature = {
        method: 'none',
        verified: false,
        trusted: false,
        error: 'The attestation is an unsigned in-toto statement.',
      };
    }

    if (document.envelope === undefined) {
      push({
        code: 'provenance/signature-missing',
        severity: 'warning',
        message: 'Provenance is an unsigned in-toto statement, so anyone could have written it',
        recommendation:
          'Publish a DSSE envelope or Sigstore bundle signed by the build service (SLSA level 2+).',
      });
    } else if (!signature.verified) {
      push({
        code: 'provenance/signature-invalid',
        severity: 'error',
        message: `Provenance signature verification failed: ${signature.error ?? 'unknown error'}`,
        recommendation:
          'Reject this artifact. Re-download the attestation and verify it with `cosign verify-attestation`.',
      });
    } else if (signature.certificateValid === false) {
      push({
        code: 'provenance/certificate-expired',
        severity: 'error',
        message: 'Signing certificate was outside its validity window when checked',
        recommendation: 'Use an attestation signed while its Fulcio certificate was valid.',
      });
    }

    const trustConfigured =
      (options.trustedPublicKeys?.length ?? 0) > 0 ||
      (options.trustedCertificateSha256?.length ?? 0) > 0 ||
      (options.trustedRootCertificates?.length ?? 0) > 0;
    if (signature.verified && !signature.trusted) {
      push({
        code: trustConfigured
          ? 'provenance/untrusted-signer'
          : 'provenance/trust-root-unconfigured',
        severity: trustConfigured ? 'error' : 'warning',
        message: trustConfigured
          ? 'Provenance signature verifies, but the signer is not one of the pinned keys or certificates'
          : 'Provenance signature verifies against the embedded signer, but no trust root was pinned',
        field: 'verificationMaterial',
        recommendation:
          'Pin the expected Fulcio certificate fingerprint or builder public key with --trusted-certificate/--trusted-key.',
      });
    }

    if (provenance !== undefined) {
      this.checkExpectations(provenance, options, push);
    }

    const level = awardLevel({
      document,
      provenance,
      signature,
      subject,
      sha256,
      trustConfigured,
    });
    const requiredLevel = options.requiredLevel ?? 1;
    if (level < requiredLevel) {
      push({
        code: 'provenance/level-below-required',
        severity: 'error',
        message: `Provenance achieves SLSA level ${level}, below the required level ${requiredLevel}`,
        recommendation:
          'Build with a hosted, trusted builder that emits signed provenance, or lower --require-level if appropriate.',
      });
    }

    const digestMatchesArtifact = digestMatches(subject, sha256);
    const controls: string[] = ['SLSA_L0_NONE'];
    if (level >= 1) controls.push('SLSA_L1_PROVENANCE_EXISTS');
    if (level >= 2) controls.push('SLSA_L2_SIGNED_PROVENANCE', 'SLSA_L2_ARTIFACT_DIGEST_BOUND');
    if (level >= 3) controls.push('SLSA_L3_TRUSTED_BUILDER', 'SLSA_L3_REPO_CONTROLLED_TRIGGER');

    const report: SlsaVerificationReport = {
      ok: level >= requiredLevel && !findings.some((finding) => finding.severity === 'error'),
      level,
      requiredLevel,
      format: document.format,
      artifact: {
        ...(options.artifactName !== undefined ? { name: options.artifactName } : {}),
        sha256,
        size: bytes.byteLength,
      },
      signature,
      predicateType,
      ...(provenance !== undefined ? { provenance } : {}),
      subject,
      findings,
      attestation: {
        slsaLevel: level,
        predicateType,
        builderId: provenance?.builderId ?? 'unknown',
        ...(provenance?.sourceRepository !== undefined
          ? { sourceRepository: provenance.sourceRepository }
          : {}),
        ...(provenance?.sourceCommit !== undefined
          ? { sourceCommit: provenance.sourceCommit }
          : {}),
        ...(provenance?.workflowTrigger !== undefined
          ? { workflowTrigger: provenance.workflowTrigger }
          : {}),
        subjectDigests: subject[0]?.digest ?? {},
        artifactSha256: sha256,
        digestMatches: digestMatchesArtifact,
        signatureVerified: signature.verified,
        signerTrusted: signature.trusted,
        controls,
      },
    };
    return report;
  }

  private checkExpectations(
    provenance: NormalizedProvenance,
    options: SlsaVerificationOptions,
    push: (finding: SlsaFinding) => void,
  ): void {
    if (
      options.expectedBuilderId !== undefined &&
      provenance.builderId !== options.expectedBuilderId
    ) {
      push({
        code: 'provenance/builder-mismatch',
        severity: 'error',
        message: `Provenance names builder "${provenance.builderId}", expected "${options.expectedBuilderId}"`,
        field: 'predicate.runDetails.builder.id',
        recommendation:
          'Rebuild with the approved builder identity or correct the expected builder.',
      });
    }

    if (
      options.expectedSourceRepository !== undefined &&
      (provenance.sourceRepository === undefined ||
        !sameRepository(provenance.sourceRepository, options.expectedSourceRepository))
    ) {
      push({
        code: 'provenance/source-mismatch',
        severity: 'error',
        message: `Provenance source repository ${provenance.sourceRepository ?? '(missing)'} does not match "${options.expectedSourceRepository}"`,
        field: 'predicate.buildDefinition.externalParameters.workflow.repository',
        recommendation:
          'Verify the artifact was built from this repository, not a fork or lookalike.',
      });
    }

    if (
      options.expectedCommitSha !== undefined &&
      (provenance.sourceCommit === undefined ||
        provenance.sourceCommit.toLowerCase() !== options.expectedCommitSha.toLowerCase())
    ) {
      push({
        code: 'provenance/commit-mismatch',
        severity: 'error',
        message: `Provenance source commit ${provenance.sourceCommit ?? '(missing)'} does not match "${options.expectedCommitSha}"`,
        field: 'predicate.buildDefinition.resolvedDependencies[].digest.gitCommit',
        recommendation: 'Build the artifact from the reviewed commit and re-generate provenance.',
      });
    }

    if (
      options.expectedWorkflowTrigger !== undefined &&
      provenance.workflowTrigger !== options.expectedWorkflowTrigger
    ) {
      push({
        code: 'provenance/trigger-mismatch',
        severity: 'error',
        message: `Provenance workflow trigger ${provenance.workflowTrigger ?? '(missing)'} does not match "${options.expectedWorkflowTrigger}"`,
        field: 'predicate.buildDefinition.internalParameters.github.event_name',
        recommendation:
          'Only release from the approved workflow trigger (usually `push` on a release branch).',
      });
    }
  }

  private emptyReport(
    sha256: string,
    size: number,
    format: AttestationFormat,
    findings: SlsaFinding[],
    options: SlsaVerificationOptions,
  ): SlsaVerificationReport {
    const requiredLevel = options.requiredLevel ?? 1;
    return {
      ok: false,
      level: 0,
      requiredLevel,
      format,
      artifact: {
        ...(options.artifactName !== undefined ? { name: options.artifactName } : {}),
        sha256,
        size,
      },
      signature: { method: 'none', verified: false, trusted: false },
      subject: [],
      findings,
      attestation: {
        slsaLevel: 0,
        predicateType: 'unknown',
        builderId: 'unknown',
        subjectDigests: {},
        artifactSha256: sha256,
        digestMatches: false,
        signatureVerified: false,
        signerTrusted: false,
        controls: ['SLSA_L0_NONE'],
      },
    };
  }
}

interface LevelInput {
  document: ParsedAttestation;
  provenance: NormalizedProvenance | undefined;
  signature: SignatureVerification;
  subject: ProvenanceSubject[];
  sha256: string;
  trustConfigured: boolean;
}

function awardLevel(input: LevelInput): SlsaLevel {
  const { provenance, signature, subject, sha256, trustConfigured } = input;
  if (provenance === undefined) return 0;
  if (input.document.envelope !== undefined && !signature.verified) return 0;
  if (!digestMatches(subject, sha256)) return 0;

  const levelTwo =
    signature.verified &&
    provenance.builderId !== 'unknown' &&
    provenance.buildType !== 'unknown' &&
    provenance.sourceRepository !== undefined &&
    provenance.sourceCommit !== undefined;
  if (!levelTwo) return 1;

  const triggerTrusted =
    provenance.workflowTrigger !== undefined && TRUSTED_TRIGGERS.has(provenance.workflowTrigger);
  const fullCommit = /^[0-9a-f]{40}$/i.test(provenance.sourceCommit ?? '');
  if (
    trustConfigured &&
    signature.trusted &&
    signature.certificateValid !== false &&
    hostedBuilder(provenance.builderId) &&
    triggerTrusted &&
    fullCommit
  ) {
    return 3;
  }
  return 2;
}

export function verifySlsaProvenance(
  artifact: string | Uint8Array,
  provenanceText: string,
  options: SlsaVerificationOptions = {},
): SlsaVerificationReport {
  return new SlsaProvenanceVerifier().verify(artifact, provenanceText, options);
}

const MARKERS: Record<SlsaSeverity, string> = {
  error: '✖',
  warning: '⚠',
  info: 'ℹ',
};

export function renderProvenanceReport(report: SlsaVerificationReport): string {
  const lines: string[] = [];
  lines.push(`SLSA provenance verification — ${report.artifact.name ?? 'artifact'}`);
  lines.push(`  artifact sha256: ${report.artifact.sha256} (${report.artifact.size} bytes)`);
  lines.push(
    `  attestation: ${report.format}${report.predicateType !== undefined ? ` (${report.predicateType})` : ''}`,
  );
  lines.push(`  slsa level: ${report.level} (required: ${report.requiredLevel})`);
  lines.push(
    `  signature: ${
      report.signature.method === 'none'
        ? 'unsigned'
        : `${report.signature.method} ${report.signature.verified ? 'verified' : 'invalid'}, signer ${
            report.signature.trusted ? 'trusted' : 'untrusted'
          }`
    }`,
  );
  if (report.provenance !== undefined) {
    lines.push(`  builder: ${report.provenance.builderId}`);
    lines.push(
      `  source: ${report.provenance.sourceRepository ?? '—'}@${report.provenance.sourceCommit ?? '—'}`,
    );
    lines.push(`  trigger: ${report.provenance.workflowTrigger ?? '—'}`);
  }

  if (report.findings.length === 0) {
    lines.push('  ✔ no provenance findings');
  } else {
    for (const finding of report.findings) {
      lines.push(`  ${MARKERS[finding.severity]} ${finding.code}: ${finding.message}`);
      lines.push(`      → ${finding.recommendation}`);
    }
  }

  lines.push('', report.ok ? 'Result: pass' : 'Result: fail');
  return `${lines.join('\n')}\n`;
}
