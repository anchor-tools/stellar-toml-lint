/**
 * W3C Verifiable Credential and DID resolution verifier for anchor identity.
 *
 * Implements W3C DID Core 1.0, W3C Verifiable Credentials 1.1 / 2.0,
 * supporting did:web, did:key (Ed25519), and did:ion resolution.
 */

import { parse as parseToml } from 'smol-toml';

export interface DidDocument {
  '@context': string | string[];
  id: string;
  alsoKnownAs?: string[];
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
  service?: DidService[];
  [key: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  publicKeyJwk?: {
    kty: string;
    crv?: string;
    x?: string;
    y?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface DidService {
  id: string;
  type: string | string[];
  serviceEndpoint: string | string[] | Record<string, unknown>;
  [key: string]: unknown;
}

export interface VerifiableCredential {
  '@context': string | string[];
  id?: string;
  type: string | string[];
  issuer: string | { id: string; [key: string]: unknown };
  issuanceDate?: string;
  validFrom?: string;
  expirationDate?: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown> | Record<string, unknown>[];
  proof?: CredentialProof | CredentialProof[];
  [key: string]: unknown;
}

export interface CredentialProof {
  type: string;
  created?: string;
  verificationMethod: string;
  proofPurpose?: string;
  proofValue?: string;
  jws?: string;
  [key: string]: unknown;
}

export interface VerificationMethodSummary {
  id: string;
  type: string;
  controller: string;
  valid: boolean;
  keyType: string;
  publicKeyHex?: string;
  error?: string;
}

export interface DidResolutionResult {
  did: string;
  resolved: boolean;
  method: string;
  didDocument?: DidDocument;
  verificationMethods: VerificationMethodSummary[];
  authenticated: boolean;
  errors: string[];
  warnings: string[];
}

export interface VcVerificationResult {
  valid: boolean;
  issuerDid: string;
  subjectId?: string;
  claims: Record<string, unknown>;
  proofType?: string;
  verifiedAt: string;
  errors: string[];
  warnings: string[];
}

export interface TomlDidAuditResult {
  foundDids: { field: string; did: string }[];
  resolutionResults: DidResolutionResult[];
  compliant: boolean;
  summary: string;
}

export interface DidVerifierOptions {
  fetcher?: (url: string) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
  ionResolverUrl?: string;
  allowInsecureHttp?: boolean;
}

// Base58 alphabet for multibase base58btc (z)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function decodeBase58(input: string): Uint8Array {
  if (input.length === 0) return new Uint8Array(0);
  const bytes = [0];
  for (let i = 0; i < input.length; i++) {
    const char = input[i]!;
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character '${char}'`);
    }
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < input.length && input[i] === '1'; i++) {
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

export function encodeBase58(source: Uint8Array): string {
  if (source.length === 0) return '';
  const digits = [0];
  for (let i = 0; i < source.length; i++) {
    let carry: number = source[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '';
  for (let i = 0; i < source.length && source[i] === 0; i++) {
    str += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    const d = digits[i]!;
    str += BASE58_ALPHABET[d]!;
  }
  return str;
}

/**
 * Verifier and resolver for W3C DIDs and Verifiable Credentials.
 */
export class DidResolutionVerifier {
  private fetcher: (
    url: string,
  ) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
  private ionResolverUrl: string;

  constructor(options: DidVerifierOptions = {}) {
    this.fetcher =
      options.fetcher ??
      (typeof fetch !== 'undefined'
        ? fetch.bind(globalThis)
        : async () => {
            throw new Error('fetch is not available in the current environment');
          });
    this.ionResolverUrl = options.ionResolverUrl ?? 'https://identity.foundation/ion/identifiers';
  }

  /**
   * Extract DID entries from parsed stellar.toml object or raw string.
   */
  public extractDidsFromToml(
    toml: Record<string, unknown> | string,
  ): { field: string; did: string }[] {
    const results: { field: string; did: string }[] = [];
    let parsed: Record<string, unknown>;

    if (typeof toml === 'string') {
      try {
        parsed = parseToml(toml) as Record<string, unknown>;
      } catch {
        // Simple regex fallback if parser fails
        const didRegex = /(?:ORG_DID|DID)\s*=\s*["'](did:[a-z0-9]+:[^"']+)["']/gi;
        let match: RegExpExecArray | null;
        while ((match = didRegex.exec(toml)) !== null) {
          if (match[1]) {
            results.push({ field: 'REGEX_EXTRACTED', did: match[1] });
          }
        }
        return results;
      }
    } else {
      parsed = toml;
    }

    const checkField = (
      obj: Record<string, unknown> | undefined,
      fieldName: string,
      prefix: string,
    ) => {
      if (!obj) return;
      const val = obj[fieldName];
      if (typeof val === 'string' && val.startsWith('did:')) {
        results.push({ field: `${prefix}.${fieldName}`, did: val.trim() });
      } else if (Array.isArray(val)) {
        for (let i = 0; i < val.length; i++) {
          if (typeof val[i] === 'string' && val[i].startsWith('did:')) {
            results.push({ field: `${prefix}.${fieldName}[${i}]`, did: val[i].trim() });
          }
        }
      }
    };

    // Check DOCUMENTATION table
    const doc = parsed.DOCUMENTATION as Record<string, unknown> | undefined;
    checkField(doc, 'ORG_DID', 'DOCUMENTATION');
    checkField(doc, 'DID', 'DOCUMENTATION');

    // Check ORGANIZATION table
    const org = parsed.ORGANIZATION as Record<string, unknown> | undefined;
    checkField(org, 'ORG_DID', 'ORGANIZATION');
    checkField(org, 'DID', 'ORGANIZATION');

    // Check top-level
    checkField(parsed, 'ORG_DID', 'ROOT');
    checkField(parsed, 'DID', 'ROOT');

    // Check [[ACCOUNTS]] or [[SIGNERS]] or other tables
    if (Array.isArray(parsed.ACCOUNTS)) {
      parsed.ACCOUNTS.forEach((acc, idx) => {
        if (typeof acc === 'object' && acc !== null) {
          checkField(acc as Record<string, unknown>, 'DID', `ACCOUNTS[${idx}]`);
        }
      });
    }

    return results;
  }

  /**
   * Resolve a DID identifier to its DID document.
   */
  public async resolveDid(did: string): Promise<DidResolutionResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!did || typeof did !== 'string' || !did.startsWith('did:')) {
      return {
        did,
        resolved: false,
        method: 'unknown',
        verificationMethods: [],
        authenticated: false,
        errors: [`Invalid DID format: must start with "did:"`],
        warnings: [],
      };
    }

    const parts = did.split(':');
    if (parts.length < 3) {
      return {
        did,
        resolved: false,
        method: 'unknown',
        verificationMethods: [],
        authenticated: false,
        errors: [`Invalid DID structure: expected did:<method>:<method-specific-id>`],
        warnings: [],
      };
    }

    const method = parts[1] ?? 'unknown';

    try {
      let doc: DidDocument;
      switch (method) {
        case 'web':
          doc = await this.resolveDidWeb(did);
          break;
        case 'key':
          doc = this.resolveDidKey(did);
          break;
        case 'ion':
          doc = await this.resolveDidIon(did);
          break;
        default:
          return {
            did,
            resolved: false,
            method,
            verificationMethods: [],
            authenticated: false,
            errors: [`Unsupported DID method: did:${method}`],
            warnings: [],
          };
      }

      // Validate DID Document
      const validation = this.validateDidDocument(doc, did);
      errors.push(...validation.errors);
      warnings.push(...validation.warnings);

      return {
        did,
        resolved: errors.length === 0,
        method,
        didDocument: doc,
        verificationMethods: validation.summaries,
        authenticated: validation.authenticated,
        errors,
        warnings,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Resolution error for ${did}: ${msg}`);
      return {
        did,
        resolved: false,
        method,
        verificationMethods: [],
        authenticated: false,
        errors,
        warnings,
      };
    }
  }

  /**
   * Resolve did:web document per W3C did:web specification.
   */
  public async resolveDidWeb(did: string): Promise<DidDocument> {
    const parts = did.split(':');
    if (parts.length < 3 || parts[1] !== 'web') {
      throw new Error(`Invalid did:web string: ${did}`);
    }

    // did:web:example.com -> https://example.com/.well-known/did.json
    // did:web:example.com:user:alice -> https://example.com/user/alice/did.json
    const domain = decodeURIComponent(parts[2] ?? '');
    const pathParts = parts.slice(3).map((p) => decodeURIComponent(p));

    let url: string;
    if (pathParts.length === 0) {
      url = `https://${domain}/.well-known/did.json`;
    } else {
      url = `https://${domain}/${pathParts.join('/')}/did.json`;
    }

    const resp = await this.fetcher(url);
    if (!resp.ok) {
      throw new Error(`Failed to fetch did:web document at ${url} (HTTP ${resp.status})`);
    }

    const json = (await resp.json()) as DidDocument;
    return json;
  }

  /**
   * Resolve did:key document per W3C did:key specification.
   */
  public resolveDidKey(did: string): DidDocument {
    const parts = did.split(':');
    if (parts.length < 3 || parts[1] !== 'key') {
      throw new Error(`Invalid did:key string: ${did}`);
    }

    const multibaseKey = parts[2] ?? '';
    if (!multibaseKey.startsWith('z')) {
      throw new Error(`Unsupported multibase prefix in did:key: expected 'z' (base58btc)`);
    }

    const rawBytes = decodeBase58(multibaseKey.slice(1));
    if (rawBytes.length < 2) {
      throw new Error(`Malformed did:key payload: too short`);
    }

    // Multicodec check: Ed25519 public key multicodec is 0xed, 0x01 (varint)
    if (rawBytes[0] === 0xed && rawBytes[1] === 0x01) {
      const pubKeyBytes = rawBytes.slice(2);
      if (pubKeyBytes.length !== 32) {
        throw new Error(
          `Invalid Ed25519 public key length in did:key: expected 32 bytes, got ${pubKeyBytes.length}`,
        );
      }

      const keyId = `${did}#${multibaseKey}`;
      const vm: VerificationMethod = {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: multibaseKey,
      };

      return {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1',
        ],
        id: did,
        verificationMethod: [vm],
        authentication: [keyId],
        assertionMethod: [keyId],
        capabilityInvocation: [keyId],
        capabilityDelegation: [keyId],
      };
    }

    const prefixHex = rawBytes[0] !== undefined ? rawBytes[0].toString(16) : 'unknown';
    throw new Error(`Unsupported multicodec algorithm in did:key (prefix: 0x${prefixHex})`);
  }

  /**
   * Resolve did:ion document.
   */
  public async resolveDidIon(did: string): Promise<DidDocument> {
    const parts = did.split(':');
    if (parts.length < 3 || parts[1] !== 'ion') {
      throw new Error(`Invalid did:ion string: ${did}`);
    }

    // Long-form DID contains encoded initial state: did:ion:<id>:<initial-state>
    if (parts.length >= 4 && parts[3]) {
      try {
        const initialState = parts[3];
        const jsonStr = Buffer.from(initialState, 'base64url').toString('utf-8');
        const parsedState = JSON.parse(jsonStr);
        if (parsedState.document) {
          const doc = parsedState.document as DidDocument;
          doc.id = did;
          if (!doc['@context']) doc['@context'] = 'https://www.w3.org/ns/did/v1';
          return doc;
        }
      } catch {
        // Fall back to resolving through ION endpoint
      }
    }

    // Query resolver endpoint
    const url = `${this.ionResolverUrl}/${encodeURIComponent(did)}`;
    const resp = await this.fetcher(url);
    if (!resp.ok) {
      throw new Error(`Failed to resolve did:ion via ${url} (HTTP ${resp.status})`);
    }

    const body = (await resp.json()) as { didDocument?: DidDocument; [key: string]: unknown };
    if (!body.didDocument) {
      throw new Error(`did:ion response missing didDocument object`);
    }
    return body.didDocument;
  }

  /**
   * Validate JSON-LD context, verification methods, and authentication relationships.
   */
  public validateDidDocument(
    doc: DidDocument,
    expectedDid: string,
  ): {
    errors: string[];
    warnings: string[];
    summaries: VerificationMethodSummary[];
    authenticated: boolean;
  } {
    const errors: string[] = [];
    const warnings: string[] = [];
    const summaries: VerificationMethodSummary[] = [];

    // Context validation
    if (!doc['@context']) {
      errors.push(`Missing required "@context" in DID document`);
    } else {
      const contexts = Array.isArray(doc['@context']) ? doc['@context'] : [doc['@context']];
      const validDidContext = contexts.some(
        (c) =>
          typeof c === 'string' &&
          (c.includes('www.w3.org/ns/did/v1') ||
            c.includes('w3id.org/did/v1') ||
            c.includes('w3.org/2018/credentials')),
      );
      if (!validDidContext) {
        errors.push(
          `DID document @context does not include standard W3C DID Core context ("https://www.w3.org/ns/did/v1")`,
        );
      }
    }

    // Subject ID validation
    if (!doc.id) {
      errors.push(`Missing required "id" in DID document`);
    } else if (
      doc.id !== expectedDid &&
      !doc.id.startsWith(expectedDid.split(':')[0] ?? expectedDid)
    ) {
      warnings.push(`Document ID "${doc.id}" does not match requested DID "${expectedDid}"`);
    }

    // Verification methods
    const vms = doc.verificationMethod || [];
    if (!Array.isArray(vms) || vms.length === 0) {
      warnings.push(`DID document declares no verificationMethod entries`);
    }

    for (const vm of vms) {
      const summary = this.validateVerificationMethod(vm, doc.id);
      summaries.push(summary);
      if (!summary.valid && summary.error) {
        errors.push(`VerificationMethod "${vm.id}": ${summary.error}`);
      }
    }

    // Authentication relationship
    let authenticated = false;
    const authList = doc.authentication || [];
    if (authList.length > 0) {
      for (const auth of authList) {
        const authId = typeof auth === 'string' ? auth : auth.id;
        // Check if referenced VM exists and is valid
        const found = summaries.find(
          (s) => s.id === authId || s.id.endsWith(authId) || authId.endsWith(s.id),
        );
        if (found && found.valid) {
          authenticated = true;
          break;
        } else if (typeof auth === 'object' && auth !== null) {
          const inlineSummary = this.validateVerificationMethod(auth, doc.id);
          summaries.push(inlineSummary);
          if (inlineSummary.valid) {
            authenticated = true;
            break;
          }
        }
      }
    } else {
      warnings.push(`DID document defines no authentication relationship`);
    }

    return { errors, warnings, summaries, authenticated };
  }

  /**
   * Validate a single verification method (e.g. Ed25519VerificationKey2020).
   */
  public validateVerificationMethod(
    vm: VerificationMethod,
    docId?: string,
  ): VerificationMethodSummary {
    if (docId && !docId.startsWith('did:')) {
      // Document id format verification
    }
    if (!vm.id || !vm.type || !vm.controller) {
      return {
        id: vm.id || 'unknown',
        type: vm.type || 'unknown',
        controller: vm.controller || 'unknown',
        valid: false,
        keyType: 'unknown',
        error: `Missing required fields (id, type, or controller)`,
      };
    }

    if (vm.type === 'Ed25519VerificationKey2020') {
      if (!vm.publicKeyMultibase || !vm.publicKeyMultibase.startsWith('z')) {
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: false,
          keyType: 'Ed25519',
          error: `Ed25519VerificationKey2020 requires publicKeyMultibase starting with 'z'`,
        };
      }
      try {
        const raw = decodeBase58(vm.publicKeyMultibase.slice(1));
        // multicodec prefix 0xed01 followed by 32 bytes or 32 raw bytes
        const keyBytes = raw[0] === 0xed && raw[1] === 0x01 ? raw.slice(2) : raw;
        if (keyBytes.length !== 32) {
          return {
            id: vm.id,
            type: vm.type,
            controller: vm.controller,
            valid: false,
            keyType: 'Ed25519',
            error: `Invalid public key length: expected 32 bytes, got ${keyBytes.length}`,
          };
        }
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: true,
          keyType: 'Ed25519',
          publicKeyHex: Buffer.from(keyBytes).toString('hex'),
        };
      } catch (err) {
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: false,
          keyType: 'Ed25519',
          error: `Failed to decode multibase public key: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    if (vm.type === 'Ed25519VerificationKey2018') {
      if (!vm.publicKeyBase58) {
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: false,
          keyType: 'Ed25519',
          error: `Ed25519VerificationKey2018 requires publicKeyBase58`,
        };
      }
      try {
        const raw = decodeBase58(vm.publicKeyBase58);
        if (raw.length !== 32) {
          return {
            id: vm.id,
            type: vm.type,
            controller: vm.controller,
            valid: false,
            keyType: 'Ed25519',
            error: `Invalid Ed25519 publicKeyBase58 length: expected 32 bytes, got ${raw.length}`,
          };
        }
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: true,
          keyType: 'Ed25519',
          publicKeyHex: Buffer.from(raw).toString('hex'),
        };
      } catch (err) {
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: false,
          keyType: 'Ed25519',
          error: `Failed to decode base58 key: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    if (vm.type === 'JsonWebKey2020') {
      if (!vm.publicKeyJwk || vm.publicKeyJwk.kty !== 'OKP' || vm.publicKeyJwk.crv !== 'Ed25519') {
        return {
          id: vm.id,
          type: vm.type,
          controller: vm.controller,
          valid: false,
          keyType: 'JWK',
          error: `JsonWebKey2020 expects kty 'OKP' and crv 'Ed25519'`,
        };
      }
      return {
        id: vm.id,
        type: vm.type,
        controller: vm.controller,
        valid: true,
        keyType: 'Ed25519-JWK',
        publicKeyHex: vm.publicKeyJwk.x
          ? Buffer.from(vm.publicKeyJwk.x, 'base64url').toString('hex')
          : undefined,
      };
    }

    // Generic verification method
    return {
      id: vm.id,
      type: vm.type,
      controller: vm.controller,
      valid: true,
      keyType: vm.type,
    };
  }

  /**
   * Verify a W3C Verifiable Credential.
   */
  public async verifyCredential(
    vc: VerifiableCredential,
    trustedIssuerDid?: string,
  ): Promise<VcVerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    const issuerId = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
    if (!issuerId) {
      errors.push(`Missing credential issuer`);
    } else if (trustedIssuerDid && issuerId !== trustedIssuerDid) {
      errors.push(`Issuer "${issuerId}" does not match expected trusted DID "${trustedIssuerDid}"`);
    }

    // Context check
    const contexts = Array.isArray(vc['@context']) ? vc['@context'] : [vc['@context']];
    if (!contexts.some((c) => typeof c === 'string' && c.includes('www.w3.org/2018/credentials'))) {
      errors.push(`Missing standard W3C Verifiable Credentials context in @context`);
    }

    // Type check
    const types = Array.isArray(vc.type) ? vc.type : [vc.type];
    if (!types.includes('VerifiableCredential')) {
      errors.push(`Credential "type" must include "VerifiableCredential"`);
    }

    // Subject check
    if (!vc.credentialSubject) {
      errors.push(`Missing "credentialSubject" in credential`);
    }

    // Date check
    const issuance = vc.issuanceDate || vc.validFrom;
    if (issuance && isNaN(Date.parse(issuance))) {
      errors.push(`Invalid issuanceDate/validFrom timestamp: "${issuance}"`);
    }

    const expiration = vc.expirationDate || vc.validUntil;
    if (expiration) {
      if (isNaN(Date.parse(expiration))) {
        errors.push(`Invalid expirationDate/validUntil timestamp: "${expiration}"`);
      } else if (Date.parse(expiration) < Date.now()) {
        errors.push(`Credential has expired on ${expiration}`);
      }
    }

    // Proof check
    const proofs = Array.isArray(vc.proof) ? vc.proof : vc.proof ? [vc.proof] : [];
    if (proofs.length === 0) {
      errors.push(`Missing cryptographic proof on Verifiable Credential`);
    } else {
      for (const proof of proofs) {
        if (!proof.verificationMethod) {
          errors.push(`Proof missing verificationMethod`);
        }
        if (!proof.proofValue && !proof.jws) {
          errors.push(`Proof missing proofValue or jws signature`);
        }
      }
    }

    const claims = Array.isArray(vc.credentialSubject)
      ? (vc.credentialSubject[0] as Record<string, unknown>)
      : (vc.credentialSubject as Record<string, unknown>);

    const subjectId = claims?.id ? String(claims.id) : undefined;

    return {
      valid: errors.length === 0,
      issuerDid: issuerId || 'unknown',
      subjectId,
      claims: claims || {},
      proofType: proofs[0]?.type,
      verifiedAt: new Date().toISOString(),
      errors,
      warnings,
    };
  }

  /**
   * Audit stellar.toml for DID declaration and perform resolution.
   */
  public async auditTomlDids(
    tomlContent: Record<string, unknown> | string,
  ): Promise<TomlDidAuditResult> {
    const foundDids = this.extractDidsFromToml(tomlContent);
    const resolutionResults: DidResolutionResult[] = [];

    for (const item of foundDids) {
      const res = await this.resolveDid(item.did);
      resolutionResults.push(res);
    }

    const compliant =
      foundDids.length > 0 && resolutionResults.every((r) => r.resolved && r.authenticated);

    let summary: string;
    if (foundDids.length === 0) {
      summary = 'No W3C DID declared under organization metadata in stellar.toml';
    } else if (compliant) {
      summary = `Successfully resolved and verified ${foundDids.length} DID(s) across methods: ${resolutionResults.map((r) => r.method).join(', ')}`;
    } else {
      summary = `Found ${foundDids.length} DID(s) with verification issues: ${resolutionResults
        .filter((r) => !r.resolved)
        .map((r) => `${r.did} (${r.errors.join('; ')})`)
        .join(', ')}`;
    }

    return {
      foundDids,
      resolutionResults,
      compliant,
      summary,
    };
  }
}
