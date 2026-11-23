/**
 * Post-Quantum Lattice-Based Signature (ML-DSA / Dilithium) Preparedness Auditor.
 *
 * Implements auditing for NIST FIPS 204 ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
 * parameter sets and hybrid post-quantum dual-signing structures in stellar.toml.
 */

import { ed25519 } from '@noble/curves/ed25519';

export type MlDsaParameterSet = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export interface MlDsaSpec {
  name: MlDsaParameterSet;
  securityCategory: number;
  publicKeyBytes: number;
  signatureBytes: number;
  aliases: string[];
}

export const ML_DSA_SPECS: Record<MlDsaParameterSet, MlDsaSpec> = {
  'ML-DSA-44': {
    name: 'ML-DSA-44',
    securityCategory: 2,
    publicKeyBytes: 1312,
    signatureBytes: 2420,
    aliases: ['dilithium2', 'ml-dsa-44', 'mldsa44'],
  },
  'ML-DSA-65': {
    name: 'ML-DSA-65',
    securityCategory: 3,
    publicKeyBytes: 1952,
    signatureBytes: 3309,
    aliases: ['dilithium3', 'ml-dsa-65', 'mldsa65'],
  },
  'ML-DSA-87': {
    name: 'ML-DSA-87',
    securityCategory: 5,
    publicKeyBytes: 2592,
    signatureBytes: 4627,
    aliases: ['dilithium5', 'ml-dsa-87', 'mldsa87'],
  },
};

export interface PostQuantumDeclaration {
  parameterSet?: string;
  publicKey?: string;
  crossSignature?: string;
  classicSigningKey?: string;
  migrationDeadline?: string;
  hybridMode?: boolean;
}

export interface PostQuantumAuditFinding {
  ruleId: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  field?: string;
}

export interface PostQuantumReadinessReport {
  score: number; // 0 - 100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  isQuantumReady: boolean;
  parameterSet?: MlDsaParameterSet;
  publicKeyValid: boolean;
  crossSignatureValid?: boolean;
  findings: PostQuantumAuditFinding[];
  recommendations: string[];
}

export class PostQuantumReadinessAuditor {
  /**
   * Resolves a canonical ML-DSA parameter set from name or alias.
   */
  static resolveParameterSet(name: string): MlDsaSpec | undefined {
    const normalized = name.trim().toLowerCase();
    for (const spec of Object.values(ML_DSA_SPECS)) {
      if (spec.name.toLowerCase() === normalized || spec.aliases.includes(normalized)) {
        return spec;
      }
    }
    return undefined;
  }

  /**
   * Validates ML-DSA public key hex or base64 format and byte length.
   */
  static validatePublicKey(paramSet: MlDsaParameterSet, keyData: string): { valid: boolean; error?: string; bytes?: Uint8Array } {
    const spec = ML_DSA_SPECS[paramSet];
    if (!spec) {
      return { valid: false, error: `Unknown parameter set: ${paramSet}` };
    }

    const trimmed = keyData.trim();
    let bytes: Uint8Array;

    const isHex = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0;
    if (isHex) {
      bytes = new Uint8Array(Buffer.from(trimmed, 'hex'));
    } else {
      try {
        bytes = new Uint8Array(Buffer.from(trimmed, 'base64'));
      } catch {
        return { valid: false, error: 'Public key must be valid hex or base64 string' };
      }
    }

    if (bytes.length !== spec.publicKeyBytes) {
      return {
        valid: false,
        error: `Invalid public key length for ${paramSet}: expected ${spec.publicKeyBytes} bytes, got ${bytes.length} bytes`,
      };
    }

    return { valid: true, bytes };
  }

  /**
   * Verifies the cross-attestation signature where classic Ed25519 key signs the post-quantum public key.
   */
  static verifyCrossSignature(
    classicEd25519PubKey: string | Uint8Array,
    pqPubKeyBytes: Uint8Array,
    signature: string | Uint8Array,
  ): boolean {
    try {
      let pubBytes: Uint8Array;
      if (typeof classicEd25519PubKey === 'string') {
        const hexOnly = classicEd25519PubKey.trim();
        if (/^[0-9a-fA-F]{64}$/.test(hexOnly)) {
          pubBytes = new Uint8Array(Buffer.from(hexOnly, 'hex'));
        } else {
          // Attempt base64 or raw 32-byte
          pubBytes = new Uint8Array(Buffer.from(hexOnly, 'base64'));
        }
      } else {
        pubBytes = classicEd25519PubKey;
      }

      let sigBytes: Uint8Array;
      if (typeof signature === 'string') {
        const hexOnly = signature.trim();
        if (/^[0-9a-fA-F]{128}$/.test(hexOnly)) {
          sigBytes = new Uint8Array(Buffer.from(hexOnly, 'hex'));
        } else {
          sigBytes = new Uint8Array(Buffer.from(hexOnly, 'base64'));
        }
      } else {
        sigBytes = signature;
      }

      if (pubBytes.length !== 32 || sigBytes.length !== 64) {
        return false;
      }

      return ed25519.verify(sigBytes, pqPubKeyBytes, pubBytes);
    } catch {
      return false;
    }
  }

  /**
   * Extracts post-quantum declaration fields from parsed TOML data.
   */
  static extractDeclaration(toml: Record<string, unknown>): PostQuantumDeclaration | undefined {
    const pqSection = (toml.POST_QUANTUM || toml.post_quantum) as Record<string, unknown> | undefined;
    if (pqSection && typeof pqSection === 'object') {
      return {
        parameterSet: (pqSection.PARAMETER_SET || pqSection.parameter_set || pqSection.ALGORITHM || pqSection.algorithm) as string | undefined,
        publicKey: (pqSection.ML_DSA_PUBLIC_KEY || pqSection.PUBLIC_KEY || pqSection.public_key) as string | undefined,
        crossSignature: (pqSection.CROSS_SIGNATURE || pqSection.cross_signature) as string | undefined,
        classicSigningKey: (pqSection.CLASSIC_SIGNING_KEY || pqSection.SIGNING_KEY || toml.SIGNING_KEY) as string | undefined,
        migrationDeadline: (pqSection.MIGRATION_DEADLINE || pqSection.migration_deadline) as string | undefined,
        hybridMode: Boolean(pqSection.HYBRID_MODE ?? true),
      };
    }

    // Direct root declarations
    if (toml.ML_DSA_PUBLIC_KEY || toml.POST_QUANTUM_KEY) {
      return {
        parameterSet: (toml.ML_DSA_PARAMETER_SET || toml.POST_QUANTUM_ALGORITHM || 'ML-DSA-65') as string,
        publicKey: (toml.ML_DSA_PUBLIC_KEY || toml.POST_QUANTUM_KEY) as string,
        crossSignature: toml.POST_QUANTUM_CROSS_SIGNATURE as string | undefined,
        classicSigningKey: toml.SIGNING_KEY as string | undefined,
        hybridMode: true,
      };
    }

    return undefined;
  }

  /**
   * Audits stellar.toml parsed content for post-quantum readiness.
   */
  static audit(toml: Record<string, unknown>): PostQuantumReadinessReport {
    const declaration = this.extractDeclaration(toml);
    const findings: PostQuantumAuditFinding[] = [];
    const recommendations: string[] = [];

    if (!declaration || !declaration.publicKey) {
      findings.push({
        ruleId: 'PQ_NOT_CONFIGURED',
        severity: 'info',
        message: 'No post-quantum lattice-based public key (ML-DSA / FIPS 204) declared in stellar.toml.',
      });
      recommendations.push('Add [POST_QUANTUM] section declaring ML_DSA_PUBLIC_KEY with NIST FIPS 204 parameters.');
      return {
        score: 0,
        grade: 'F',
        isQuantumReady: false,
        publicKeyValid: false,
        findings,
        recommendations,
      };
    }

    let score = 50;
    let paramSet: MlDsaParameterSet | undefined;
    let keyValid = false;
    let crossSigValid: boolean | undefined;

    const rawParam = declaration.parameterSet ?? 'ML-DSA-65';
    const spec = this.resolveParameterSet(rawParam);

    if (!spec) {
      findings.push({
        ruleId: 'PQ_INVALID_PARAMETER_SET',
        severity: 'error',
        field: 'PARAMETER_SET',
        message: `Unsupported post-quantum algorithm '${rawParam}'. Supported NIST FIPS 204 algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87.`,
      });
      score -= 20;
    } else {
      paramSet = spec.name;
      findings.push({
        ruleId: 'PQ_PARAMETER_SET_RECOGNIZED',
        severity: 'info',
        field: 'PARAMETER_SET',
        message: `Configured parameter set ${spec.name} (NIST Security Category ${spec.securityCategory}).`,
      });

      const keyCheck = this.validatePublicKey(spec.name, declaration.publicKey);
      if (!keyCheck.valid) {
        findings.push({
          ruleId: 'PQ_INVALID_KEY_LENGTH',
          severity: 'error',
          field: 'ML_DSA_PUBLIC_KEY',
          message: keyCheck.error ?? 'Invalid public key format',
        });
        score -= 30;
      } else {
        keyValid = true;
        score += 25;

        // Verify cross-signature if present
        if (declaration.crossSignature && declaration.classicSigningKey && keyCheck.bytes) {
          const verified = this.verifyCrossSignature(declaration.classicSigningKey, keyCheck.bytes, declaration.crossSignature);
          crossSigValid = verified;
          if (verified) {
            findings.push({
              ruleId: 'PQ_CROSS_SIGNATURE_VALID',
              severity: 'info',
              field: 'CROSS_SIGNATURE',
              message: 'Classic Ed25519 cross-signature over post-quantum public key verified successfully.',
            });
            score += 25;
          } else {
            findings.push({
              ruleId: 'PQ_CROSS_SIGNATURE_INVALID',
              severity: 'error',
              field: 'CROSS_SIGNATURE',
              message: 'Cross-signature verification failed against the classic signing key.',
            });
            score -= 15;
          }
        } else if (!declaration.crossSignature) {
          recommendations.push('Generate a cross-attestation signature using your classic Ed25519 signing key to bind the post-quantum key.');
        }
      }
    }

    if (declaration.migrationDeadline) {
      findings.push({
        ruleId: 'PQ_MIGRATION_TIMELINE_PRESENT',
        severity: 'info',
        field: 'MIGRATION_DEADLINE',
        message: `Target quantum migration deadline noted: ${declaration.migrationDeadline}`,
      });
      score = Math.min(100, score + 5);
    }

    const finalScore = Math.max(0, Math.min(100, score));
    let grade: 'A' | 'B' | 'C' | 'D' | 'F' = 'F';
    if (finalScore >= 90) grade = 'A';
    else if (finalScore >= 75) grade = 'B';
    else if (finalScore >= 60) grade = 'C';
    else if (finalScore >= 40) grade = 'D';

    return {
      score: finalScore,
      grade,
      isQuantumReady: keyValid && (crossSigValid === undefined || crossSigValid),
      parameterSet: paramSet,
      publicKeyValid: keyValid,
      crossSignatureValid: crossSigValid,
      findings,
      recommendations,
    };
  }
}
