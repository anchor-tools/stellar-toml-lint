/**
 * Automated Cryptographic Hash Agility and Collision Resistance Auditor.
 *
 * Scans stellar.toml documents for cryptographic hashes, checksums, and digests.
 * Flags deprecated hashing algorithms (MD5, SHA-1, RIPEMD-160), enforces >= 256-bit
 * collision resistance standards (SHA-256, SHA-512, Blake2b, SHA-3), and generates
 * migration suggestions and security ratings.
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

export type HashAlgorithm =
  | 'MD5'
  | 'SHA-1'
  | 'RIPEMD-160'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'BLAKE2B'
  | 'KECCAK-256'
  | 'UNKNOWN';

export interface HashFieldInspection {
  field: string;
  value: string;
  detectedAlgorithm: HashAlgorithm;
  bitLength: number;
  encoding: 'hex' | 'base64' | 'unknown';
  isDeprecated: boolean;
  isCompliant: boolean; // >= 256-bit collision resistance
  severity: 'error' | 'warning' | 'info';
  issue?: string;
  recommendedAlgorithm: 'SHA-256' | 'SHA-512';
}

export interface HashAgilityReport {
  score: number; // 0 - 100
  securityRating: 'SECURE' | 'MODERATE_RISK' | 'INSECURE';
  totalHashesFound: number;
  compliantCount: number;
  deprecatedCount: number;
  insufficientLengthCount: number;
  inspections: HashFieldInspection[];
  recommendations: string[];
}

export class HashAgilityAuditor {
  /** Known fields in SEP-1 and ecosystem extensions that contain hashes/checksums */
  static readonly HASH_FIELD_PATTERNS = [
    /_HASH$/i,
    /_CHECKSUM$/i,
    /_DIGEST$/i,
    /^CODE_HASH$/i,
    /^DOCUMENTATION_HASH$/i,
    /^ORG_LOGO_HASH$/i,
    /^IMAGE_HASH$/i,
    /^COMMIT_HASH$/i,
    /^MERKLE_ROOT$/i,
    /^MULTIHASH$/i,
    /^CONTENT_HASH$/i,
  ];

  /**
   * Identifies candidate hash algorithm based on bit length and structure.
   */
  static classifyHash(value: string): {
    algorithm: HashAlgorithm;
    bitLength: number;
    encoding: 'hex' | 'base64' | 'unknown';
  } {
    const trimmed = value.trim();

    // Check Hex
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
      const byteLen = trimmed.length / 2;
      const bitLen = byteLen * 8;
      let algorithm: HashAlgorithm = 'UNKNOWN';

      if (bitLen === 128) algorithm = 'MD5';
      else if (bitLen === 160) algorithm = 'SHA-1'; // or RIPEMD-160
      else if (bitLen === 256) algorithm = 'SHA-256';
      else if (bitLen === 384) algorithm = 'SHA-384';
      else if (bitLen === 512) algorithm = 'SHA-512';

      return { algorithm, bitLength: bitLen, encoding: 'hex' };
    }

    // Check Base64
    if (/^[A-Za-z0-9+/=]+$/.test(trimmed) && (trimmed.length % 4 === 0 || trimmed.length % 4 === 2 || trimmed.length % 4 === 3)) {
      try {
        const buf = Buffer.from(trimmed, 'base64');
        const bitLen = buf.length * 8;
        let algorithm: HashAlgorithm = 'UNKNOWN';

        if (bitLen === 128) algorithm = 'MD5';
        else if (bitLen === 160) algorithm = 'SHA-1';
        else if (bitLen === 256) algorithm = 'SHA-256';
        else if (bitLen === 384) algorithm = 'SHA-384';
        else if (bitLen === 512) algorithm = 'SHA-512';

        return { algorithm, bitLength: bitLen, encoding: 'base64' };
      } catch {
        // Fall through
      }
    }

    return { algorithm: 'UNKNOWN', bitLength: 0, encoding: 'unknown' };
  }

  /**
   * Scans an object recursively for hash/checksum fields.
   */
  static findHashFields(data: unknown, prefix = ''): Array<{ path: string; value: string }> {
    const results: Array<{ path: string; value: string }> = [];

    if (!data || typeof data !== 'object') {
      return results;
    }

    for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
      const fullPath = prefix ? `${prefix}.${key}` : key;

      if (typeof val === 'string') {
        const isHashField = this.HASH_FIELD_PATTERNS.some((pattern) => pattern.test(key));
        if (isHashField) {
          results.push({ path: fullPath, value: val });
        }
      } else if (Array.isArray(val)) {
        val.forEach((item, index) => {
          results.push(...this.findHashFields(item, `${fullPath}[${index}]`));
        });
      } else if (typeof val === 'object') {
        results.push(...this.findHashFields(val, fullPath));
      }
    }

    return results;
  }

  /**
   * Computes SHA-256 upgrade digest for text or byte data.
   */
  static computeSha256(data: string | Uint8Array): string {
    const input = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return Buffer.from(sha256(input)).toString('hex');
  }

  /**
   * Computes SHA-512 upgrade digest for text or byte data.
   */
  static computeSha512(data: string | Uint8Array): string {
    const input = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return Buffer.from(sha512(input)).toString('hex');
  }

  /**
   * Audits parsed stellar.toml object for hash agility and collision resistance.
   */
  static audit(toml: Record<string, unknown>): HashAgilityReport {
    const hashFields = this.findHashFields(toml);
    const inspections: HashFieldInspection[] = [];
    const recommendations: string[] = [];

    let compliantCount = 0;
    let deprecatedCount = 0;
    let insufficientLengthCount = 0;
    let score = 100;

    for (const { path, value } of hashFields) {
      const { algorithm, bitLength, encoding } = this.classifyHash(value);

      const isDeprecated = algorithm === 'MD5' || algorithm === 'SHA-1' || algorithm === 'RIPEMD-160';
      const isCompliant = bitLength >= 256 && !isDeprecated;

      let severity: 'error' | 'warning' | 'info' = 'info';
      let issue: string | undefined;

      if (isDeprecated) {
        severity = 'error';
        deprecatedCount++;
        score -= 25;
        issue = `Field '${path}' uses obsolete collision-compromised algorithm ${algorithm} (${bitLength}-bit). Upgrade immediately to SHA-256 or SHA-512.`;
        recommendations.push(`Replace deprecated ${algorithm} hash in '${path}' with standard SHA-256 digest.`);
      } else if (bitLength > 0 && bitLength < 256) {
        severity = 'error';
        insufficientLengthCount++;
        score -= 20;
        issue = `Field '${path}' digest bit length (${bitLength} bits) is below the minimum required 256 bits collision resistance standard.`;
        recommendations.push(`Upgrade digest in '${path}' to >= 256-bit hash (SHA-256 or SHA-512).`);
      } else if (algorithm === 'UNKNOWN' || encoding === 'unknown') {
        severity = 'warning';
        score -= 10;
        issue = `Field '${path}' hash format could not be verified as valid hex or base64 cryptographic digest.`;
      } else {
        compliantCount++;
      }

      inspections.push({
        field: path,
        value,
        detectedAlgorithm: algorithm,
        bitLength,
        encoding,
        isDeprecated,
        isCompliant,
        severity,
        issue,
        recommendedAlgorithm: 'SHA-256',
      });
    }

    if (hashFields.length === 0) {
      recommendations.push('No explicit checksums or hashes declared. When publishing binary or document artifacts, declare SHA-256 hashes.');
    }

    const finalScore = Math.max(0, Math.min(100, score));
    let securityRating: 'SECURE' | 'MODERATE_RISK' | 'INSECURE' = 'SECURE';
    if (finalScore < 60 || deprecatedCount > 0) {
      securityRating = 'INSECURE';
    } else if (finalScore < 85 || insufficientLengthCount > 0) {
      securityRating = 'MODERATE_RISK';
    }

    return {
      score: finalScore,
      securityRating,
      totalHashesFound: hashFields.length,
      compliantCount,
      deprecatedCount,
      insufficientLengthCount,
      inspections,
      recommendations,
    };
  }
}
