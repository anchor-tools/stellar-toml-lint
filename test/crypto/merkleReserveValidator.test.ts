import { describe, expect, it } from 'vitest';
import {
  MerkleReserveValidator,
  merkleRules,
  merkleRuleIds,
  MERKLE_INVALID_ROOT,
  MERKLE_INVALID_PROOF,
  MERKLE_NEGATIVE_BALANCE,
  MERKLE_SUM_MISMATCH,
  MERKLE_MALFORMED_LEAF,
  type MerkleLeaf,
} from '../../src/crypto/merkleReserveValidator.js';

const SAMPLE_LEAVES: MerkleLeaf[] = [
  { account: 'GABC123', balance: 1000n },
  { account: 'GDEF456', balance: 2500n },
  { account: 'GHIJ789', balance: 750n },
  { account: 'GKLM012', balance: 3200n },
];

describe('MerkleReserveValidator', () => {
  const validator = new MerkleReserveValidator('sha256');

  it('exposes merkle rules and rule IDs', () => {
    expect(merkleRules).toHaveLength(5);
    expect(merkleRuleIds).toContain(MERKLE_INVALID_ROOT);
    expect(merkleRuleIds).toContain(MERKLE_INVALID_PROOF);
    expect(merkleRuleIds).toContain(MERKLE_NEGATIVE_BALANCE);
    expect(merkleRuleIds).toContain(MERKLE_SUM_MISMATCH);
    expect(merkleRuleIds).toContain(MERKLE_MALFORMED_LEAF);
  });

  describe('hashLeafNode', () => {
    it('produces a 64-character hex string', () => {
      const hash = validator.hashLeafNode(SAMPLE_LEAVES[0]!);
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]+$/);
    });

    it('produces deterministic results', () => {
      const h1 = validator.hashLeafNode(SAMPLE_LEAVES[0]!);
      const h2 = validator.hashLeafNode(SAMPLE_LEAVES[0]!);
      expect(h1).toBe(h2);
    });

    it('produces different hashes for different accounts', () => {
      const h1 = validator.hashLeafNode(SAMPLE_LEAVES[0]!);
      const h2 = validator.hashLeafNode(SAMPLE_LEAVES[1]!);
      expect(h1).not.toBe(h2);
    });

    it('throws for negative balance', () => {
      expect(() => validator.hashLeafNode({ account: 'GTEST', balance: -1n })).toThrow(
        /Negative balance/,
      );
    });
  });

  describe('buildTree / computeRoot', () => {
    it('builds a tree and returns a 64-char root', () => {
      const { root } = validator.computeRoot(SAMPLE_LEAVES);
      expect(root).toHaveLength(64);
      expect(root).toMatch(/^[0-9a-f]+$/);
    });

    it('handles odd number of leaves (promotes last leaf)', () => {
      const oddLeaves: MerkleLeaf[] = [
        { account: 'G1', balance: 100n },
        { account: 'G2', balance: 200n },
        { account: 'G3', balance: 300n },
      ];
      const { root } = validator.computeRoot(oddLeaves);
      expect(root).toHaveLength(64);
    });

    it('handles single leaf', () => {
      const { root } = validator.computeRoot([{ account: 'GONLY', balance: 999n }]);
      expect(root).toHaveLength(64);
    });

    it('accumulates total liability correctly', () => {
      const { totalLiability } = validator.computeRoot(SAMPLE_LEAVES);
      expect(totalLiability).toBe(1000n + 2500n + 750n + 3200n);
    });

    it('produces different roots for different leaf sets', () => {
      const { root: r1 } = validator.computeRoot(SAMPLE_LEAVES);
      const modified = [...SAMPLE_LEAVES.slice(0, 3), { account: 'GKLM012', balance: 9999n }];
      const { root: r2 } = validator.computeRoot(modified);
      expect(r1).not.toBe(r2);
    });
  });

  describe('generateProof / verifyProof', () => {
    it('generates valid inclusion proof for each leaf', () => {
      const { leafHashes } = validator.computeRoot(SAMPLE_LEAVES);
      for (let i = 0; i < SAMPLE_LEAVES.length; i++) {
        const proof = validator.generateProof(leafHashes, i);
        expect(validator.verifyProof(proof)).toBe(true);
      }
    });

    it('rejects proof verified against wrong root', () => {
      const { leafHashes } = validator.computeRoot(SAMPLE_LEAVES);
      const proof = validator.generateProof(leafHashes, 0);
      const wrongRoot = '0'.repeat(64);
      expect(validator.verifyProof(proof, wrongRoot)).toBe(false);
    });

    it('handles large-scale trees (64 leaves)', () => {
      const bigLeaves: MerkleLeaf[] = Array.from({ length: 64 }, (_, i) => ({
        account: `GACCOUNT${String(i).padStart(4, '0')}`,
        balance: BigInt(i + 1) * 1000n,
      }));
      const { leafHashes } = validator.computeRoot(bigLeaves);
      const proof = validator.generateProof(leafHashes, 0);
      expect(validator.verifyProof(proof)).toBe(true);
    });

    it('throws when leaf index is out of range', () => {
      const { leafHashes } = validator.computeRoot(SAMPLE_LEAVES);
      expect(() => validator.generateProof(leafHashes, SAMPLE_LEAVES.length)).toThrow(
        /out of range/i,
      );
    });
  });

  describe('validateLeaves', () => {
    it('validates correct leaves with no issues', () => {
      const results = validator.validateLeaves(SAMPLE_LEAVES);
      expect(results.every((r) => r.valid)).toBe(true);
    });

    it('flags negative balances', () => {
      const bad: MerkleLeaf[] = [{ account: 'GBAD', balance: -100n }];
      const results = validator.validateLeaves(bad);
      expect(results[0]!.valid).toBe(false);
      expect(results[0]!.issues[0]).toMatch(/non-negative/i);
    });

    it('flags empty account identifiers', () => {
      const bad: MerkleLeaf[] = [{ account: '', balance: 500n }];
      const results = validator.validateLeaves(bad);
      expect(results[0]!.valid).toBe(false);
      expect(results[0]!.issues[0]).toMatch(/empty/i);
    });
  });

  describe('audit', () => {
    it('passes audit when leaves and root match', () => {
      const { root } = validator.computeRoot(SAMPLE_LEAVES);
      const report = validator.audit(SAMPLE_LEAVES, root);
      expect(report.valid).toBe(true);
      expect(report.findings).toHaveLength(0);
    });

    it('fails audit when declared root is wrong', () => {
      const report = validator.audit(SAMPLE_LEAVES, '0'.repeat(64));
      expect(report.valid).toBe(false);
      expect(report.findings.some((f) => f.message.includes('does not match'))).toBe(true);
    });

    it('fails audit when declared total liability is wrong', () => {
      const { root } = validator.computeRoot(SAMPLE_LEAVES);
      const report = validator.audit(SAMPLE_LEAVES, root, 9999999n);
      expect(report.valid).toBe(false);
      expect(report.findings.some((f) => f.message.includes('liability'))).toBe(true);
    });

    it('passes audit with correct total liability declared', () => {
      const { root, totalLiability } = validator.computeRoot(SAMPLE_LEAVES);
      const report = validator.audit(SAMPLE_LEAVES, root, totalLiability);
      expect(report.valid).toBe(true);
    });
  });

  describe('poseidon mode (double-sha256 approximation)', () => {
    it('computes different roots with poseidon vs sha256', () => {
      const sha = new MerkleReserveValidator('sha256');
      const pos = new MerkleReserveValidator('poseidon');
      const { root: r1 } = sha.computeRoot(SAMPLE_LEAVES);
      const { root: r2 } = pos.computeRoot(SAMPLE_LEAVES);
      expect(r1).not.toBe(r2);
    });

    it('round-trips inclusion proofs with poseidon mode', () => {
      const pos = new MerkleReserveValidator('poseidon');
      const { leafHashes } = pos.computeRoot(SAMPLE_LEAVES);
      const proof = pos.generateProof(leafHashes, 1);
      expect(pos.verifyProof(proof)).toBe(true);
    });
  });

  describe('auditToml', () => {
    it('returns no diagnostics for a toml with no proof-of-reserve section', () => {
      const diagnostics = validator.auditToml({ DOCUMENTATION: { ORG_NAME: 'Test' } });
      expect(diagnostics).toHaveLength(0);
    });

    it('warns when merkle_root is declared without leaves', () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PROOF_OF_RESERVE: { merkle_root: 'a'.repeat(64) },
        },
      };
      const diagnostics = validator.auditToml(doc);
      expect(diagnostics.length).toBeGreaterThan(0);
      expect(diagnostics[0]!.severity).toBe('warning');
    });

    it('reports invalid root in diagnostics', () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PROOF_OF_RESERVE: {
            merkle_root: '0'.repeat(64),
            leaves: SAMPLE_LEAVES,
          },
        },
      };
      const diagnostics = validator.auditToml(doc);
      expect(diagnostics.length).toBeGreaterThan(0);
      expect(diagnostics.some((d) => d.rule === MERKLE_INVALID_ROOT)).toBe(true);
    });

    it('passes clean toml with matching root', () => {
      const { root } = validator.computeRoot(SAMPLE_LEAVES);
      const doc = {
        DOCUMENTATION: {
          ORG_PROOF_OF_RESERVE: { merkle_root: root, leaves: SAMPLE_LEAVES },
        },
      };
      const diagnostics = validator.auditToml(doc);
      expect(diagnostics).toHaveLength(0);
    });
  });
});
