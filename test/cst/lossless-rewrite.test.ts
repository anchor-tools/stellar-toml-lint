import { describe, expect, it } from 'vitest';
import {
  COMMENT_LOSS_RULE,
  LosslessRewriter,
  countComments,
  detectCommentLoss,
  evaluateRewritten,
  rewrite,
} from '../../src/cst/lossless-rewrite.js';

const SOURCE = [
  '# top of file',
  'VERSION = "2.7.0"  # pinned release',
  '[DOCUMENTATION]',
  'ORG_NAME = "Example"   # keep this comment',
  '# note above url',
  'ORG_URL = "https://example.com"',
  '',
].join('\n');

describe('countComments', () => {
  it('counts hash comment tokens, not hashes inside strings', () => {
    expect(countComments(SOURCE)).toBe(4);
    expect(countComments('')).toBe(0);
    expect(countComments('URL = "https://x.example/#fragment"\n')).toBe(0);
  });
});

describe('rewrite', () => {
  it('serializes an untouched document byte-for-byte', () => {
    const result = rewrite(SOURCE, () => {});

    expect(result.source).toBe(SOURCE);
    expect(result.edits).toEqual([]);
    expect(result.diagnostics).toEqual([]);
  });

  it('replaces a value and keeps every byte outside it', () => {
    const result = rewrite(SOURCE, (rewriter) => {
      expect(rewriter.replaceNode('DOCUMENTATION.ORG_NAME', '"Renamed"')).toBe(true);
    });

    expect(result.source).toContain('ORG_NAME = "Renamed"   # keep this comment');
    expect(result.source).toContain('# top of file');
    expect(result.source).toContain('# note above url');
    expect(result.source).not.toContain('"Example"');
    expect(countComments(result.source)).toBe(countComments(SOURCE));
    expect(result.diagnostics).toEqual([]);

    const doc = evaluateRewritten(result);
    const documentation = doc.DOCUMENTATION as Record<string, unknown>;
    expect(documentation.ORG_NAME).toBe('Renamed');
  });

  it('deletes an assignment while keeping its comments', () => {
    const result = rewrite(SOURCE, (rewriter) => {
      expect(rewriter.deleteNode('DOCUMENTATION.ORG_URL')).toBe(true);
    });

    expect(result.source).not.toContain('ORG_URL = "https://example.com"');
    expect(result.source).toContain('# note above url');
    expect(countComments(result.source)).toBe(countComments(SOURCE));
    expect(result.diagnostics).toEqual([]);

    const doc = evaluateRewritten(result);
    const documentation = doc.DOCUMENTATION as Record<string, unknown>;
    expect(documentation.ORG_URL).toBeUndefined();
    expect(documentation.ORG_NAME).toBe('Example');
  });

  it('inserts a line after an entry without disturbing the line', () => {
    const result = rewrite(SOURCE, (rewriter) => {
      expect(
        rewriter.insertAfter(
          'VERSION',
          'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
        ),
      ).toBe(true);
    });

    expect(result.source).toContain(
      'VERSION = "2.7.0"  # pinned release\nNETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
    );
    expect(result.source).toContain('[DOCUMENTATION]');
    expect(countComments(result.source)).toBe(countComments(SOURCE));
    expect(result.diagnostics).toEqual([]);
  });

  it('refuses an overlapping mutation instead of corrupting the file', () => {
    const rewriter = new LosslessRewriter(SOURCE);

    expect(rewriter.replaceNode('DOCUMENTATION.ORG_NAME', '"First"')).toBe(true);
    expect(rewriter.replaceNode('DOCUMENTATION.ORG_NAME', '"Second"')).toBe(false);

    const result = rewriter.serialize();
    expect(result.source).toContain('ORG_NAME = "First"');
    expect(result.source).not.toContain('"Second"');
  });

  it('refuses paths that do not resolve to a key-value entry', () => {
    const rewriter = new LosslessRewriter(SOURCE);

    expect(rewriter.replaceNode('NOPE.MISSING', '"x"')).toBe(false);
    expect(rewriter.deleteNode('NOPE.MISSING')).toBe(false);
    expect(rewriter.insertAfter('NOPE.MISSING', 'X = 1')).toBe(false);
    // A table header is an entry, but not a key-value one.
    expect(rewriter.replaceNode('DOCUMENTATION', '"x"')).toBe(false);
    expect(rewriter.deleteNode('DOCUMENTATION')).toBe(false);
  });
});

describe('detectCommentLoss', () => {
  it('reports a dropped comment with the cst/comment-loss rule', () => {
    const before = '# one\nA = 1  # two\n';
    const after = '# one\nA = 1\n';

    const loss = detectCommentLoss(before, after);
    expect(loss).toBeDefined();
    expect(loss?.rule).toBe(COMMENT_LOSS_RULE);
    expect(loss?.severity).toBe('error');
    expect(loss?.category).toBe('file');
    expect(loss?.message).toContain('dropped 1 of 2 comments');
    expect(loss?.suggestion).toContain('bug');
  });

  it('returns undefined when every comment survives', () => {
    const before = '# one\nA = 1  # two\n';

    expect(detectCommentLoss(before, '# one\nA = 2  # two\n')).toBeUndefined();
  });

  it('returns undefined when the rewrite adds comments', () => {
    expect(detectCommentLoss('A = 1\n', '# added\nA = 1\n')).toBeUndefined();
  });

  it('returns undefined when there were no comments at all', () => {
    expect(detectCommentLoss('A = 1\n', 'A = 2\n')).toBeUndefined();
  });
});
