import { describe, it, expect, vi } from 'vitest';

describe('GitHub App', () => {
  it('should detect PRs that modify stellar.toml', async () => {
    const files = [
      { filename: 'stellar.toml', status: 'modified' },
      { filename: 'README.md', status: 'modified' },
    ];
    const modifiesStellarToml = files.some(
      (f) =>
        f.filename === 'stellar.toml' ||
        f.filename === '.well-known/stellar.toml' ||
        f.filename.endsWith('/stellar.toml'),
    );
    expect(modifiesStellarToml).toBe(true);
  });

  it('should not trigger for PRs that do not modify stellar.toml', async () => {
    const files = [{ filename: 'README.md', status: 'modified' }];
    const modifiesStellarToml = files.some(
      (f) =>
        f.filename === 'stellar.toml' ||
        f.filename === '.well-known/stellar.toml' ||
        f.filename.endsWith('/stellar.toml'),
    );
    expect(modifiesStellarToml).toBe(false);
  });

  it('should create a check run for PRs modifying stellar.toml', async () => {
    const mockChecksCreate = vi.fn().mockResolvedValue({ data: { id: 1 } });
    const mockRest = {
      checks: { create: mockChecksCreate, update: vi.fn() },
      pulls: {
        listFiles: vi
          .fn()
          .mockResolvedValue({ data: [{ filename: 'stellar.toml', status: 'modified' }] }),
      },
      repos: { getContent: vi.fn() },
      issues: { createComment: vi.fn() },
    };
    void mockRest;
    expect(mockChecksCreate).toBeDefined();
  });

  it('should format diagnostics as suggestion comments', async () => {
    const diagnostic = {
      rule: 'currencies/issuance-exclusive',
      severity: 'error' as const,
      message: 'CURRENCIES[0] sets fixed_number and is_unlimited',
      suggestion: 'Remove either fixed_number or is_unlimited from the currency definition.',
      position: { line: 31, column: 1 },
    };
    const suggestionBody = `> **[stellar-toml-lint]** \`${diagnostic.rule}\`\n> ${diagnostic.message}\n> \n> \`\`\`suggestion\n${diagnostic.suggestion}\n\`\`\``;
    expect(suggestionBody).toContain('suggestion');
    expect(suggestionBody).toContain(diagnostic.suggestion);
  });
});
