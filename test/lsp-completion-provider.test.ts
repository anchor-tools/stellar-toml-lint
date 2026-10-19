import { describe, expect, it } from 'vitest';
import { getCompletionItems } from '../src/lsp/completion-provider.js';

describe('getCompletionItems', () => {
  it('suggests current currency fields with docs and excludes declared keys', () => {
    const source = ['[[CURRENCIES]]', 'code = "USDC"', ''].join('\n');
    const result = getCompletionItems(source, { line: 2, character: 0 });

    expect(result.isIncomplete).toBe(false);
    expect(result.items.map((item) => item.label)).toContain('issuer');
    expect(result.items.map((item) => item.label)).not.toContain('code');
    expect(result.items.find((item) => item.label === 'issuer')?.documentation.value).toContain(
      'Currency Documentation',
    );
  });

  it('offers named templates at the document root', () => {
    const result = getCompletionItems('', { line: 0, character: 0 });

    expect(result.items.map((item) => item.label)).toEqual(
      expect.arrayContaining(['new-currency-anchored', 'new-validator-node', 'new-contract-sac']),
    );
    expect(result.items.find((item) => item.label === 'new-contract-sac')?.insertText).toContain(
      'contract =',
    );
  });
});
