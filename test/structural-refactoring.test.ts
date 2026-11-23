import { describe, expect, it } from 'vitest';
import {
  StructuralRefactoringEngine,
  deduplicateAssets,
  diffText,
  renderRefactorSummary,
  splitLargeFile,
} from '../src/cst/structuralRefactoring.js';

const ISSUER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB';

const DUPLICATED = `VERSION = "2"

# canonical USD declaration
[[CURRENCIES]]
code = "USD"
issuer = "${ISSUER}"
name = "US Dollar" # primary name
display_decimals = 2

# second declaration of the same asset
[[CURRENCIES]]
code = "USD"
issuer = "${ISSUER}"
# fixed supply note
fixed_number = "100"
name = "US Dollar Backup"

[DOCUMENTATION]
ORG_NAME = "Anchor"
`;

describe('structural refactoring engine', () => {
  it('deduplicates assets, keeps comments and reports conflicts', () => {
    const result = deduplicateAssets(DUPLICATED);
    expect(result.groups).toHaveLength(1);
    expect(result.duplicateCount).toBe(1);
    expect(result.validation.ok).toBe(true);
    expect(result.validation.originalCurrencies).toBe(2);
    expect(result.validation.refactoredCurrencies).toBe(1);
    expect(result.validation.errors).toEqual([]);

    const group = result.groups[0];
    expect(group?.code).toBe('USD');
    expect(group?.conflicts).toHaveLength(1);
    expect(group?.conflicts[0]).toMatchObject({
      field: 'name',
      kept: 'US Dollar',
      discarded: 'US Dollar Backup',
    });
    expect(group?.commentsRetained).toBe(2);

    expect(result.source).toContain('# canonical USD declaration');
    expect(result.source).toContain('# second declaration of the same asset');
    expect(result.source).toContain('# fixed supply note');
    expect(result.source).toContain('# primary name');
    expect(result.source).toContain('# refactor: conflict for name');
    expect(result.source).toContain('fixed_number = "100"');
    expect(result.source).toContain('name = "US Dollar" # primary name');
    expect(result.source).not.toContain('name = "US Dollar Backup"');
    expect(result.source).toContain('[DOCUMENTATION]');
  });

  it('produces a reviewable diff', () => {
    const result = deduplicateAssets(DUPLICATED);
    expect(result.diff).toContain('--- original');
    expect(result.diff).toContain('+++ refactored');
    expect(result.diff).toContain('-[[CURRENCIES]]');
    expect(result.diff).toContain('+# refactor: conflict');
  });

  it('renders a summary', () => {
    const summary = renderRefactorSummary(deduplicateAssets(DUPLICATED));
    expect(summary).toContain('Duplicates removed: 1');
    expect(summary).toContain('Validation: passed (zero data loss)');
    expect(summary).toContain('USD /');
    expect(summary).toContain('1 conflict(s)');
  });

  it('handles files with no duplicates without changing them', () => {
    const source = `VERSION = "2"\n\n[[CURRENCIES]]\ncode = "EUR"\nissuer = "${ISSUER}"\n`;
    const result = deduplicateAssets(source);
    expect(result.groups).toEqual([]);
    expect(result.duplicateCount).toBe(0);
    expect(result.source).toBe(source);
    expect(result.diff).toContain('(no changes)');
    expect(result.validation.ok).toBe(true);
  });

  it('keeps non-conflicting metadata from both declarations', () => {
    const source = `[[CURRENCIES]]
code = "XLM"
issuer = "${ISSUER}"
name = "Lumen"

[[CURRENCIES]]
code = "XLM"
issuer = "${ISSUER}"
display_decimals = 7
`;
    const result = deduplicateAssets(source);
    expect(result.groups[0]?.conflicts).toEqual([]);
    expect(result.source).toContain('name = "Lumen"');
    expect(result.source).toContain('display_decimals = 7');
    expect(result.validation.ok).toBe(true);
  });

  it('splits large files into modular partials with no data loss', () => {
    const result = splitLargeFile(DUPLICATED, { maxBytes: 120, baseName: 'anchor' });
    expect(result.files.length).toBeGreaterThan(1);
    expect(result.validation.ok).toBe(true);
    expect(result.validation.errors).toEqual([]);
    expect(result.files.every((file) => file.name.startsWith('anchor.'))).toBe(true);
    const combined = result.files.map((file) => file.source).join('\n');
    expect(combined).toContain('code = "USD"');
    expect(combined).toContain('[DOCUMENTATION]');
  });

  it('exposes the same operations through the engine facade', () => {
    const engine = new StructuralRefactoringEngine(DUPLICATED);
    const result = engine.deduplicateAssets();
    expect(result.source).toBe(deduplicateAssets(DUPLICATED).source);
    expect(engine.diff(result.source)).toBe(diffText(DUPLICATED, result.source));
    expect(engine.split().files.length).toBeGreaterThan(0);
  });
});
