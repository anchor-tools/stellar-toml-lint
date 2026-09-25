import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { formatNdjson } from '../src/reporters.js';

const BROKEN = 'VERSION="two"\nSIGNING_KEY="nope"\n';

describe('formatNdjson', () => {
  it('emits one JSON object per line, ending with a summary', () => {
    const result = lint(BROKEN);
    const output = formatNdjson(result, 'stellar.toml');
    const lines = output.trim().split('\n');

    expect(lines.length).toBeGreaterThan(1);

    for (let i = 0; i < lines.length - 1; i++) {
      const parsed = JSON.parse(lines[i] as string);
      expect(parsed.type).toBe('diagnostic');
      expect(parsed.file).toBe('stellar.toml');
      expect(parsed.rule).toBeDefined();
      expect(parsed.severity).toBeDefined();
      expect(parsed.message).toBeDefined();
    }

    const summary = JSON.parse(lines[lines.length - 1] as string);
    expect(summary.type).toBe('summary');
    expect(summary.file).toBe('stellar.toml');
    expect(summary.ok).toBe(false);
    expect(summary.counts).toBeDefined();
  });
});
