import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';

const duplicateConfig = `
[[VALIDATORS]]
PUBLIC_KEY = "key-a"
HOST = "one.example.com:11625"
ALIAS = "one"

[[VALIDATORS]]
PUBLIC_KEY = "key-a"
HOST = "one.example.com:11625"
ALIAS = "one"
`;

describe('validator deduplication rules', () => {
  it('reports duplicate public keys, hosts, and aliases with the required severities', () => {
    const result = lint(duplicateConfig);
    const diagnostics = result.diagnostics.filter((diagnostic) =>
      diagnostic.rule.startsWith('validators/duplicate-'),
    );

    expect(diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule: 'validators/duplicate-public-key',
          severity: 'error',
          path: 'VALIDATORS[1].PUBLIC_KEY',
        }),
        expect.objectContaining({
          rule: 'validators/duplicate-host',
          severity: 'warning',
          path: 'VALIDATORS[1].HOST',
        }),
        expect.objectContaining({
          rule: 'validators/duplicate-alias',
          severity: 'warning',
          path: 'VALIDATORS[1].ALIAS',
        }),
      ]),
    );
    expect(diagnostics).toHaveLength(3);
  });

  it('reports each repeated value after its first occurrence', () => {
    const result = lint(`${duplicateConfig}
[[VALIDATORS]]
PUBLIC_KEY = "key-a"
HOST = "one.example.com:11625"
ALIAS = "one"
`);

    for (const rule of [
      'validators/duplicate-public-key',
      'validators/duplicate-host',
      'validators/duplicate-alias',
    ]) {
      expect(result.diagnostics.filter((diagnostic) => diagnostic.rule === rule)).toHaveLength(2);
    }
  });

  it('does not report unique validator values', () => {
    const result = lint(`
[[VALIDATORS]]
PUBLIC_KEY = "key-a"
HOST = "one.example.com:11625"
ALIAS = "one"

[[VALIDATORS]]
PUBLIC_KEY = "key-b"
HOST = "two.example.com:11625"
ALIAS = "two"
`);

    expect(
      result.diagnostics.filter((diagnostic) =>
        diagnostic.rule.startsWith('validators/duplicate-'),
      ),
    ).toEqual([]);
  });
});
