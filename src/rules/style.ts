import type { Rule } from '../types.js';
import { auditIndentation } from '../cst/indentation.js';

/**
 * Style rules for indentation (#303).
 *
 * Both rules read the parsed CST rather than the decoded document, because
 * indentation lives in trivia the value tree has already discarded. They are
 * advisory (`warning`) and never block a run, and neither carries a `fix`:
 * reindenting a file is a document-wide rewrite, which belongs to
 * `--format-style` and its `normalizeIndentation`, not to a single-value edit.
 *
 * The rules stay silent on a document whose indentation is consistent, so an
 * already-clean file reports nothing and a second `--format-style` run is a
 * no-op.
 */
export const styleRules: Rule[] = [
  {
    id: 'style/mixed-indentation',
    category: 'style',
    severity: 'warning',
    description: 'Indentation should use tabs or spaces consistently, never both',
    run(ctx) {
      for (const finding of auditIndentation(ctx.source, ctx.cst)) {
        if (finding.rule !== 'style/mixed-indentation') continue;
        ctx.report({
          rule: 'style/mixed-indentation',
          category: 'style',
          message: finding.message,
          position: finding.position,
          helpUri: 'https://toml.io/en/v1.0.0#keys',
          suggestion: finding.suggestion,
        });
      }
    },
  },

  {
    id: 'style/misaligned-table-key',
    category: 'style',
    severity: 'warning',
    description: 'Nested table headers and key-value assignments should line up',
    run(ctx) {
      for (const finding of auditIndentation(ctx.source, ctx.cst)) {
        if (finding.rule !== 'style/misaligned-table-key') continue;
        ctx.report({
          rule: 'style/misaligned-table-key',
          category: 'style',
          message: finding.message,
          position: finding.position,
          helpUri: 'https://toml.io/en/v1.0.0#keys',
          suggestion: finding.suggestion,
        });
      }
    },
  },
];
