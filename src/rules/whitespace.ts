import type { Rule, RuleContext } from '../types.js';
import { specUrl } from '../spec.js';

const UNTRIMMED_STRING_VALUE_RULE = 'general/untrimmed-string-value';

function walkStrings(
  obj: unknown,
  path: string,
  visit: (value: string, currentPath: string) => void,
): void {
  if (typeof obj === 'string') {
    visit(obj, path);
    return;
  }
  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      const currentPath = path ? `${path}[${index}]` : `[${index}]`;
      walkStrings(item, currentPath, visit);
    });
    return;
  }
  if (typeof obj === 'object' && obj !== null) {
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      walkStrings(value, currentPath, visit);
    }
  }
}

export const whitespaceRules: Rule[] = [
  {
    id: UNTRIMMED_STRING_VALUE_RULE,
    category: 'general',
    severity: 'warning',
    description: 'String values should not contain leading or trailing whitespace',
    run(ctx: RuleContext) {
      walkStrings(ctx.doc, '', (val, path) => {
        if (/^\s+|\s+$/.test(val)) {
          const trimmed = val.trim();
          ctx.report({
            rule: UNTRIMMED_STRING_VALUE_RULE,
            category: 'general',
            severity: 'warning',
            message: `${path} has leading or trailing whitespace`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('general-information'),
            suggestion: `Trim whitespace from "${val}" to "${trimmed}".`,
            fix: { value: trimmed },
          });
        }
      });
    },
  },
];
