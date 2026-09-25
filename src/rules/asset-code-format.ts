import type { Rule, RuleContext } from '../types.js';
import { specUrl } from '../spec.js';

const INVALID_FORMAT_RULE = 'currencies/invalid-asset-code-format';
const TOO_LONG_RULE = 'currencies/asset-code-too-long';
const MAX_ASSET_CODE_LENGTH = 12;
const ASSET_CODE_PATTERN = /^[a-zA-Z0-9]+$/;

function eachCurrency(
  ctx: RuleContext,
  visit: (entry: Record<string, unknown>, path: string) => void,
): void {
  const currencies = ctx.doc.CURRENCIES;
  if (!Array.isArray(currencies)) return;

  currencies.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    if (entry.toml !== undefined) return;
    visit(entry, `CURRENCIES[${index}]`);
  });
}

function isNativeAsset(entry: Record<string, unknown>): boolean {
  return typeof entry.code === 'string' && entry.code.toLowerCase() === 'xlm';
}

function report(
  ctx: RuleContext,
  rule: string,
  path: string,
  message: string,
  suggestion: string,
): void {
  ctx.report({
    rule,
    category: 'currencies',
    message,
    path,
    position: ctx.locate(path),
    helpUri: specUrl('currency-documentation'),
    suggestion,
  });
}

export const assetCodeFormatRules: Rule[] = [
  {
    id: TOO_LONG_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'Stellar asset codes must be 1 to 12 characters long',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const code = entry.code;
        if (
          typeof code !== 'string' ||
          isNativeAsset(entry) ||
          code.length <= MAX_ASSET_CODE_LENGTH
        ) {
          return;
        }

        report(
          ctx,
          TOO_LONG_RULE,
          `${path}.code`,
          `${path}.code is ${code.length} characters; Stellar asset codes must be 12 characters or fewer`,
          'Shorten the asset code to 12 characters or fewer.',
        );
      });
    },
  },
  {
    id: INVALID_FORMAT_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'Stellar asset codes must contain only alphanumeric ASCII characters',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const code = entry.code;
        if (typeof code !== 'string' || isNativeAsset(entry) || ASSET_CODE_PATTERN.test(code)) {
          return;
        }

        report(
          ctx,
          INVALID_FORMAT_RULE,
          `${path}.code`,
          `${path}.code "${code}" contains characters that are not valid in a Stellar asset code`,
          'Use 1 to 12 alphanumeric ASCII characters for the asset code.',
        );
      });
    },
  },
];
