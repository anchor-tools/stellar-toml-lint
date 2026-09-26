import type { Rule, RuleContext } from '../types.js';
import { specUrl } from '../spec.js';

export const INVALID_SIGNATURE_ENCODING_RULE = 'currencies/invalid-signature-encoding';
export const INVALID_SIGNATURE_LENGTH_RULE = 'currencies/invalid-signature-length';

const ED25519_SIGNATURE_BYTE_LENGTH = 64;

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

function isValidBase64(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) return false;
  try {
    atob(trimmed);
    return true;
  } catch {
    return false;
  }
}

function decodeBase64(value: string): Uint8Array | null {
  const trimmed = value.trim();
  if (!isValidBase64(trimmed)) return null;
  try {
    const binary = atob(trimmed);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

export const collateralSigFormatRules: Rule[] = [
  {
    id: INVALID_SIGNATURE_ENCODING_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'Each collateral_address_signatures entry must be a valid base64-encoded string',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const signatures = entry.collateral_address_signatures;
        if (!Array.isArray(signatures)) return;

        signatures.forEach((sig, index) => {
          if (typeof sig !== 'string') return;
          if (!isValidBase64(sig)) {
            ctx.report({
              rule: INVALID_SIGNATURE_ENCODING_RULE,
              category: 'currencies',
              severity: 'error',
              message: `${path}.collateral_address_signatures[${index}] is not a valid base64 string`,
              path: `${path}.collateral_address_signatures`,
              position: ctx.locate(`${path}.collateral_address_signatures`),
              helpUri: specUrl('currency-documentation'),
              suggestion:
                'Encode the signature using standard base64 characters with valid padding.',
            });
          }
        });
      });
    },
  },
  {
    id: INVALID_SIGNATURE_LENGTH_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'Each collateral_address_signatures entry must decode to exactly 64 bytes',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const signatures = entry.collateral_address_signatures;
        if (!Array.isArray(signatures)) return;

        signatures.forEach((sig, index) => {
          if (typeof sig !== 'string') return;
          const bytes = decodeBase64(sig);
          if (!bytes) return; // Non-base64 is handled by INVALID_SIGNATURE_ENCODING_RULE
          if (bytes.length !== ED25519_SIGNATURE_BYTE_LENGTH) {
            ctx.report({
              rule: INVALID_SIGNATURE_LENGTH_RULE,
              category: 'currencies',
              severity: 'error',
              message: `${path}.collateral_address_signatures[${index}] decodes to ${bytes.length} bytes; Ed25519 signatures must be exactly 64 bytes`,
              path: `${path}.collateral_address_signatures`,
              position: ctx.locate(`${path}.collateral_address_signatures`),
              helpUri: specUrl('currency-documentation'),
              suggestion: 'Provide a valid 64-byte Ed25519 signature.',
            });
          }
        });
      });
    },
  },
];
