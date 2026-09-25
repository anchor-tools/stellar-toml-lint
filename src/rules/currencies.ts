import type { Rule, RuleContext } from '../types.js';
import { displayDecimalsRules } from './display-decimals-audit.js';
import { anchoredAssetRules } from './anchored-asset-rules.js';
import { assetCodeFormatRules } from './asset-code-format.js';
import {
  ANCHOR_ASSET_TYPES,
  CURRENCY_STATUSES,
  ISSUANCE_FIELDS,
  KNOWN_CURRENCY_FIELDS,
  specUrl,
} from '../spec.js';
import {
  isAccountId,
  isBoolean,
  isContractId,
  isHttpsUrl,
  isInteger,
  isString,
  isStringArray,
  isUrl,
} from '../predicates.js';

/** Reads `[[CURRENCIES]]` as a list of tables, ignoring malformed entries. */
export function currenciesOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = doc.CURRENCIES;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

/**
 * A `[[CURRENCIES]]` entry may instead be a single `toml` pointer to a separate
 * per-currency file. Those entries are exempt from the field rules, since the
 * real definition lives elsewhere.
 */
export function isTomlPointer(entry: Record<string, unknown>): boolean {
  return entry.toml !== undefined;
}

/**
 * True for the entry describing XLM, the network's native asset.
 *
 * XLM has no issuing account and its supply is set by the protocol rather than
 * by the party publishing the file, so the issuer and issuance-policy rules do
 * not apply. `code="native"` is the convention the Stellar SDKs and the SDF's
 * own reference anchor use; `XLM` with no issuer means the same thing.
 */
function isNativeAsset(entry: Record<string, unknown>): boolean {
  if (!isString(entry.code)) return false;
  const code = entry.code.toLowerCase();
  if (code === 'native') return true;
  return code === 'xlm' && entry.issuer === undefined && entry.contract === undefined;
}

/** Iterates the real (non-pointer) currency entries with their indices. */
function eachCurrency(
  ctx: RuleContext,
  visit: (entry: Record<string, unknown>, path: string, index: number) => void,
): void {
  currenciesOf(ctx.doc).forEach((entry, i) => {
    if (isTomlPointer(entry)) return;
    visit(entry, `CURRENCIES[${i}]`, i);
  });
} /**
 * The Soroban contract ids declared in `[[CURRENCIES]]`, with the path each
 * came from, for network checks. Native assets and `toml` pointers are not
 * contracts this file owns, so they are skipped.
 */
export function contractIdsOf(doc: Record<string, unknown>): { id: string; path: string }[] {
  const contracts: { id: string; path: string }[] = [];
  currenciesOf(doc).forEach((entry, index) => {
    if (isTomlPointer(entry) || isNativeAsset(entry)) return;
    if (isString(entry.contract) && isContractId(entry.contract)) {
      contracts.push({ id: entry.contract, path: `CURRENCIES[${index}].contract` });
    }
  });
  return contracts;
}

/** Rules covering the `[[CURRENCIES]]` list. */
export const currencyRules: Rule[] = [
  ...displayDecimalsRules,

  ...anchoredAssetRules,
  ...assetCodeFormatRules,

  {
    id: 'currencies/entries-are-tables',
    category: 'currencies',
    severity: 'error',
    description: 'CURRENCIES must be a list of tables',
    run(ctx) {
      const list = ctx.doc.CURRENCIES;
      if (list === undefined) return;

      if (!Array.isArray(list)) {
        ctx.report({
          rule: 'currencies/entries-are-tables',
          category: 'currencies',
          message: 'CURRENCIES must be a list of tables, written as [[CURRENCIES]]',
          path: 'CURRENCIES',
          position: ctx.locate('CURRENCIES'),
          helpUri: specUrl('currency-documentation'),
        });
        return;
      }

      list.forEach((entry, i) => {
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          ctx.report({
            rule: 'currencies/entries-are-tables',
            category: 'currencies',
            message: `CURRENCIES[${i}] must be a table`,
            path: `CURRENCIES[${i}]`,
            position: ctx.locate(`CURRENCIES[${i}]`),
            helpUri: specUrl('currency-documentation'),
          });
        }
      });
    },
  },

  {
    id: 'currencies/code',
    category: 'currencies',
    severity: 'error',
    description: 'Each currency needs a code or code_template',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const code = entry.code;
        const template = entry.code_template;

        if (code === undefined && template === undefined) {
          ctx.report({
            rule: 'currencies/code',
            category: 'currencies',
            message: `${path} is missing the required code field`,
            path: `${path}.code`,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Add code="USD", or code_template for a family of assets.',
          });
          return;
        }

        for (const [field, value] of [
          ['code', code],
          ['code_template', template],
        ] as const) {
          if (value === undefined) continue;
          if (!isString(value)) {
            ctx.report({
              rule: 'currencies/code',
              category: 'currencies',
              message: `${path}.${field} must be a string`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
            });
          } else if (field === 'code_template' && value.length > 12) {
            ctx.report({
              rule: 'currencies/code',
              category: 'currencies',
              message: `${path}.${field} is ${value.length} characters; the maximum is 12`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
            });
          }
        }

        if (isString(template) && !template.includes('?')) {
          ctx.report({
            rule: 'currencies/code',
            category: 'currencies',
            severity: 'warning',
            message: `${path}.code_template has no ? wildcard, so it matches only one code`,
            path: `${path}.code_template`,
            position: ctx.locate(`${path}.code_template`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Use code instead, or add ? wildcards such as "CORN????????".',
          });
        }
      });
    },
  },

  {
    id: 'currencies/issuer-or-contract',
    category: 'currencies',
    severity: 'error',
    description:
      'A currency needs exactly one of issuer (Stellar asset) or contract (SEP-41 token)',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const hasIssuer = entry.issuer !== undefined;
        const hasContract = entry.contract !== undefined;

        if (isNativeAsset(entry)) {
          // XLM has no issuing account. Declaring one is the actual mistake.
          if (hasIssuer || hasContract) {
            ctx.report({
              rule: 'currencies/issuer-or-contract',
              category: 'currencies',
              message: `${path} describes the native asset, which has no issuer or contract`,
              path,
              position: ctx.locate(path),
              helpUri: specUrl('currency-documentation'),
              suggestion: 'Remove the issuer and contract fields from the native XLM entry.',
            });
          }
          return;
        }

        if (!hasIssuer && !hasContract) {
          ctx.report({
            rule: 'currencies/issuer-or-contract',
            category: 'currencies',
            message: `${path} has neither issuer nor contract, so the token cannot be identified`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion:
              'Add issuer="G..." for a Stellar asset, or contract="C..." for a SEP-41 token.',
          });
          return;
        }

        if (hasIssuer && hasContract) {
          ctx.report({
            rule: 'currencies/issuer-or-contract',
            category: 'currencies',
            message: `${path} sets both issuer and contract, but they are mutually exclusive`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion:
              'Keep issuer for a Stellar asset, or contract for a custom token — not both.',
          });
        }

        if (hasIssuer && !isAccountId(entry.issuer)) {
          ctx.report({
            rule: 'currencies/issuer-or-contract',
            category: 'currencies',
            message: `${path}.issuer is not a valid Stellar account ID`,
            path: `${path}.issuer`,
            position: ctx.locate(`${path}.issuer`),
            helpUri: specUrl('currency-documentation'),
            suggestion: isContractId(entry.issuer)
              ? 'This is a contract ID — use the contract field instead.'
              : 'Check for a transcription error — the checksum does not match.',
          });
        }

        if (hasContract && !isContractId(entry.contract)) {
          ctx.report({
            rule: 'currencies/issuer-or-contract',
            category: 'currencies',
            message: `${path}.contract is not a valid Stellar contract ID`,
            path: `${path}.contract`,
            position: ctx.locate(`${path}.contract`),
            helpUri: specUrl('currency-documentation'),
            suggestion: isAccountId(entry.contract)
              ? 'This is an account ID — use the issuer field instead.'
              : 'Contract IDs start with C and are 56 characters long.',
          });
        }
      });
    },
  },

  {
    id: 'currencies/issuance-exclusive',
    category: 'currencies',
    severity: 'error',
    description: 'Include exactly one of fixed_number, max_number, or is_unlimited',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        // The native asset's supply is a protocol property, not an issuer policy.
        if (isNativeAsset(entry)) return;

        const present = ISSUANCE_FIELDS.filter((field) => entry[field] !== undefined);

        if (present.length > 1) {
          ctx.report({
            rule: 'currencies/issuance-exclusive',
            category: 'currencies',
            message: `${path} sets ${present.join(' and ')}, but these issuance policies are mutually exclusive`,
            path: `${path}.${present[0]}`,
            position: ctx.locate(`${path}.${present[0]}`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'SEP-1 requires exactly one of fixed_number, max_number, or is_unlimited.',
          });
        } else if (present.length === 0) {
          ctx.report({
            rule: 'currencies/issuance-exclusive',
            category: 'currencies',
            severity: 'warning',
            message: `${path} declares no issuance policy`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion:
              'Add one of fixed_number, max_number, or is_unlimited so holders know the supply model.',
          });
        }

        // Type-check whichever policy field is present.
        for (const field of ['fixed_number', 'max_number'] as const) {
          const value = entry[field];
          if (value === undefined) continue;
          if (!isInteger(value)) {
            ctx.report({
              rule: 'currencies/issuance-exclusive',
              category: 'currencies',
              message: `${path}.${field} must be an integer`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
            });
          } else if (value < 0) {
            ctx.report({
              rule: 'currencies/issuance-exclusive',
              category: 'currencies',
              message: `${path}.${field} must not be negative`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
            });
          }
        }

        if (entry.is_unlimited !== undefined && !isBoolean(entry.is_unlimited)) {
          ctx.report({
            rule: 'currencies/issuance-exclusive',
            category: 'currencies',
            message: `${path}.is_unlimited must be a boolean`,
            path: `${path}.is_unlimited`,
            position: ctx.locate(`${path}.is_unlimited`),
            helpUri: specUrl('currency-documentation'),
          });
        }
      });
    },
  },

  {
    id: 'currencies/enums',
    category: 'currencies',
    severity: 'error',
    description: 'status and anchor_asset_type must use the values SEP-1 defines',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const status = entry.status;
        if (status !== undefined && !CURRENCY_STATUSES.includes(status as never)) {
          ctx.report({
            rule: 'currencies/enums',
            category: 'currencies',
            message: `${path}.status must be one of ${CURRENCY_STATUSES.join(', ')}`,
            path: `${path}.status`,
            position: ctx.locate(`${path}.status`),
            helpUri: specUrl('currency-documentation'),
          });
        }

        const type = entry.anchor_asset_type;
        if (type !== undefined && !ANCHOR_ASSET_TYPES.includes(type as never)) {
          ctx.report({
            rule: 'currencies/enums',
            category: 'currencies',
            message: `${path}.anchor_asset_type must be one of ${ANCHOR_ASSET_TYPES.join(', ')}`,
            path: `${path}.anchor_asset_type`,
            position: ctx.locate(`${path}.anchor_asset_type`),
            helpUri: specUrl('currency-documentation'),
          });
        }
      });
    },
  },

  {
    id: 'currencies/display-decimals',
    category: 'currencies',
    severity: 'error',
    description:
      'display_decimals must be an integer from 0 to 7, and has no meaning on the native asset',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const value = entry.display_decimals;
        if (value === undefined) return;

        // XLM's scale is fixed at 7 decimals by the protocol; no issuer can
        // override it, so a value here is meaningless and can mislead wallets
        // into rendering the native asset at the wrong scale.
        if (isNativeAsset(entry)) {
          ctx.report({
            rule: 'currencies/display-decimals',
            category: 'currencies',
            severity: 'info',
            message: `${path} sets display_decimals on the native asset, but the protocol fixes XLM at 7 decimals`,
            path: `${path}.display_decimals`,
            position: ctx.locate(`${path}.display_decimals`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Remove display_decimals from the native XLM entry.',
          });
        }

        if (!isInteger(value) || value < 0 || value > 7) {
          ctx.report({
            rule: 'currencies/display-decimals',
            category: 'currencies',
            message: `${path}.display_decimals must be an integer from 0 to 7`,
            path: `${path}.display_decimals`,
            position: ctx.locate(`${path}.display_decimals`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Stellar amounts carry at most 7 decimal places.',
          });
        }
      });
    },
  },

  {
    id: 'currencies/name-length',
    category: 'currencies',
    severity: 'warning',
    description: 'name must be at most 20 characters',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const name = entry.name;
        if (name === undefined) return;

        if (!isString(name)) {
          ctx.report({
            rule: 'currencies/name-length',
            category: 'currencies',
            severity: 'error',
            message: `${path}.name must be a string`,
            path: `${path}.name`,
            position: ctx.locate(`${path}.name`),
            helpUri: specUrl('currency-documentation'),
          });
        } else if (name.length > 20) {
          ctx.report({
            rule: 'currencies/name-length',
            category: 'currencies',
            message: `${path}.name is ${name.length} characters; the maximum is 20`,
            path: `${path}.name`,
            position: ctx.locate(`${path}.name`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Move the longer explanation into desc.',
          });
        }
      });
    },
  },

  {
    id: 'currencies/urls',
    category: 'currencies',
    severity: 'error',
    description: 'Currency URL fields must be valid, and approval_server must use https://',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        for (const field of ['image', 'attestation_of_reserve'] as const) {
          const value = entry[field];
          if (value === undefined) continue;
          if (!isUrl(value)) {
            ctx.report({
              rule: 'currencies/urls',
              category: 'currencies',
              message: `${path}.${field} must be a valid URL`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
            });
          }
        }

        const approval = entry.approval_server;
        if (approval !== undefined && !isHttpsUrl(approval)) {
          ctx.report({
            rule: 'currencies/urls',
            category: 'currencies',
            message: `${path}.approval_server must be an https:// URL`,
            path: `${path}.approval_server`,
            position: ctx.locate(`${path}.approval_server`),
            helpUri:
              'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0008.md',
          });
        }
      });
    },
  },

  {
    id: 'currencies/regulated-needs-approval-server',
    category: 'currencies',
    severity: 'error',
    description: 'A regulated asset (SEP-8) requires an approval_server',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        if (entry.regulated !== true) return;

        if (entry.approval_server === undefined) {
          ctx.report({
            rule: 'currencies/regulated-needs-approval-server',
            category: 'currencies',
            message: `${path} is marked regulated but has no approval_server`,
            path,
            position: ctx.locate(path),
            helpUri:
              'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0008.md',
            suggestion:
              'SEP-8 clients need approval_server to get transactions signed before submission.',
          });
        }

        if (entry.approval_criteria === undefined) {
          ctx.report({
            rule: 'currencies/regulated-needs-approval-server',
            category: 'currencies',
            severity: 'warning',
            message: `${path} is marked regulated but has no approval_criteria`,
            path,
            position: ctx.locate(path),
            helpUri:
              'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0008.md',
            suggestion:
              'Explain in approval_criteria what you require in order to approve a transfer.',
          });
        }
      });
    },
  },

  {
    id: 'currencies/anchored-asset-fields',
    category: 'currencies',
    severity: 'warning',
    description: 'An anchored asset should describe what backs it and how to redeem it',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        if (entry.is_asset_anchored !== true) {
          // Describing a backing asset while not claiming to be anchored is
          // contradictory, and readers will trust the wrong one.
          if (entry.is_asset_anchored === false && entry.anchor_asset !== undefined) {
            ctx.report({
              rule: 'currencies/anchored-asset-fields',
              category: 'currencies',
              message: `${path} sets is_asset_anchored=false but still declares anchor_asset`,
              path: `${path}.anchor_asset`,
              position: ctx.locate(`${path}.anchor_asset`),
              helpUri: specUrl('currency-documentation'),
              suggestion:
                'Set is_asset_anchored=true if the token is redeemable, or drop the anchor_asset fields.',
            });
          }
          return;
        }

        for (const field of ['redemption_instructions'] as const) {
          if (entry[field] !== undefined) continue;
          ctx.report({
            rule: 'currencies/anchored-asset-fields',
            category: 'currencies',
            message: `${path} is anchored but does not specify ${field}`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Holders need to know what backs the token and how to redeem it.',
          });
        }
      });
    },
  },

  {
    id: 'currencies/anchored-fiat-needs-transfer-server',
    category: 'currencies',
    severity: 'warning',
    description: 'Anchored fiat assets need a transfer server to be redeemed',
    run(ctx) {
      const hasTransferServer =
        ctx.doc.TRANSFER_SERVER !== undefined || ctx.doc.TRANSFER_SERVER_SEP0024 !== undefined;
      if (hasTransferServer) return;

      eachCurrency(ctx, (entry, path) => {
        if (entry.is_asset_anchored !== true || entry.anchor_asset_type !== 'fiat') return;

        ctx.report({
          rule: 'currencies/anchored-fiat-needs-transfer-server',
          category: 'currencies',
          message: `${path} is anchored fiat but no transfer server is declared in the file`,
          path,
          position: ctx.locate(path),
          helpUri: specUrl('currency-documentation'),
          suggestion:
            'Add TRANSFER_SERVER or TRANSFER_SERVER_SEP0024 so clients know where to deposit and redeem the asset.',
        });
      });
    },
  },

  {
    id: 'currencies/regulated-invalid-target',
    category: 'currencies',
    severity: 'error',
    description:
      'regulated = true applies only to classic issued assets, not native XLM or contracts',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        if (entry.regulated !== true) return;

        if (isNativeAsset(entry)) {
          ctx.report({
            rule: 'currencies/regulated-invalid-target',
            category: 'currencies',
            message: `${path} marks the native asset as regulated, but SEP-8 applies only to classic issued assets`,
            path: `${path}.regulated`,
            position: ctx.locate(`${path}.regulated`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Remove regulated from the native XLM entry — no issuer controls it.',
          });
          return;
        }

        if (entry.contract !== undefined) {
          ctx.report({
            rule: 'currencies/regulated-invalid-target',
            category: 'currencies',
            message: `${path} marks a Soroban contract token as regulated, but SEP-8 applies only to classic Stellar assets`,
            path: `${path}.regulated`,
            position: ctx.locate(`${path}.regulated`),
            helpUri: specUrl('currency-documentation'),
            suggestion:
              'Remove regulated, or issue the asset as a classic Stellar account with issuer authorization flags.',
          });
        }
      });
    },
  },

  {
    id: 'currencies/collateral-consistency',
    category: 'currencies',
    severity: 'error',
    description: 'Collateral address, message, and signature lists must line up',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const addresses = entry.collateral_addresses;
        const messages = entry.collateral_address_messages;
        const signatures = entry.collateral_address_signatures;

        if (addresses === undefined && messages === undefined && signatures === undefined) return;

        for (const [field, value] of [
          ['collateral_addresses', addresses],
          ['collateral_address_messages', messages],
          ['collateral_address_signatures', signatures],
        ] as const) {
          if (value !== undefined && !isStringArray(value)) {
            ctx.report({
              rule: 'currencies/collateral-consistency',
              category: 'currencies',
              message: `${path}.${field} must be a list of strings`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
            });
          }
        }

        if (!isStringArray(addresses)) return;

        // Each address needs a matching message and signature, or the reserve
        // claim is unverifiable — which is the whole point of these fields.
        for (const [field, value] of [
          ['collateral_address_messages', messages],
          ['collateral_address_signatures', signatures],
        ] as const) {
          if (value === undefined) {
            ctx.report({
              rule: 'currencies/collateral-consistency',
              category: 'currencies',
              message: `${path} lists collateral_addresses but no ${field}, so the reserve claim cannot be verified`,
              path: `${path}.collateral_addresses`,
              position: ctx.locate(`${path}.collateral_addresses`),
              helpUri: specUrl('currency-documentation'),
            });
          } else if (isStringArray(value) && value.length !== addresses.length) {
            ctx.report({
              rule: 'currencies/collateral-consistency',
              category: 'currencies',
              message: `${path}.${field} has ${value.length} entries but collateral_addresses has ${addresses.length}`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
              suggestion: 'Provide one message and one signature per collateral address, in order.',
            });
          }
        }
      });
    },
  },

  {
    id: 'currencies/toml-pointer',
    category: 'currencies',
    severity: 'error',
    description: 'A currency using the toml pointer must specify no other fields',
    run(ctx) {
      currenciesOf(ctx.doc).forEach((entry, i) => {
        if (!isTomlPointer(entry)) return;
        const path = `CURRENCIES[${i}]`;

        if (!isHttpsUrl(entry.toml)) {
          ctx.report({
            rule: 'currencies/toml-pointer',
            category: 'currencies',
            message: `${path}.toml must be an https:// URL`,
            path: `${path}.toml`,
            position: ctx.locate(`${path}.toml`),
            helpUri: specUrl('currency-documentation'),
          });
        }

        const extras = Object.keys(entry).filter((key) => key !== 'toml');
        if (extras.length > 0) {
          ctx.report({
            rule: 'currencies/toml-pointer',
            category: 'currencies',
            message: `${path} uses the toml pointer, so it must not also set ${extras.join(', ')}`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion: "SEP-1 requires toml to be the entry's only field.",
          });
        }
      });
    },
  },

  {
    id: 'currencies/duplicate-asset',
    category: 'currencies',
    severity: 'error',
    description: 'The same code and issuer pair must not appear twice',
    run(ctx) {
      const seen = new Map<string, number>();

      eachCurrency(ctx, (entry, path, index) => {
        const code = entry.code;
        const identity = entry.issuer ?? entry.contract;
        if (!isString(code) || !isString(identity)) return;

        const key = `${code}:${identity}`;
        const first = seen.get(key);
        if (first !== undefined) {
          ctx.report({
            rule: 'currencies/duplicate-asset',
            category: 'currencies',
            message: `${path} duplicates the asset already declared in CURRENCIES[${first}]`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Merge the two entries, or correct whichever code or issuer is wrong.',
          });
        } else {
          seen.set(key, index);
        }
      });
    },
  },

  {
    id: 'currencies/unknown-field',
    category: 'currencies',
    severity: 'info',
    description: 'Flags currency fields SEP-1 does not define',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        for (const key of Object.keys(entry)) {
          if (KNOWN_CURRENCY_FIELDS.has(key)) continue;
          ctx.report({
            rule: 'currencies/unknown-field',
            category: 'currencies',
            message: `${path}.${key} is not a field defined by SEP-1`,
            path: `${path}.${key}`,
            position: ctx.locate(`${path}.${key}`),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Currency fields are lower_snake_case in SEP-1.',
          });
        }
      });
    },
  },
];
