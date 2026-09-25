import type { Rule } from '../types.js';
import {
  ACCOUNT_ID_FIELDS,
  DEPRECATED_FIELDS,
  HTTPS_ENDPOINT_FIELDS,
  KNOWN_GLOBAL_FIELDS,
  specUrl,
} from '../spec.js';
import {
  KNOWN_PASSPHRASES,
  MAX_FILE_BYTES,
  isAccountId,
  isContractId,
  isHttpsUrl,
  isMuxedAccountId,
  isString,
  isUrl,
} from '../predicates.js';
import { emptyStringValuesRule } from './empty-values.js';
import { githubHandleRules } from './github-handle.js';
import { trailingSlashRule } from './trailing-slash.js';
import { uppercaseKeyRules } from './uppercase-keys.js';

/**
 * The `WEB_AUTH_CONTRACT_ID` when it is a valid C... id, with its file path,
 * so network checks can verify the SEP-45 auth contract's TTL. Invalid ids
 * are reported offline by `general/web-auth-contract-id` instead.
 */
export function webAuthContractIdOf(
  doc: Record<string, unknown>,
): { id: string; path: string } | undefined {
  const value = doc.WEB_AUTH_CONTRACT_ID;
  if (!isString(value) || !isContractId(value)) return undefined;
  return { id: value, path: 'WEB_AUTH_CONTRACT_ID' };
}

/** Rules covering file-level constraints and the global (untabled) fields. */
export const generalRules: Rule[] = [
  ...uppercaseKeyRules,
  trailingSlashRule,
  {
    id: 'file/max-size',
    category: 'file',
    severity: 'error',
    description: 'stellar.toml must not exceed 100KB',
    run(ctx) {
      const bytes =
        typeof Buffer !== 'undefined'
          ? Buffer.byteLength(ctx.source, 'utf8')
          : new TextEncoder().encode(ctx.source).length;
      if (bytes > MAX_FILE_BYTES) {
        ctx.report({
          rule: 'file/max-size',
          category: 'file',
          message: `File is ${(bytes / 1024).toFixed(1)}KB, exceeding the 100KB maximum`,
          helpUri: specUrl('specification'),
          suggestion:
            'Move per-asset detail into linked currency TOML files using the `toml` field.',
        });
      }
    },
  },

  {
    id: 'general/version',
    category: 'general',
    severity: 'warning',
    description: 'VERSION should be present and look like a semantic version',
    run(ctx) {
      const version = ctx.doc.VERSION;
      if (version === undefined) {
        ctx.report({
          rule: 'general/version',
          category: 'general',
          message: 'VERSION is missing, so parsers cannot tell which fields to expect',
          path: 'VERSION',
          helpUri: specUrl('general-information'),
          suggestion: 'Add VERSION="2.7.0" at the top of the file.',
        });
        return;
      }
      if (!isString(version)) {
        ctx.report({
          rule: 'general/version',
          category: 'general',
          message: 'VERSION must be a string',
          path: 'VERSION',
          position: ctx.locate('VERSION'),
          helpUri: specUrl('general-information'),
          suggestion: 'Quote the value, e.g. VERSION="2.7.0".',
        });
        return;
      }
      if (!/^\d+\.\d+\.\d+$/.test(version)) {
        ctx.report({
          rule: 'general/version',
          category: 'general',
          message: `VERSION "${version}" is not a semantic version`,
          path: 'VERSION',
          position: ctx.locate('VERSION'),
          helpUri: specUrl('general-information'),
          suggestion: 'Use a MAJOR.MINOR.PATCH string, e.g. "2.7.0".',
        });
      }
    },
  },

  {
    id: 'network/passphrase',
    category: 'network',
    severity: 'error',
    description: 'NETWORK_PASSPHRASE must exactly match a known Stellar network',
    run(ctx) {
      const passphrase = ctx.doc.NETWORK_PASSPHRASE;
      if (passphrase === undefined) {
        ctx.report({
          rule: 'network/passphrase',
          category: 'network',
          severity: 'warning',
          message:
            'NETWORK_PASSPHRASE is missing, so clients cannot tell which network you operate on',
          path: 'NETWORK_PASSPHRASE',
          helpUri: specUrl('general-information'),
          suggestion:
            'Add NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015" for mainnet.',
        });
        return;
      }
      if (!isString(passphrase)) {
        ctx.report({
          rule: 'network/passphrase',
          category: 'network',
          message: 'NETWORK_PASSPHRASE must be a string',
          path: 'NETWORK_PASSPHRASE',
          position: ctx.locate('NETWORK_PASSPHRASE'),
          helpUri: specUrl('general-information'),
        });
        return;
      }
      if (KNOWN_PASSPHRASES[passphrase]) return;

      // Whitespace around the `;` is the classic hand-typed mistake, and it
      // breaks signature verification in a way that is painful to debug.
      const normalized = passphrase.trim().replace(/\s*;\s*/, ' ; ');
      const near = KNOWN_PASSPHRASES[normalized];
      ctx.report({
        rule: 'network/passphrase',
        category: 'network',
        message: near
          ? `NETWORK_PASSPHRASE has stray whitespace; it must match the ${near} passphrase byte for byte`
          : `NETWORK_PASSPHRASE "${passphrase}" does not match any known Stellar network`,
        path: 'NETWORK_PASSPHRASE',
        position: ctx.locate('NETWORK_PASSPHRASE'),
        helpUri: 'https://developers.stellar.org/docs/networks',
        suggestion: near
          ? `Replace it with exactly: ${normalized}`
          : 'Use the Public, Testnet, or Futurenet passphrase exactly as published.',
        ...(near ? { fix: { value: normalized } } : {}),
      });
    },
  },

  {
    id: 'general/https-endpoints',
    category: 'general',
    severity: 'error',
    description: 'Endpoint fields must be https:// URLs',
    run(ctx) {
      for (const field of HTTPS_ENDPOINT_FIELDS) {
        const value = ctx.doc[field];
        if (value === undefined) continue;

        if (!isHttpsUrl(value)) {
          const shown = isString(value) ? value : JSON.stringify(value);
          ctx.report({
            rule: 'general/https-endpoints',
            category: 'general',
            message: `${field} must be an https:// URL, got ${shown}`,
            path: field,
            position: ctx.locate(field),
            helpUri: specUrl('general-information'),
            suggestion: 'Serve the endpoint over TLS and use its https:// URL here.',
          });
        }
      }
    },
  },

  {
    id: 'general/horizon-url',
    category: 'general',
    severity: 'warning',
    description: 'HORIZON_URL must be a valid URL',
    run(ctx) {
      const value = ctx.doc.HORIZON_URL;
      if (value === undefined) return;
      if (!isUrl(value)) {
        ctx.report({
          rule: 'general/horizon-url',
          category: 'general',
          message: 'HORIZON_URL must be a valid URL',
          path: 'HORIZON_URL',
          position: ctx.locate('HORIZON_URL'),
          helpUri: specUrl('general-information'),
        });
      } else if (!isHttpsUrl(value)) {
        ctx.report({
          rule: 'general/horizon-url',
          category: 'general',
          message: 'HORIZON_URL should use https://',
          path: 'HORIZON_URL',
          position: ctx.locate('HORIZON_URL'),
          helpUri: specUrl('general-information'),
        });
      }
    },
  },

  {
    id: 'general/signing-keys',
    category: 'general',
    severity: 'error',
    description: 'SIGNING_KEY and URI_REQUEST_SIGNING_KEY must be valid G... account IDs',
    run(ctx) {
      for (const field of ACCOUNT_ID_FIELDS) {
        const value = ctx.doc[field];
        if (value === undefined) continue;
        if (isAccountId(value)) continue;

        // Distinguish "wrong kind of key" from "corrupt key" — the fix differs.
        const muxed = isMuxedAccountId(value);
        const contract = isContractId(value);
        ctx.report({
          rule: 'general/signing-keys',
          category: 'general',
          message: muxed
            ? `${field} is a muxed (M...) account; it must be a plain G... account ID`
            : contract
              ? `${field} is a contract (C...) ID; it must be a G... account ID`
              : `${field} is not a valid Stellar account ID`,
          path: field,
          position: ctx.locate(field),
          helpUri: specUrl('general-information'),
          suggestion: muxed
            ? 'Use the underlying G... account that the muxed address wraps.'
            : 'Check for a transcription error — the checksum does not match.',
        });
      }
    },
  },

  {
    id: 'general/web-auth-contract-id',
    category: 'general',
    severity: 'error',
    description: 'WEB_AUTH_CONTRACT_ID must be a valid C... contract ID',
    run(ctx) {
      const value = ctx.doc.WEB_AUTH_CONTRACT_ID;
      if (value === undefined) return;
      if (!isContractId(value)) {
        ctx.report({
          rule: 'general/web-auth-contract-id',
          category: 'general',
          message: 'WEB_AUTH_CONTRACT_ID is not a valid Stellar contract ID',
          path: 'WEB_AUTH_CONTRACT_ID',
          position: ctx.locate('WEB_AUTH_CONTRACT_ID'),
          helpUri: specUrl('general-information'),
          suggestion: 'Contract IDs start with C and are 56 characters long.',
        });
      }
    },
  },

  {
    id: 'general/accounts',
    category: 'general',
    severity: 'error',
    description: 'ACCOUNTS must be a list of valid G... account IDs',
    run(ctx) {
      const accounts = ctx.doc.ACCOUNTS;
      if (accounts === undefined) return;

      if (!Array.isArray(accounts)) {
        ctx.report({
          rule: 'general/accounts',
          category: 'general',
          message: 'ACCOUNTS must be an array of account IDs',
          path: 'ACCOUNTS',
          position: ctx.locate('ACCOUNTS'),
          helpUri: specUrl('general-information'),
        });
        return;
      }

      const seen = new Map<string, number>();
      accounts.forEach((account, i) => {
        if (!isAccountId(account)) {
          ctx.report({
            rule: 'general/accounts',
            category: 'general',
            message: `ACCOUNTS[${i}] is not a valid Stellar account ID`,
            path: `ACCOUNTS[${i}]`,
            position: ctx.locate('ACCOUNTS'),
            helpUri: specUrl('general-information'),
            suggestion: 'Account IDs start with G and are 56 characters long.',
          });
          return;
        }
        const first = seen.get(account as string);
        if (first !== undefined) {
          ctx.report({
            rule: 'general/accounts',
            category: 'general',
            severity: 'warning',
            message: `ACCOUNTS[${i}] duplicates ACCOUNTS[${first}]`,
            path: `ACCOUNTS[${i}]`,
            position: ctx.locate('ACCOUNTS'),
            helpUri: specUrl('general-information'),
          });
        } else {
          seen.set(account as string, i);
        }
      });
    },
  },

  {
    id: 'general/sep31-requires-kyc',
    category: 'general',
    severity: 'error',
    description: 'DIRECT_PAYMENT_SERVER (SEP-31) requires KYC_SERVER (SEP-12)',
    run(ctx) {
      if (ctx.doc.DIRECT_PAYMENT_SERVER !== undefined && ctx.doc.KYC_SERVER === undefined) {
        ctx.report({
          rule: 'general/sep31-requires-kyc',
          category: 'general',
          message: 'DIRECT_PAYMENT_SERVER is set but KYC_SERVER is missing',
          path: 'DIRECT_PAYMENT_SERVER',
          position: ctx.locate('DIRECT_PAYMENT_SERVER'),
          helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md',
          suggestion:
            'SEP-31 depends on SEP-12, so add a KYC_SERVER entry pointing at your SEP-12 service.',
        });
      }
    },
  },

  {
    id: 'general/sep45-completeness',
    category: 'general',
    severity: 'warning',
    description: 'SEP-45 web auth needs both an endpoint and a contract ID',
    run(ctx) {
      const endpoint = ctx.doc.WEB_AUTH_FOR_CONTRACTS_ENDPOINT !== undefined;
      const contract = ctx.doc.WEB_AUTH_CONTRACT_ID !== undefined;
      if (endpoint === contract) return;

      const present = endpoint ? 'WEB_AUTH_FOR_CONTRACTS_ENDPOINT' : 'WEB_AUTH_CONTRACT_ID';
      const missing = endpoint ? 'WEB_AUTH_CONTRACT_ID' : 'WEB_AUTH_FOR_CONTRACTS_ENDPOINT';
      ctx.report({
        rule: 'general/sep45-completeness',
        category: 'general',
        message: `${present} is set but ${missing} is missing, so SEP-45 auth is unusable`,
        path: present,
        position: ctx.locate(present),
        helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md',
        suggestion: `Add ${missing}, or remove ${present} if you do not support SEP-45.`,
      });
    },
  },

  {
    id: 'general/auth-requires-signing-key',
    category: 'general',
    severity: 'error',
    description: 'WEB_AUTH_ENDPOINT (SEP-10) requires SIGNING_KEY',
    run(ctx) {
      if (ctx.doc.WEB_AUTH_ENDPOINT !== undefined && ctx.doc.SIGNING_KEY === undefined) {
        ctx.report({
          rule: 'general/auth-requires-signing-key',
          category: 'general',
          message: 'WEB_AUTH_ENDPOINT is set but SIGNING_KEY is missing',
          path: 'WEB_AUTH_ENDPOINT',
          position: ctx.locate('WEB_AUTH_ENDPOINT'),
          helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md',
          suggestion:
            'Clients verify SEP-10 challenge signatures against SIGNING_KEY, so it is required.',
        });
      }
    },
  },

  {
    id: 'general/sep24-requires-auth',
    category: 'general',
    severity: 'error',
    description: 'TRANSFER_SERVER_SEP0024 (SEP-24) requires WEB_AUTH_ENDPOINT (SEP-10)',
    run(ctx) {
      if (
        ctx.doc.TRANSFER_SERVER_SEP0024 !== undefined &&
        ctx.doc.WEB_AUTH_ENDPOINT === undefined
      ) {
        ctx.report({
          rule: 'general/sep24-requires-auth',
          category: 'general',
          message: 'TRANSFER_SERVER_SEP0024 is set but WEB_AUTH_ENDPOINT is missing',
          path: 'TRANSFER_SERVER_SEP0024',
          position: ctx.locate('TRANSFER_SERVER_SEP0024'),
          helpUri: specUrl('general-information'),
          suggestion:
            'SEP-24 requires SEP-10 authentication before deposit and withdraw flows can start, so add WEB_AUTH_ENDPOINT.',
        });
      }
    },
  },

  {
    id: 'general/kyc-requires-auth',
    category: 'general',
    severity: 'error',
    description: 'KYC_SERVER (SEP-12) requires WEB_AUTH_ENDPOINT (SEP-10)',
    run(ctx) {
      if (ctx.doc.KYC_SERVER !== undefined && ctx.doc.WEB_AUTH_ENDPOINT === undefined) {
        ctx.report({
          rule: 'general/kyc-requires-auth',
          category: 'general',
          message: 'KYC_SERVER is set but WEB_AUTH_ENDPOINT is missing',
          path: 'KYC_SERVER',
          position: ctx.locate('KYC_SERVER'),
          helpUri: specUrl('general-information'),
          suggestion:
            'SEP-12 endpoints expect a SEP-10 JWT on every request, so add WEB_AUTH_ENDPOINT.',
        });
      }
    },
  },

  {
    id: 'general/sep38-requires-auth',
    category: 'general',
    severity: 'error',
    description: 'ANCHOR_QUOTE_SERVER (SEP-38) requires WEB_AUTH_ENDPOINT (SEP-10)',
    run(ctx) {
      if (ctx.doc.ANCHOR_QUOTE_SERVER !== undefined && ctx.doc.WEB_AUTH_ENDPOINT === undefined) {
        ctx.report({
          rule: 'general/sep38-requires-auth',
          category: 'general',
          message: 'ANCHOR_QUOTE_SERVER is set but WEB_AUTH_ENDPOINT is missing',
          path: 'ANCHOR_QUOTE_SERVER',
          position: ctx.locate('ANCHOR_QUOTE_SERVER'),
          helpUri: specUrl('general-information'),
          suggestion:
            'SEP-38 firm and retail quote requests authenticate with SEP-10, so add WEB_AUTH_ENDPOINT.',
        });
      }
    },
  },

  {
    id: 'general/transfer-server-needs-currencies',
    category: 'general',
    severity: 'warning',
    description: 'A declared transfer server should have a non-empty [[CURRENCIES]] list',
    run(ctx) {
      const currencies = ctx.doc.CURRENCIES;
      // A present-but-malformed CURRENCIES is currencies/entries-are-tables'
      // finding; only "absent" or "empty" belongs to this rule.
      const emptyOrAbsent =
        currencies === undefined || (Array.isArray(currencies) && currencies.length === 0);
      if (!emptyOrAbsent) return;

      const field =
        ctx.doc.TRANSFER_SERVER !== undefined
          ? 'TRANSFER_SERVER'
          : ctx.doc.TRANSFER_SERVER_SEP0024 !== undefined
            ? 'TRANSFER_SERVER_SEP0024'
            : undefined;
      if (field === undefined) return;

      ctx.report({
        rule: 'general/transfer-server-needs-currencies',
        category: 'general',
        message: `${field} is declared but [[CURRENCIES]] is empty or missing`,
        path: field,
        position: ctx.locate(field),
        helpUri: specUrl('currency-documentation'),
        suggestion: 'List the assets the transfer server handles as [[CURRENCIES]] entries.',
      });
    },
  },

  {
    id: 'general/deprecated-field',
    category: 'general',
    severity: 'warning',
    description: 'Flags fields SEP-1 marks as deprecated',
    run(ctx) {
      for (const [field, note] of Object.entries(DEPRECATED_FIELDS)) {
        if (ctx.doc[field] === undefined) continue;
        ctx.report({
          rule: 'general/deprecated-field',
          category: 'general',
          message: `${field} is deprecated: ${note}`,
          path: field,
          position: ctx.locate(field),
          helpUri: specUrl('general-information'),
          suggestion: `Remove ${field} unless a legacy client still depends on it.`,
        });
      }
    },
  },

  {
    id: 'general/unknown-field',
    category: 'general',
    severity: 'info',
    description: 'Flags top-level fields SEP-1 does not define',
    run(ctx) {
      for (const key of Object.keys(ctx.doc)) {
        if (KNOWN_GLOBAL_FIELDS.has(key)) continue;
        ctx.report({
          rule: 'general/unknown-field',
          category: 'general',
          message: `${key} is not a field defined by SEP-1`,
          path: key,
          position: ctx.locate(key),
          helpUri: specUrl('general-information'),
          suggestion: 'Check the spelling and casing — SEP-1 global fields are UPPER_SNAKE_CASE.',
        });
      }
    },
  },
  emptyStringValuesRule,
  ...githubHandleRules,
];
