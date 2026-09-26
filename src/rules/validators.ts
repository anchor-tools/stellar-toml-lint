import type { Rule } from '../types.js';
import { KNOWN_VALIDATOR_FIELDS, RESERVED_VALIDATOR_ALIASES, specUrl } from '../spec.js';
import { isAccountId, isHostPort, isString } from '../predicates.js';
import { historyUrlRules } from './history-url-check.js';

/** Reads `[[VALIDATORS]]` as a list of tables, ignoring malformed entries. */
function validatorsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = doc.VALIDATORS;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

/** Rules covering the `[[VALIDATORS]]` list (SEP-20 node declaration). */
export const validatorRules: Rule[] = [
  {
    id: 'validators/entries-are-tables',
    category: 'validators',
    severity: 'error',
    description: 'VALIDATORS must be a list of tables',
    run(ctx) {
      const list = ctx.doc.VALIDATORS;
      if (list === undefined) return;

      if (!Array.isArray(list)) {
        ctx.report({
          rule: 'validators/entries-are-tables',
          category: 'validators',
          message: 'VALIDATORS must be a list of tables, written as [[VALIDATORS]]',
          path: 'VALIDATORS',
          position: ctx.locate('VALIDATORS'),
          helpUri: specUrl('validator-information'),
        });
        return;
      }

      list.forEach((entry, i) => {
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          ctx.report({
            rule: 'validators/entries-are-tables',
            category: 'validators',
            message: `VALIDATORS[${i}] must be a table`,
            path: `VALIDATORS[${i}]`,
            position: ctx.locate(`VALIDATORS[${i}]`),
            helpUri: specUrl('validator-information'),
          });
        }
      });
    },
  },

  {
    id: 'validators/alias',
    category: 'validators',
    severity: 'error',
    description: 'ALIAS must match ^[a-z0-9-]{2,16}$ so stellar-core configs accept it',
    run(ctx) {
      const seen = new Map<string, number>();

      validatorsOf(ctx.doc).forEach((entry, i) => {
        const path = `VALIDATORS[${i}]`;
        const alias = entry.ALIAS;

        if (alias === undefined) {
          ctx.report({
            rule: 'validators/alias',
            category: 'validators',
            severity: 'warning',
            message: `${path} is missing ALIAS`,
            path: `${path}.ALIAS`,
            position: ctx.locate(path),
            helpUri: specUrl('validator-information'),
            suggestion: "ALIAS is what appears in other operators' stellar-core configs.",
          });
          return;
        }

        if (!isString(alias) || !/^[a-z0-9-]{2,16}$/.test(alias)) {
          ctx.report({
            rule: 'validators/alias',
            category: 'validators',
            message: `${path}.ALIAS must match ^[a-z0-9-]{2,16}$`,
            path: `${path}.ALIAS`,
            position: ctx.locate(`${path}.ALIAS`),
            helpUri: specUrl('validator-information'),
            suggestion: isString(alias)
              ? `Try "${alias
                  .toLowerCase()
                  .replace(/[^a-z0-9-]/g, '-')
                  .slice(0, 16)}".`
              : 'Use a lowercase, hyphenated name of 2 to 16 characters.',
          });
          return;
        }

        const first = seen.get(alias);
        if (first !== undefined) {
          ctx.report({
            rule: 'validators/alias',
            category: 'validators',
            message: `${path}.ALIAS "${alias}" duplicates VALIDATORS[${first}]`,
            path: `${path}.ALIAS`,
            position: ctx.locate(`${path}.ALIAS`),
            helpUri: specUrl('validator-information'),
            suggestion: 'Aliases identify individual nodes, so each must be unique.',
          });
        } else {
          seen.set(alias, i);
        }
      });
    },
  },

  {
    id: 'validators/alias-reserved-keyword',
    category: 'validators',
    severity: 'error',
    description:
      'ALIAS must not be a reserved stellar-core config keyword (self, all, default, none, quorum, peers, manual, auto)',
    run(ctx) {
      validatorsOf(ctx.doc).forEach((entry, i) => {
        const path = `VALIDATORS[${i}]`;
        const alias = entry.ALIAS;

        if (!isString(alias) || !/^[a-z0-9-]{2,16}$/.test(alias)) return;
        if (!RESERVED_VALIDATOR_ALIASES.has(alias.toLowerCase())) return;

        ctx.report({
          rule: 'validators/alias-reserved-keyword',
          category: 'validators',
          message: `${path}.ALIAS "${alias}" is a reserved stellar-core config keyword`,
          path: `${path}.ALIAS`,
          position: ctx.locate(`${path}.ALIAS`),
          helpUri: specUrl('validator-information'),
          suggestion: `Other operators import this name into their quorum slices; try "${alias}-${i}".`,
        });
      });
    },
  },

  {
    id: 'validators/public-key',
    category: 'validators',
    severity: 'error',
    description: 'PUBLIC_KEY must be a valid G... account ID and unique per node',
    run(ctx) {
      const seen = new Map<string, number>();

      validatorsOf(ctx.doc).forEach((entry, i) => {
        const path = `VALIDATORS[${i}]`;
        const key = entry.PUBLIC_KEY;

        if (key === undefined) {
          ctx.report({
            rule: 'validators/public-key',
            category: 'validators',
            severity: 'warning',
            message: `${path} is missing PUBLIC_KEY, so the node cannot be identified`,
            path: `${path}.PUBLIC_KEY`,
            position: ctx.locate(path),
            helpUri: specUrl('validator-information'),
          });
          return;
        }

        if (!isAccountId(key)) {
          ctx.report({
            rule: 'validators/public-key',
            category: 'validators',
            message: `${path}.PUBLIC_KEY is not a valid Stellar account ID`,
            path: `${path}.PUBLIC_KEY`,
            position: ctx.locate(`${path}.PUBLIC_KEY`),
            helpUri: specUrl('validator-information'),
            suggestion: 'Check for a transcription error — the checksum does not match.',
          });
          return;
        }

        const first = seen.get(key as string);
        if (first !== undefined) {
          ctx.report({
            rule: 'validators/public-key',
            category: 'validators',
            message: `${path}.PUBLIC_KEY duplicates VALIDATORS[${first}]`,
            path: `${path}.PUBLIC_KEY`,
            position: ctx.locate(`${path}.PUBLIC_KEY`),
            helpUri: specUrl('validator-information'),
            suggestion: 'Two nodes sharing a key will be treated as one by quorum tooling.',
          });
        } else {
          seen.set(key as string, i);
        }
      });
    },
  },

  {
    id: 'validators/host',
    category: 'validators',
    severity: 'error',
    description: 'HOST must be a host:port peers can dial',
    run(ctx) {
      validatorsOf(ctx.doc).forEach((entry, i) => {
        const path = `VALIDATORS[${i}]`;
        const host = entry.HOST;
        if (host === undefined) return;

        if (!isHostPort(host)) {
          ctx.report({
            rule: 'validators/host',
            category: 'validators',
            message: `${path}.HOST must be in host:port form`,
            path: `${path}.HOST`,
            position: ctx.locate(`${path}.HOST`),
            helpUri: specUrl('validator-information'),
            suggestion: 'Include the peer port, e.g. "core-au.example.com:11625".',
          });
        }
      });
    },
  },

  // HISTORY is validated by `validators/invalid-history-url`, which supersedes
  // the earlier absolute-URI warning and adds `{0}` template handling.
  ...historyUrlRules,

  {
    id: 'validators/unknown-field',
    category: 'validators',
    severity: 'info',
    description: 'Flags validator fields SEP-1 does not define',
    run(ctx) {
      validatorsOf(ctx.doc).forEach((entry, i) => {
        const path = `VALIDATORS[${i}]`;
        for (const key of Object.keys(entry)) {
          if (KNOWN_VALIDATOR_FIELDS.has(key)) continue;
          ctx.report({
            rule: 'validators/unknown-field',
            category: 'validators',
            message: `${path}.${key} is not a field defined by SEP-1`,
            path: `${path}.${key}`,
            position: ctx.locate(`${path}.${key}`),
            helpUri: specUrl('validator-information'),
          });
        }
      });
    },
  },
];

export { checkValidatorNetwork } from '../validators/check-validator.js';
