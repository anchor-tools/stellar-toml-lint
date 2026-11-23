/**
 * Migrations for the fields SEP-1 itself calls deprecated or legacy.
 *
 * Three things, each lifted from a check that already ships:
 *
 * - `AUTH_SERVER` and `DEPOSIT_SERVER` ({@link DEPRECATED_FIELDS}) are renamed
 *   to the successor the deprecation text names. The value carries over
 *   unchanged because both successors hold the same kind of thing, an HTTPS
 *   endpoint. Where the deprecation asks for a *second* endpoint that no value
 *   in this file can answer — `KYC_SERVER` for SEP-12 — the step says so
 *   instead of inventing one.
 * - `FEDERATION_SERVER` written with `http://` (the same check
 *   `general/deprecated-field` makes) gets its scheme rewritten and nothing
 *   else, so the host, the path, and the quoting style survive.
 * - A `[DOCUMENTATION]` field written at the document root — also flagged by
 *   that rule — moves under `[DOCUMENTATION]`. The statement travels with the
 *   comments attached to it, so documentation written *about* the field does
 *   not get orphaned where the field used to be.
 *
 * A rename is skipped when the successor is already in the file, and the
 * reason is reported: two `WEB_AUTH_ENDPOINT` lines would not be a migration,
 * it would be a corrupted config, and TOML rejects the duplicate anyway.
 */
import { DEPRECATED_FIELDS, KNOWN_DOCUMENTATION_FIELDS } from '../../spec.js';
import type { CstStringValue } from '../parser.js';
import type { MigrationContext, MigrationRule, MigrationStep } from './types.js';

/**
 * The successor each deprecated root field is renamed to.
 *
 * Keyed by `DEPRECATED_FIELDS`, and a test fails if a deprecation is added
 * without saying what replaces it, so the two lists cannot drift apart.
 */
export const SUCCESSOR_FIELD: Readonly<Record<string, string>> = {
  AUTH_SERVER: 'WEB_AUTH_ENDPOINT',
  DEPOSIT_SERVER: 'TRANSFER_SERVER',
};

/** What the deprecation still asks for that this file cannot supply. */
const MANUAL_FOLLOW_UP: Readonly<Record<string, string>> = {
  AUTH_SERVER: 'SEP-12 customer data needs its own KYC_SERVER endpoint',
};

const deprecatedRootFields: MigrationRule = {
  id: 'deprecated-root-field',
  reason: 'the SEP that defined the field is deprecated, or the field was replaced',
  plan(context: MigrationContext): MigrationStep[] {
    const steps: MigrationStep[] = [];

    for (const legacy of Object.keys(DEPRECATED_FIELDS)) {
      const entry = context.rootKey(legacy);
      const key = entry?.key ?? null;
      const successor = SUCCESSOR_FIELD[legacy];
      const deprecation = DEPRECATED_FIELDS[legacy];
      if (
        entry === undefined ||
        key === null ||
        successor === undefined ||
        deprecation === undefined
      ) {
        continue;
      }

      if (context.hasField('', successor)) {
        context.note(
          `${legacy}: ${successor} is already set, left ${legacy} in place for you to reconcile`,
        );
        continue;
      }

      const followUp = MANUAL_FOLLOW_UP[legacy];
      steps.push({
        rule: 'deprecated-root-field',
        path: legacy,
        action: 'rename-key',
        description: `${legacy} → ${successor} (${deprecation.message})${
          followUp === undefined ? '' : `; ${followUp}`
        }`,
        // Only the key text is replaced, so the `=`, the value, and the
        // spacing the anchor wrote all survive untouched.
        edits: [{ start: key.start, end: key.end, text: successor }],
      });
    }

    return steps;
  },
};

const plaintextFederation: MigrationRule = {
  id: 'federation-server-scheme',
  reason: 'SEP-1 requires the federation endpoint to be served over HTTPS',
  plan(context: MigrationContext): MigrationStep[] {
    const entry = context.rootKey('FEDERATION_SERVER');
    const value = entry?.value;
    if (entry === undefined || value === null || value === undefined || value.kind !== 'string') {
      return [];
    }
    const span = context.valueSpan(entry);
    const raw = (value as CstStringValue).raw;
    if (span === undefined || !/^(['"]?)http:\/\//i.test(raw)) return [];

    return [
      {
        rule: 'federation-server-scheme',
        path: 'FEDERATION_SERVER',
        action: 'rewrite-value',
        description: 'FEDERATION_SERVER scheme http:// → https://',
        edits: [
          {
            start: span.start,
            end: span.end,
            text: span.text.replace(/^(["']?)http:\/\//i, '$1https://'),
          },
        ],
      },
    ];
  },
};

const misplacedDocumentationFields: MigrationRule = {
  id: 'documentation-field-at-root',
  reason: 'SEP-1 defines these fields inside [DOCUMENTATION], not at the document root',
  plan(context: MigrationContext): MigrationStep[] {
    const steps: MigrationStep[] = [];

    for (const field of KNOWN_DOCUMENTATION_FIELDS) {
      const entry = context.rootKey(field);
      if (entry === undefined) continue;
      // A file can hold both `ORG_NAME` at the root and `[DOCUMENTATION]`
      // with `ORG_NAME`; moving it onto the field that is already there would
      // be a duplicate key, so the root copy stays for the anchor to delete.
      if (context.hasField('DOCUMENTATION', field)) {
        context.note(`${field}: already set in [DOCUMENTATION], left the root copy in place`);
        continue;
      }
      const edits = context.moveStatement(entry, { section: 'DOCUMENTATION' });
      if (edits === undefined) continue;

      steps.push({
        rule: 'documentation-field-at-root',
        path: field,
        action: 'move-into-table',
        description: `${field} moved from the document root into [DOCUMENTATION]`,
        edits,
      });
    }

    return steps;
  },
};

/** Rules that need no user decision: the specification already picked the successor. */
export const DEPRECATED_FIELD_RULES: readonly MigrationRule[] = [
  deprecatedRootFields,
  plaintextFederation,
  misplacedDocumentationFields,
];
