/**
 * Rule presets: curated rule bundles for the roles that actually publish
 * `stellar.toml` files.
 *
 * A validator operator publishes `[[VALIDATORS]]` and little else. An asset
 * issuer publishes `[[CURRENCIES]]` and `[DOCUMENTATION]`, and runs no web
 * servers. A SEP-24 anchor publishes service endpoints plus a currency list.
 * None of them covers the whole surface SEP-1 describes, so every role ends up
 * silencing rules that have nothing to do with its infrastructure — today as a
 * long `--off` chain copied into each CI workflow, Makefile, and pre-commit
 * hook, and each copy drifting a little further from the last.
 *
 * A preset is that chain written once and reviewed as a unit. It is a
 * *baseline*, not a policy: `--off`, `--warn`, and `--error` on the same
 * command line still win over it, so the one-off deviation never needs a new
 * preset.
 *
 * Bundles are assembled from the rule registry rather than from a hand-typed
 * list of ids, so a rule registered later joins the group its category puts it
 * in instead of being quietly left behind. Ids named individually are checked
 * against the registry as the module loads, which turns a rule being renamed
 * into an import-time error rather than a silently dead entry in a bundle.
 */
import { allRules } from './rules/index.js';
import type { RuleCategory, RuleOverrides, Severity } from './types.js';

/** A rule bundle name accepted by `--preset`. */
export type PresetName = 'validator' | 'anchor-sep24' | 'issuer';

/** Every preset name, in the order `--help` and the error messages list them. */
export const PRESET_NAMES: readonly PresetName[] = ['validator', 'anchor-sep24', 'issuer'];

/** One role's baseline severities. */
export interface Preset {
  /** The name `--preset` accepts. */
  name: PresetName;
  /** One line, shown by `--help` and when an unknown name is passed. */
  summary: string;
  /** The baseline rule severities. Explicit CLI flags still take precedence. */
  rules: RuleOverrides;
}

/** What a role may set on a rule: any severity, or `off` to silence it. */
type Setting = Severity | 'off';

/**
 * The rules that describe an anchor's service endpoints rather than the file.
 *
 * SEP-6 `/info`, SEP-10, SEP-12, SEP-24, SEP-31, SEP-38, and SEP-45 all hang
 * off a server the organisation has to run, so a role without one has nothing
 * to be told about them. CORS pre-flight belongs here too: it only ever probes
 * `WEB_AUTH_ENDPOINT`, `TRANSFER_SERVER`, `KYC_SERVER`, and
 * `ANCHOR_QUOTE_SERVER`, all of them anchor endpoints.
 */
const ANCHOR_SERVICE_RULES: readonly string[] = [
  'general/auth-requires-signing-key',
  'general/kyc-requires-auth',
  'general/sep24-requires-auth',
  'general/sep31-requires-kyc',
  'general/sep38-requires-auth',
  'general/sep45-completeness',
  'general/transfer-server-needs-currencies',
  'network/cors-preflight-failed',
  'network/missing-allow-headers',
  'soroban/invalid-auth-contract-interface',
];

/** Rule id prefixes that cover the anchor services, which have no shared category. */
const ANCHOR_SERVICE_PREFIXES: readonly string[] = ['sep12/', 'sep38/', 'network/sep6-'];

/** Sets `setting` on every rule the registry files under `category`. */
function byCategory(category: RuleCategory, setting: Setting): RuleOverrides {
  return fromRules(
    allRules.filter((rule) => rule.category === category),
    setting,
  );
}

/** Sets `setting` on every rule whose id starts with `prefix`. */
function byPrefix(prefix: string, setting: Setting): RuleOverrides {
  return fromRules(
    allRules.filter((rule) => rule.id.startsWith(prefix)),
    setting,
  );
}

/** Sets `setting` on the named rules, rejecting ids the registry no longer knows. */
function byId(ids: readonly string[], setting: Setting): RuleOverrides {
  const known = new Set(allRules.map((rule) => rule.id));
  for (const id of ids) {
    if (!known.has(id)) {
      throw new Error(
        `Preset references the unknown rule "${id}". Run --list-rules to see the current ids.`,
      );
    }
  }
  return fromIds(ids, setting);
}

/** Builds `{ id: setting }` from rule objects. */
function fromRules(rules: readonly { id: string }[], setting: Setting): RuleOverrides {
  const overrides: RuleOverrides = {};
  for (const rule of rules) overrides[rule.id] = setting;
  return overrides;
}

/** Builds `{ id: setting }` from bare ids. */
function fromIds(ids: readonly string[], setting: Setting): RuleOverrides {
  const overrides: RuleOverrides = {};
  for (const id of ids) overrides[id] = setting;
  return overrides;
}

/** Merges bundles left to right, so a later group overrides an earlier one. */
function merge(...bundles: RuleOverrides[]): RuleOverrides {
  return Object.assign({}, ...bundles);
}

/** Currency issuance, as a validator operator's file has no `[[CURRENCIES]]`. */
const offCurrencies = byCategory('currencies', 'off');

/** Every rule that only makes sense for a role running an anchor. */
const offAnchorServices = merge(
  ...ANCHOR_SERVICE_PREFIXES.map((prefix) => byPrefix(prefix, 'off')),
  byId(ANCHOR_SERVICE_RULES, 'off'),
);

const PRESET_LIST: readonly Preset[] = [
  {
    name: 'validator',
    summary: 'Validator operator: validator and general file checks, no anchor or currency rules',
    rules: merge(
      offCurrencies,
      offAnchorServices,
      // Two nodes sharing a HOST or an ALIAS is a quorum problem, not a style
      // question, so a validator operator wants it to fail the build.
      byId(['validators/duplicate-alias', 'validators/duplicate-host'], 'error'),
    ),
  },
  {
    name: 'anchor-sep24',
    summary: 'SEP-24 anchor: SEP-24, SEP-10, and currency requirements at error',
    rules: merge(
      // A hosted anchor runs no validator nodes.
      byCategory('validators', 'off'),
      // The requirements SEP-24 makes on an anchor are the ones a wallet trips
      // over, so they fail the build rather than scroll past in a log. The
      // rules already at error (SEP-24 needing SEP-10, SEP-10 needing a
      // SIGNING_KEY) stay there; these are the ones that were only warnings.
      byId(
        [
          'general/sep45-completeness',
          'general/transfer-server-needs-currencies',
          'currencies/anchored-asset-fields',
          'currencies/anchored-fiat-needs-transfer-server',
          'currencies/display-decimals-exceeds-max',
          'currencies/missing-anchor-asset-code',
        ],
        'error',
      ),
    ),
  },
  {
    name: 'issuer',
    summary: 'Asset issuer: currency, collateral, and documentation completeness at error',
    rules: merge(
      // A standalone issuer redeems nothing, so it serves nothing to check.
      offAnchorServices,
      // Everything that says "wallets may not list this" becomes a build
      // failure: an incomplete [DOCUMENTATION] or an undescribed anchor.
      // `currencies/collateral-consistency` is already an error, and the
      // collateral fields it guards are part of `anchored-asset-fields`.
      byId(
        [
          'documentation/present',
          'documentation/recommended-fields',
          'currencies/anchored-asset-fields',
          'currencies/display-decimals-contract-mismatch',
          'currencies/missing-anchor-asset-code',
        ],
        'error',
      ),
    ),
  },
];

/** Every preset, keyed by the name `--preset` accepts. */
export const PRESETS: Record<PresetName, Preset> = Object.fromEntries(
  PRESET_LIST.map((preset) => [preset.name, preset]),
) as Record<PresetName, Preset>;

// Callers spread a preset into their own overrides map, so a stray write must
// not reach the shared bundle every other run of the same preset reads.
for (const preset of PRESET_LIST) Object.freeze(preset.rules);

/**
 * Looks up a preset by name, as `--preset` does.
 *
 * Throws a message listing every available preset and what it is for — plus the
 * closest name when there is a close one — so a typo is a usage error the caller
 * turns into exit code 2 rather than a silent fallback to the default
 * severities.
 */
export function resolvePreset(name: string): Preset {
  const preset = PRESETS[name as PresetName];
  if (preset !== undefined) return preset;

  const near = nearestPreset(name);
  throw new Error(
    `Unknown preset "${name}". Available presets:\n${presetList()}${
      near === undefined ? '' : `\nDid you mean: ${near}?`
    }`,
  );
}

/** The presets and their one-line summaries, aligned, for an error message. */
function presetList(): string {
  const width = Math.max(...PRESET_NAMES.map((name) => name.length));
  return PRESET_LIST.map((preset) => `  ${preset.name.padEnd(width)}  ${preset.summary}`).join(
    '\n',
  );
}

/**
 * The preset name closest to `name`, or `undefined` when nothing is near.
 *
 * The list is three names long, so a plain edit distance is the whole cost of
 * catching the typo that matters — `--preset valdator` is a real keystroke, and
 * guessing is only better than silence when the guess is close.
 */
function nearestPreset(name: string): PresetName | undefined {
  let nearest: PresetName | undefined;
  let smallest = Number.POSITIVE_INFINITY;

  for (const candidate of PRESET_NAMES) {
    const distance = editDistance(name, candidate);
    if (distance < smallest) {
      nearest = candidate;
      smallest = distance;
    }
  }

  // One edit is always a typo; beyond that, only for a name long enough for the
  // distance to mean something, since `i` is one edit from every name there is.
  return smallest <= Math.max(1, Math.floor(name.length / 3)) ? nearest : undefined;
}

/** Levenshtein distance, over the whole string. */
function editDistance(a: string, b: string): number {
  const row = (length: number): number[] => Array.from({ length: length + 1 }, (_, i) => i);
  let previous = row(b.length);

  for (let i = 1; i <= a.length; i++) {
    const current = row(b.length);
    current[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const substitution = (previous[j - 1] ?? i) + (a[i - 1] === b[j - 1] ? 0 : 1);
      current[j] = Math.min(substitution, (previous[j] ?? i) + 1, (current[j - 1] ?? j) + 1);
    }
    previous = current;
  }

  return previous[b.length] ?? Math.max(a.length, b.length);
}
