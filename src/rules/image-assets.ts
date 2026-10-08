/**
 * The branding images a live-domain audit probes.
 *
 * `DOCUMENTATION.ORG_LOGO` and each `[[CURRENCIES]].image` are downloaded by
 * wallets — LOBSTR, Vibrant, Freighter, StellarX — to draw asset lists and
 * transaction confirmations. A URL that 404s, a CDN that withholds
 * `Access-Control-Allow-Origin: *` from browser wallets, or an uncompressed
 * 15MB PNG therefore shows up in production as a blank tile or a stalled app
 * rather than as a linter finding.
 *
 * The rule objects are empty by design: `lintDomain` owns the probing and
 * reports these ids itself, because a network probe has no place in the
 * offline rule pipeline. Registering them anyway is what lets `--list-rules`
 * document the checks and `--off` / `--warn` / `--error` configure them.
 */
import type { Rule } from '../types.js';

export const IMAGE_UNREACHABLE_RULE = 'network/image-unreachable';
export const IMAGE_CORS_RULE = 'network/image-cors';
export const IMAGE_CONTENT_TYPE_RULE = 'network/image-content-type';
export const IMAGE_MAX_SIZE_RULE = 'network/image-max-size';

/** Every id {@link imageAssetRules} can report, in report order. */
export const imageAssetRuleIds: readonly string[] = [
  IMAGE_UNREACHABLE_RULE,
  IMAGE_CORS_RULE,
  IMAGE_CONTENT_TYPE_RULE,
  IMAGE_MAX_SIZE_RULE,
];

/** Rules `lintDomain` reports while probing the images wallets download. */
export const imageAssetRules: Rule[] = [
  {
    id: IMAGE_UNREACHABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Branding images (ORG_LOGO, currency image) must resolve over HTTP',
    run() {},
  },
  {
    id: IMAGE_CORS_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Branding images must be served with Access-Control-Allow-Origin: *',
    run() {},
  },
  {
    id: IMAGE_CONTENT_TYPE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Branding image URLs must be served with an image/* content type',
    run() {},
  },
  {
    id: IMAGE_MAX_SIZE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Branding images should stay under 500KB so asset lists stay fast',
    run() {},
  },
];
