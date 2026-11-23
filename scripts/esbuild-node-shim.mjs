/**
 * esbuild plugin that replaces Node built-ins with browser-safe stubs.
 *
 * Lives on its own because every browser bundle in this repository needs it and
 * importing it from a build script would run that script's build as a side
 * effect of the import.
 */

/**
 * `node:tls` is imported lazily by the TLS audit, which a page can never run:
 * a browser cannot observe a negotiated protocol or cipher suite. The shim
 * throws rather than returning a guess, so `security/*` reports nothing instead
 * of inventing a finding.
 */
export const nodeShimPlugin = {
  name: 'node-builtins-shim',
  setup(build) {
    build.onResolve({ filter: /^node:tls$/ }, (args) => ({
      path: args.path,
      namespace: 'node-shim',
    }));

    build.onLoad({ filter: /.*/, namespace: 'node-shim' }, () => ({
      contents: `
        export function connect() {
          throw new Error('TLS audit is not supported in browser environments.');
        }
        export default { connect };
      `,
      loader: 'js',
    }));
  },
};

/** Banner the browser bundles need: a Worker has no `window`. */
export const browserBanner = {
  js: 'var self = typeof window !== "undefined" ? window : typeof globalThis !== "undefined" ? globalThis : this;',
};
