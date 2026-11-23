import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Several suites spawn the built CLI for each case. On a loaded machine
    // that legitimately takes longer than Vitest's 5s default, so a timeout is
    // not a signal that the assertion failed.
    testTimeout: 20000,
    hookTimeout: 20000,
    // `tests` is a symlink to `test`. Collecting both runs every suite twice,
    // concurrently, against the same fixture files, which makes suites that
    // write fixtures race each other.
    exclude: [...configDefaults.exclude, 'tests/**'],
  },
});
