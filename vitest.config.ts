import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Only collect tests from `test/`. The `tests/` path is a symlink to
    // `test/`; collecting both runs every suite twice and causes races on
    // shared fixtures and file watchers.
    include: ['test/**/*.test.ts', 'integrations/**/*.test.ts'],
    // Several suites spawn the built CLI for each case. On a loaded machine
    // that legitimately takes longer than Vitest's 5s default, so a timeout is
    // not a signal that the assertion failed.
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
