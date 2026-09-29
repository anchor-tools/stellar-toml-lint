import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Many suites spawn the built CLI as a subprocess (often several times per
    // test); the 5s default regularly trips on loaded or cold CI runners.
    testTimeout: 15_000,
  },
});
