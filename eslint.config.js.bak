import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'docs/stellar-toml-lint.browser.js',
      'node_modules/**',
      // Build output of the editor extension and the desktop app. Both are
      // gitignored, but they exist in a working tree that has been built, and
      // linting generated code reports problems nobody can fix in a source
      // file.
      'editors/vscode/out/**',
      'apps/desktop/out/**',
      'apps/*/node_modules/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // The codebase deliberately narrows `unknown` with explicit predicates
      // rather than casting, so flag any cast that slipped through.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-console': 'error',
      eqeqeq: ['error', 'always'],
      '@typescript-eslint/no-unused-vars': ['error', { varsIgnorePattern: '^_' }],
    },
  },
  {
    // Tests assert on parsed JSON and drive stubbed browser APIs, which are
    // legitimately `any`. Applies to the companion apps' tests too.
    files: ['test/**/*.ts', 'apps/**/test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },
  {
    // LSP module has parameters that are intentionally unused in function signatures.
    files: ['src/lsp.ts'],
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    // Benchmarks use console output for reporting.
    files: ['benchmarks/**/*.ts'],
    rules: {
      'no-console': 'off',
    },
  },
  {
    // Electron Forge loads its config with `require`, so this one file is
    // CommonJS while the rest of the desktop app is ESM.
    files: ['apps/desktop/forge.config.cjs'],
    languageOptions: {
      sourceType: 'commonjs',
      globals: {
        module: 'writable',
        require: 'readonly',
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
      },
    },
  },
  {
    // The desktop renderer is plain browser JavaScript loaded by a <script>
    // tag — no bundler, so no module globals, and `no-undef` needs to be told
    // which globals the page actually has.
    files: ['apps/desktop/renderer/**/*.js'],
    languageOptions: {
      globals: {
        window: 'readonly',
        document: 'readonly',
      },
    },
  },
);
