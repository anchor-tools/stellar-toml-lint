import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**'] },
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
    // Tests assert on parsed JSON, which is legitimately `any`.
    files: ['test/**/*.ts'],
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
    // Tree-sitter grammars are written in the tree-sitter DSL. The CLI injects
    // `grammar`, `seq`, `repeat`, and friends when it loads grammar.js, so they
    // are globals rather than imports. Rule callbacks conventionally take `$`
    // or `_` when they do not use the DSL object.
    files: ['grammars/**/grammar.js'],
    languageOptions: {
      sourceType: 'commonjs',
      globals: {
        grammar: 'readonly',
        seq: 'readonly',
        repeat: 'readonly',
        choice: 'readonly',
        optional: 'readonly',
        token: 'readonly',
        prec: 'readonly',
        alias: 'readonly',
        field: 'readonly',
        module: 'writable',
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^[$_]', varsIgnorePattern: '^[$_]' },
      ],
      // TOML forbids control characters, so the grammar's string rules spell
      // out the exact ranges they exclude.
      'no-control-regex': 'off',
    },
  },
  {
    // Tree-sitter's generated Node bindings are CommonJS by design.
    files: ['grammars/**/bindings/node/**/*.js'],
    languageOptions: {
      sourceType: 'commonjs',
      globals: {
        module: 'writable',
        require: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
);
