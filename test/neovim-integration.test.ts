import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

function read(path: string): string {
  return readFileSync(join(root, path), 'utf8');
}

describe('neovim integration', () => {
  describe('init.lua', () => {
    it('contains M.setup', () => {
      const content = read('integrations/neovim/lua/stellar-toml-lint/init.lua');
      expect(content).toContain('M.setup');
    });

    it('contains M.config', () => {
      const content = read('integrations/neovim/lua/stellar-toml-lint/init.lua');
      expect(content).toContain('M.config');
    });

    it('contains function M.setup', () => {
      const content = read('integrations/neovim/lua/stellar-toml-lint/init.lua');
      expect(content).toContain('function M.setup');
    });
  });

  describe('syntax/stellar-toml.scm', () => {
    it('contains CURRENCIES', () => {
      const content = read('integrations/neovim/syntax/stellar-toml.scm');
      expect(content).toContain('CURRENCIES');
    });

    it('contains VALIDATORS', () => {
      const content = read('integrations/neovim/syntax/stellar-toml.scm');
      expect(content).toContain('VALIDATORS');
    });

    it('contains DOCUMENTATION', () => {
      const content = read('integrations/neovim/syntax/stellar-toml.scm');
      expect(content).toContain('DOCUMENTATION');
    });
  });

  describe('lspconfig.lua', () => {
    it('contains stellar-toml-lint', () => {
      const content = read('integrations/neovim/lua/stellar-toml-lint/lspconfig.lua');
      expect(content).toContain('stellar-toml-lint');
    });

    it('contains --lsp', () => {
      const content = read('integrations/neovim/lua/stellar-toml-lint/lspconfig.lua');
      expect(content).toContain('--lsp');
    });

    it('contains default_config', () => {
      const content = read('integrations/neovim/lua/stellar-toml-lint/lspconfig.lua');
      expect(content).toContain('default_config');
    });
  });

  describe('README.md', () => {
    it('contains lazy.nvim', () => {
      const content = read('integrations/neovim/README.md');
      expect(content).toContain('lazy.nvim');
    });

    it('contains packer.nvim', () => {
      const content = read('integrations/neovim/README.md');
      expect(content).toContain('packer.nvim');
    });

    it('contains Tree-sitter', () => {
      const content = read('integrations/neovim/README.md');
      expect(content).toContain('Tree-sitter');
    });
  });
});
