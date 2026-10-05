local M = {}

M.default_config = {
  cmd = { "stellar-toml-lint", "--lsp" },
  filetypes = { "stellar.toml" },
  root_dir = function(fname)
    local root = vim.loop.cwd()
    local dir = vim.fs.dirname(fname)
    while dir and dir ~= root do
      if vim.fs.dirname(dir) == dir then break end
      if vim.loop.fs_stat(vim.pesc(dir) .. "/.git") or vim.loop.fs_stat(vim.pesc(dir) .. "/.stellartomlrc.json") then
        return dir
      end
      dir = vim.fs.dirname(dir)
    end
    return root
  end,
  settings = {
    diagnostics = {
      enable = true,
      virtualText = true,
      signs = true,
      float = true,
      underline = true,
    },
  },
  singleFileSupport = true,
}

M.docs = {
  description = [[
Language server for `stellar.toml` files providing diagnostics, code actions, and hover documentation.

Provides real-time SEP-1 linting diagnostics, quick-fix code actions, and hover documentation with spec links for stellar.toml files.
  ]],
}

return M
