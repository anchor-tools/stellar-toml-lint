local M = {}

M.DEFAULT_CONFIG = {
  command = "stellar-toml-lint",
  args = { "--lsp" },
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
  diagnostics = {
    virtual_text = true,
    signs = true,
    float = true,
    underline = true,
  },
  formatting = {
    format_on_save = true,
  },
  settings = {},
}

function M.setup(config)
  config = vim.tbl_deep_extend("force", M.DEFAULT_CONFIG, config or {})

  vim.lsp.register_server({
    name = "stellar-toml-lint",
    cmd = { "stellar-toml-lint", "--lsp" },
    filetypes = { "stellar.toml" },
    root_dir = config.root_dir,
    settings = config.settings,
  })

  vim.api.nvim_create_autocmd("LspAttach", {
    pattern = { "stellar.toml" },
    callback = function()
      local buf = vim.api.nvim_get_current_buf()
      local opts = { buffer = buf }
      vim.diagnostic.config({
        virtual_text = config.diagnostics.virtual_text,
        signs = config.diagnostics.signs,
        float = config.diagnostics.float,
        underline = config.diagnostics.underline,
      })
      vim.keymap.set("n", "<leader>f", "<cmd>lua vim.lsp.buf.format({ timeout_ms = 5000 })<CR>", opts)
      vim.api.nvim_create_autocmd("BufWritePre", {
        pattern = { "*.toml" },
        callback = function()
          vim.fn.system({ "stellar-toml-lint", "--fix", vim.api.nvim_buf_get_name(buf) })
        end,
        buffer = buf,
      })
    end,
  })

  vim.api.nvim_create_autocmd("BufReadPost", {
    pattern = { "*stellar.toml" },
    callback = function()
      if not vim.lsp.get_active_clients({ name = "stellar-toml-lint" })[1] then
        vim.lsp.buf_attach_client(0, "stellar-toml-lint")
      end
    end,
  })

  local keymap_opts = { buffer = true, silent = true }
  vim.keymap.set("n", "gD", "<cmd>lua vim.lsp.buf.declaration()<CR>", keymap_opts)
  vim.keymap.set("n", "gd", "<cmd>lua vim.lsp.buf.definition()<CR>", keymap_opts)
  vim.keymap.set("n", "K", "<cmd>lua vim.lsp.buf.hover()<CR>", keymap_opts)
  vim.keymap.set("n", "<leader>rn", "<cmd>lua vim.lsp.buf.rename()<CR>", keymap_opts)
  vim.keymap.set("n", "<leader>ca", "<cmd>lua vim.lsp.buf.code_action()<CR>", keymap_opts)
end

function M.config()
  return vim.tbl_deep_extend("force", {}, M.DEFAULT_CONFIG)
end

return M
