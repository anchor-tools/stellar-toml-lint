local M = {}

function M.assert_diagnostics(result, expected_count)
  assert(result, "Expected diagnostics result but got nil")
  assert(result.diagnostics, "Expected diagnostics in result")
  assert(#result.diagnostics == expected_count, string.format(
    "Expected %d diagnostics, got %d",
    expected_count,
    #result.diagnostics
  ))
end

function M.assert_diagnostics_contain(result, message_substring)
  assert(result.diagnostics, "Expected diagnostics in result")
  local found = false
  for _, diag in ipairs(result.diagnostics) do
    if string.find(diag.message, message_substring) then
      found = true
      break
    end
  end
  assert(found, string.format("Expected diagnostic containing '%s' not found", message_substring))
end

function M.assert_no_diagnostics(result)
  assert(result, "Expected diagnostics result but got nil")
  assert(result.diagnostics, "Expected diagnostics in result")
  assert(#result.diagnostics == 0, string.format(
    "Expected 0 diagnostics, got %d",
    #result.diagnostics
  ))
end

function M.assert_lsp_server(client)
  assert(client, "Expected LSP client but got nil")
  assert(client.name, "Expected client.name")
  assert(client.name == "stellar-toml-lint", string.format(
    "Expected client name 'stellar-toml-lint', got '%s'",
    client.name
  ))
end

function M.assert_attached(bufnr)
  assert(bufnr, "Expected bufnr")
  local clients = vim.lsp.get_active_clients({ buffer = bufnr })
  assert(#clients > 0, "Expected at least one active LSP client on buffer")
end

return M
