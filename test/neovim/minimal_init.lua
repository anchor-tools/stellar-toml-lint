-- Minimal init for headless neovim testing
vim.opt.runtimepath:prepend(os.getenv("VIM_DIR") or ".")

-- Disable UI elements for headless testing
vim.opt.number = false
vim.opt.relativenumber = false
vim.opt.termguicolors = true
vim.opt.mouse = ""

-- Set up minimal paths
package.path = package.path .. ";/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua"
package.cpath = package.cpath .. ";/usr/local/lib/lua/5.1/?.so"

-- Prevent auto-startup from interfering
vim.cmd("set rtp+=/tmp/opencode")
