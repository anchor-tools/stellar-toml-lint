; Syntax highlighting queries for stellar.toml, matched against the
; tree-sitter-toml grammar declared in extension.toml. Keys are painted as
; properties, table headers as types, and values by their TOML type; the
; language server adds the semantic layer (addresses, contracts, endpoints,
; deprecated keys) on top.

(comment) @comment

(string) @string
(integer) @number
(float) @number
(boolean) @boolean

(pair key: (bare_key) @property)
(pair key: (quoted_key) @property)
(pair key: (dotted_key) @property)

(table (bare_key) @type)
(table (quoted_key) @type)
(table_array_element (bare_key) @type)
(table_array_element (quoted_key) @type)

((bare_key) @keyword
  (#match? @keyword "^(VERSION|NETWORK_PASSPHRASE)$"))

[ "[" "]" "{" "}" "=" "." "," ] @punctuation
