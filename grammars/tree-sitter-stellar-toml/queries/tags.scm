; Captures: @definition @name @reference
;
; Symbol index (`tree-sitter tags`, Helix's symbol list, Neovim's tag sources).
; A `stellar.toml` has two kinds of named things worth indexing: the tables the
; anchor is organised into, and the accounts and contracts those tables point
; at. Only the SEP-1 nodes get tags — a vendor table is still a table, but it is
; not something a reader searches for by name.

; `[DOCUMENTATION]`, `[VALIDATORS]`, …
(table
  name: (sep_table) @name @definition)

; One `[[CURRENCIES]]` entry per asset.
(array_table
  name: (currency_entry) @name @definition)

; The keys the anchor claims to control, and the contracts it delegates to.
((public_key) @name @reference)
((contract_id) @name @reference)
