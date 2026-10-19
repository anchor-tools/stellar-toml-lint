; Indentation rules: array and inline-table contents indent, and a table body
; keeps its keys one level in from the header.

(array "]" @end) @indent
(inline_table "}" @end) @indent
(table) @indent
