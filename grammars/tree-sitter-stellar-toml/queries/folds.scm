; Captures: @fold
;
; Fold regions, not highlights: `@fold` is the only capture the folding
; consumers read.

; Fold a whole table, including its key/value pairs.
(table) @fold
(array_table) @fold

; Fold arrays and inline tables that span several lines.
(array) @fold
(inline_table) @fold

; Fold multi-line strings.
(string) @fold
