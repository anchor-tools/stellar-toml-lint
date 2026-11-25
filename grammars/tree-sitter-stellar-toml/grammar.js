/**
 * Tree-sitter grammar for `stellar.toml` (SEP-1).
 *
 * The grammar is a TOML 1.0 grammar with concrete nodes for the structures an
 * anchor file is made of: table headers, array-of-table headers, dotted keys,
 * scalar values, arrays, inline tables, and comments.
 *
 * The five SEP-1 names an editor or a symbol index actually asks for —
 * `public_key`, `asset_code`, `contract_id`, `sep_table` and `currency_entry` —
 * are nodes, not regex `#match?` filters bolted onto `bare_key` and `string`.
 * Recognising them in the parser is what makes `queries/tags.scm` possible
 * (`tree-sitter tags` cannot emit a symbol for a node it cannot name), and it
 * keeps highlighting identical across every consumer that reads
 * `node-types.json` instead of this repository's queries.
 *
 * That is a deliberate reversal of the first draft, which left SEP-1 names to
 * `queries/highlights.scm` so vendor extensions would still parse. Vendor
 * extensions still parse: each new node matches a *shape* (a StrKey, an asset
 * code, a known header name), and anything that does not match falls back to
 * the plain `string` / `bare_key` path untouched.
 */

const decimal_integer = /[+-]?(0|[1-9](_?[0-9])*)/;
const decimal_integer_in_float_exponent_part = /[+-]?[0-9](_?[0-9])*/;
const hexadecimal_integer = /0x[0-9a-fA-F](_?[0-9a-fA-F])*/;
const octal_integer = /0o[0-7](_?[0-7])*/;
const binary_integer = /0b[01](_?[01])*/;
const float_fractional_part = /[.][0-9](_?[0-9])*/;
const float_exponent_part = seq(/[eE]/, decimal_integer_in_float_exponent_part);

const rfc3339_date = /([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])/;
const rfc3339_delimiter = /[ tT]/;
const rfc3339_time = /([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)([.][0-9]+)?/;
const rfc3339_offset = /([zZ])|([+-]([01][0-9]|2[0-3]):[0-5][0-9])/;

// Control characters that TOML forbids in strings. Tab is deliberately
// allowed; newline handling is left to the external scanner for multi-line
// strings and to the grammar for single-line ones.
const BASIC_STRING_CONTENT = /[^\x00-\x08\x0a-\x1f\x7f"\\]+/;
const MULTILINE_BASIC_STRING_CONTENT = /[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f"\\]+/;
const LITERAL_STRING_CONTENT = /[^\x00-\x08\x0a-\x1f\x7f']+/;
const MULTILINE_LITERAL_STRING_CONTENT = /[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f']+/;

// Stellar `StrKey`s are a version byte, a payload and a CRC16 checksum, all
// base32 (RFC 4648, no padding), so the version byte shows up as the first
// character: `G` for an ed25519 account (1 + 32 + 2 = 35 bytes, 56 characters),
// `C` for a contract (same 32-byte payload), and `M` for a muxed account,
// whose med25519 preimage is the key plus a 64-bit id (1 + 32 + 8 + 2 = 43
// bytes, 69 characters). Matching the shape is enough for a syntax node;
// checksum validity is the linter's job (`src/predicates.ts`).
const STRKEY_ACCOUNT = /G[A-Z2-7]{55}/;
const STRKEY_MUXED_ACCOUNT = /M[A-Z2-7]{68}/;
const STRKEY_CONTRACT = /C[A-Z2-7]{55}/;

// SEP-1 asset codes: 1 to 12 alphanumeric characters, uppercase by convention.
const ASSET_CODE = /[A-Z0-9]{1,12}/;

module.exports = grammar({
  name: 'stellar_toml',

  externals: ($) => [
    $._line_ending_or_eof,
    $._multiline_basic_string_content,
    $._multiline_basic_string_end,
    $._multiline_literal_string_content,
    $._multiline_literal_string_end,
    // The reserved SEP-1 header names, matched by the external scanner rather
    // than by a token rule: the key token is at least as long as a reserved
    // name, and token precedence outranks length in the lexer, so a `token`
    // rule for `DOCUMENTATION` would also win inside `[DOCUMENTATIONX]`.
    $.sep_table,
    $.currency_entry,
  ],

  extras: ($) => [$.comment, /[ \t\r]/],

  rules: {
    document: ($) => seq(repeat(choice($.pair, $.newline)), repeat(choice($.table, $.array_table))),

    comment: (_) => token(prec(-1, seq('#', /[^\x00-\x08\x0a-\x1f\x7f]*/))),

    newline: (_) => /\n/,

    table: ($) =>
      seq(
        '[',
        field('name', choice($.sep_table, $.dotted_key, $._key)),
        ']',
        $._line_ending_or_eof,
        repeat(choice($.pair, $.newline)),
      ),

    // `[[CURRENCIES]]` gets its own node because currency entries repeat: a
    // symbol list wants one row per asset, not one row per table. Every other
    // array-of-table header keeps its plain `bare_key`.
    array_table: ($) =>
      seq(
        '[[',
        field('name', choice($.currency_entry, $.dotted_key, $._key)),
        ']]',
        $._line_ending_or_eof,
        repeat(choice($.pair, $.newline)),
      ),

    // Both reserved-name tokens are legal only in header states, which is not
    // the set of states a `pair` key is lexed in: `[DOCUMENTATION]` names a
    // table, while `DOCUMENTATION = "x"` is an ordinary key and must stay a
    // `bare_key` to keep being highlighted as a property. Dotted headers
    // (`[FIELDS.expiration]`) also stay plain, because the scanner rejects a
    // reserved name that is not the whole header.

    pair: ($) => seq($._inline_pair, $._line_ending_or_eof),

    _inline_pair: ($) =>
      seq(field('key', choice($.dotted_key, $._key)), '=', field('value', $._inline_value)),

    _key: ($) => choice($.bare_key, $.quoted_key),
    dotted_key: ($) => prec.left(seq(choice($.dotted_key, $._key), '.', $._key)),
    bare_key: (_) => /[A-Za-z0-9_-]+/,
    quoted_key: ($) => choice($._basic_string, $._literal_string),

    _inline_value: ($) =>
      choice(
        $.string,
        $.public_key,
        $.contract_id,
        $.asset_code,
        $.integer,
        $.float,
        $.boolean,
        $.offset_date_time,
        $.local_date_time,
        $.local_date,
        $.local_time,
        $.array,
        $.inline_table,
      ),

    string: ($) =>
      choice(
        $._basic_string,
        $._multiline_basic_string,
        $._literal_string,
        $._multiline_literal_string,
      ),

    // The three Stellar scalar shapes. Each one is a single token that
    // includes its quotes, so it is strictly longer than the one-character `"`
    // that opens `_basic_string` and the lexer's longest-match rule picks it.
    // A value whose content does not fit the shape is therefore still an
    // ordinary `string`, and none of these tokens is valid in a key position,
    // so a 56-character `"G…K" = 1` stays a `quoted_key`.
    public_key: (_) => token(prec(1, seq('"', choice(STRKEY_ACCOUNT, STRKEY_MUXED_ACCOUNT), '"'))),

    contract_id: (_) => token(prec(1, seq('"', STRKEY_CONTRACT, '"'))),

    asset_code: (_) => token(prec(1, seq('"', ASSET_CODE, '"'))),

    _basic_string: ($) =>
      seq(
        '"',
        repeat(choice(token.immediate(BASIC_STRING_CONTENT), $.escape_sequence)),
        token.immediate('"'),
      ),

    _multiline_basic_string: ($) =>
      seq(
        '"""',
        repeat(
          choice(
            token.immediate(MULTILINE_BASIC_STRING_CONTENT),
            $._multiline_basic_string_content,
            token.immediate(/\r?\n/),
            $.escape_sequence,
            alias($._escape_line_ending, $.escape_sequence),
          ),
        ),
        $._multiline_basic_string_end,
      ),

    escape_sequence: (_) => token.immediate(/\\([btnfr"\\]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/),
    _escape_line_ending: (_) => token.immediate(seq(/\\/, /\r?\n/)),

    _literal_string: ($) =>
      seq("'", optional(token.immediate(LITERAL_STRING_CONTENT)), token.immediate("'")),

    _multiline_literal_string: ($) =>
      seq(
        "'''",
        repeat(
          choice(
            token.immediate(MULTILINE_LITERAL_STRING_CONTENT),
            $._multiline_literal_string_content,
            token.immediate(/\r?\n/),
          ),
        ),
        $._multiline_literal_string_end,
      ),

    integer: (_) => choice(decimal_integer, hexadecimal_integer, octal_integer, binary_integer),

    float: (_) =>
      choice(
        token(
          seq(
            decimal_integer,
            choice(
              float_fractional_part,
              seq(optional(float_fractional_part), float_exponent_part),
            ),
          ),
        ),
        /[+-]?(inf|nan)/,
      ),

    boolean: (_) => /true|false/,

    offset_date_time: (_) =>
      token(seq(rfc3339_date, rfc3339_delimiter, rfc3339_time, rfc3339_offset)),
    local_date_time: (_) => token(seq(rfc3339_date, rfc3339_delimiter, rfc3339_time)),
    local_date: (_) => rfc3339_date,
    local_time: (_) => rfc3339_time,

    array: ($) =>
      seq(
        '[',
        repeat($.newline),
        optional(
          seq(
            $._inline_value,
            repeat($.newline),
            repeat(seq(',', repeat($.newline), $._inline_value, repeat($.newline))),
            optional(seq(',', repeat($.newline))),
          ),
        ),
        ']',
      ),

    inline_table: ($) =>
      seq(
        '{',
        optional(
          seq(alias($._inline_pair, $.pair), repeat(seq(',', alias($._inline_pair, $.pair)))),
        ),
        '}',
      ),
  },
});
