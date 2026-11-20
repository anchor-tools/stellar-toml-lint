/**
 * Tree-sitter grammar for `stellar.toml` (SEP-1).
 *
 * The grammar is a TOML 1.0 grammar with concrete nodes for the structures an
 * anchor file is made of: table headers, array-of-table headers, dotted keys,
 * scalar values, arrays, inline tables, and comments. SEP-1 table and key
 * names are highlighted by `queries/highlights.scm` rather than baked into the
 * parser, so an anchor that adds a vendor extension still parses.
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

module.exports = grammar({
  name: 'stellar_toml',

  externals: ($) => [
    $._line_ending_or_eof,
    $._multiline_basic_string_content,
    $._multiline_basic_string_end,
    $._multiline_literal_string_content,
    $._multiline_literal_string_end,
  ],

  extras: ($) => [$.comment, /[ \t\r]/],

  rules: {
    document: ($) => seq(repeat(choice($.pair, $.newline)), repeat(choice($.table, $.array_table))),

    comment: (_) => token(prec(-1, seq('#', /[^\x00-\x08\x0a-\x1f\x7f]*/))),

    newline: (_) => /\n/,

    table: ($) =>
      seq(
        '[',
        field('name', choice($.dotted_key, $._key)),
        ']',
        $._line_ending_or_eof,
        repeat(choice($.pair, $.newline)),
      ),

    array_table: ($) =>
      seq(
        '[[',
        field('name', choice($.dotted_key, $._key)),
        ']]',
        $._line_ending_or_eof,
        repeat(choice($.pair, $.newline)),
      ),

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
