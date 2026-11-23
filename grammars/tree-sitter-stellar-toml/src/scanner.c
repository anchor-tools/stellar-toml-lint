/**
 * External scanner for the stellar.toml grammar.
 *
 * It disambiguates the closing delimiter of multi-line strings (one, two, or
 * three quote characters, where one or two belong to the content) and consumes
 * the line ending that terminates a table header or key/value pair. Both need
 * lookahead the generated lexer cannot express on its own.
 *
 * It also recognises SEP-1's reserved table-header names. A `token` rule could
 * not do that job: `bare_key` matches any reserved name *and* everything after
 * it, and the lexer ranks explicit precedence above match length, so a token
 * for `DOCUMENTATION` would also fire inside `[DOCUMENTATIONX]` and derail the
 * parse. Here the whole key run is read first, so the name has to match
 * exactly, and `mark_end` keeps the closing bracket out of the token.
 */
#include <string.h>
#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

enum TokenType {
  LINE_ENDING_OR_EOF,
  MULTILINE_BASIC_STRING_CONTENT,
  MULTILINE_BASIC_STRING_END,
  MULTILINE_LITERAL_STRING_CONTENT,
  MULTILINE_LITERAL_STRING_END,
  SEP_TABLE,
  CURRENCY_ENTRY,
};

// SEP-1's `[...]` tables. `CURRENCIES` is listed here too because
// `[CURRENCIES]` (single brackets) is a table; the `[[CURRENCIES]]` array-of-
// tables gets its own symbol below.
static const char *const SEP_TABLE_NAMES[] = {
  "ACCOUNTS",
  "CURRENCIES",
  "DATES",
  "DOCUMENTATION",
  "FIELDS",
  "PRINCIPALS",
  "SERVERS",
  "VALIDATORS",
};

// Array-of-table headers named per entry rather than per table.
static const char *const CURRENCY_ENTRY_NAMES[] = { "CURRENCIES" };

#define SEP_TABLE_NAME_COUNT (sizeof(SEP_TABLE_NAMES) / sizeof(SEP_TABLE_NAMES[0]))
#define CURRENCY_ENTRY_NAME_COUNT (sizeof(CURRENCY_ENTRY_NAMES) / sizeof(CURRENCY_ENTRY_NAMES[0]))

// Longest reserved name (`DOCUMENTATION`) plus a terminator.
#define RESERVED_NAME_MAX_LENGTH 16

void *tree_sitter_stellar_toml_external_scanner_create(void) { return NULL; }
void tree_sitter_stellar_toml_external_scanner_destroy(void *payload) {}
unsigned tree_sitter_stellar_toml_external_scanner_serialize(void *payload, char *buffer) {
  return 0;
}
void tree_sitter_stellar_toml_external_scanner_deserialize(
  void *payload,
  const char *buffer,
  unsigned length
) {}

static bool is_key_character(int32_t character) {
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9') || character == '_' || character == '-';
}

static bool is_reserved_name(const char *word, const char *const *names, unsigned name_count) {
  for (unsigned i = 0; i < name_count; i++) {
    if (strcmp(word, names[i]) == 0) {
      return true;
    }
  }
  return false;
}

static bool scan_reserved_name(
  TSLexer *lexer,
  const char *const *names,
  unsigned name_count,
  enum TokenType result_symbol
) {
  char word[RESERVED_NAME_MAX_LENGTH];
  unsigned length = 0;

  while (lexer->lookahead == ' ' || lexer->lookahead == '\t') {
    lexer->advance(lexer, true);
  }

  while (is_key_character(lexer->lookahead)) {
    // Longer than any reserved name, so it cannot be one: bail out and let the
    // ordinary `bare_key` token match, which the parser restores to after a
    // false return.
    if (length == RESERVED_NAME_MAX_LENGTH - 1) {
      return false;
    }
    word[length++] = (char)lexer->lookahead;
    lexer->advance(lexer, false);
    lexer->mark_end(lexer);
  }
  word[length] = '\0';

  // The header has to end here. `[FIELDS.expiration]` is a dotted key, and
  // `DOCUMENTATION` followed by anything else is not a reserved name.
  if (lexer->lookahead != ']') {
    return false;
  }

  if (length == 0 || !is_reserved_name(word, names, name_count)) {
    return false;
  }

  lexer->result_symbol = result_symbol;
  return true;
}

static bool scan_multiline_string_end(
  TSLexer *lexer,
  const bool *valid_symbols,
  int32_t delimiter,
  enum TokenType content_symbol,
  enum TokenType end_symbol
) {
  if (!valid_symbols[end_symbol] || lexer->lookahead != delimiter) {
    return false;
  }

  lexer->advance(lexer, false);
  lexer->mark_end(lexer);

  if (lexer->lookahead != delimiter) {
    lexer->result_symbol = content_symbol;
    return true;
  }

  lexer->advance(lexer, false);

  if (lexer->lookahead != delimiter) {
    lexer->mark_end(lexer);
    lexer->result_symbol = content_symbol;
    return true;
  }

  lexer->advance(lexer, false);

  if (lexer->lookahead != delimiter) {
    lexer->mark_end(lexer);
    lexer->result_symbol = end_symbol;
    return true;
  }

  lexer->result_symbol = content_symbol;
  return true;
}

bool tree_sitter_stellar_toml_external_scanner_scan(
  void *payload,
  TSLexer *lexer,
  const bool *valid_symbols
) {
  if (
    valid_symbols[SEP_TABLE] &&
    scan_reserved_name(lexer, SEP_TABLE_NAMES, SEP_TABLE_NAME_COUNT, SEP_TABLE)
  ) {
    return true;
  }

  if (
    valid_symbols[CURRENCY_ENTRY] &&
    scan_reserved_name(lexer, CURRENCY_ENTRY_NAMES, CURRENCY_ENTRY_NAME_COUNT, CURRENCY_ENTRY)
  ) {
    return true;
  }

  if (
    scan_multiline_string_end(
      lexer,
      valid_symbols,
      '"',
      MULTILINE_BASIC_STRING_CONTENT,
      MULTILINE_BASIC_STRING_END
    ) ||
    scan_multiline_string_end(
      lexer,
      valid_symbols,
      '\'',
      MULTILINE_LITERAL_STRING_CONTENT,
      MULTILINE_LITERAL_STRING_END
    )
  ) {
    return true;
  }

  if (valid_symbols[LINE_ENDING_OR_EOF]) {
    lexer->result_symbol = LINE_ENDING_OR_EOF;

    while (lexer->lookahead == ' ' || lexer->lookahead == '\t') {
      lexer->advance(lexer, true);
    }

    if (lexer->lookahead == 0 || lexer->lookahead == '\n') {
      return true;
    }

    if (lexer->lookahead == '\r') {
      lexer->advance(lexer, true);
      if (lexer->lookahead == '\n') {
        return true;
      }
    }
  }

  return false;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
