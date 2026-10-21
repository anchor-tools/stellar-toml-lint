/**
 * External scanner for the stellar.toml grammar.
 *
 * It disambiguates the closing delimiter of multi-line strings (one, two, or
 * three quote characters, where one or two belong to the content) and consumes
 * the line ending that terminates a table header or key/value pair. Both need
 * lookahead the generated lexer cannot express on its own.
 */
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
};

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
