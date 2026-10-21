/**
 * Barrel for the Concrete Syntax Tree subsystem.
 *
 * Re-exports the lossless parser, visitor, lexer, semantic hash, the
 * comment-preserving rewrite engine, and the incremental reparsing engine so
 * consumers can import the whole CST surface from one module.
 */
export {
  parseCst,
  parseOrThrow,
  printCst,
  serialize,
  firstError,
  CstParseError,
} from './parser.js';
export type {
  CstArrayItem,
  CstArrayValue,
  CstBooleanValue,
  CstComment,
  CstDateTimeValue,
  CstDocument,
  CstEntry,
  CstError,
  CstInlineEntry,
  CstInlineTableValue,
  CstInvalidValue,
  CstKey,
  CstKeySegment,
  CstKeyValueEntry,
  CstNumberValue,
  CstStringValue,
  CstTableEntry,
  CstTokenSpan,
  CstTrivia,
  CstValue,
} from './parser.js';

export {
  walk,
  keyValueEntries,
  tableEntries,
  collectComments,
  nodeAtOffset,
  evaluateDocument,
  toValue,
} from './visitor.js';
export type { CstNode, CstVisitor, EvaluationResult } from './visitor.js';

export { Lexer, tokenize, SourcePositions, isTrivia } from './lexer.js';
export type {
  LexContext,
  SourcePosition,
  StringStyle,
  Token,
  TokenKind,
  TriviaKind,
} from './lexer.js';

export { canonicalize, hashCanonical, semanticHash, semanticallyEqual } from './semantic-hash.js';
export type { SemanticHashResult } from './semantic-hash.js';

export {
  LosslessRewriter,
  rewrite,
  countComments,
  detectCommentLoss,
  evaluateRewritten,
  COMMENT_LOSS_RULE,
} from './lossless-rewrite.js';
export type { RewriteEdit, RewriteResult } from './lossless-rewrite.js';

export {
  IncrementalParser,
  computeLineDelta,
  type IncrementalParserOptions,
  type LineDelta,
  type ReparseResult,
} from './incremental-parser.js';

export {
  auditIndentation,
  detectIndentation,
  INDENT_STYLES,
  indentUnit,
  isIndentStyle,
  normalizeIndentation,
} from './indentation.js';
export type { IndentStyle, IndentationFinding, IndentationReport } from './indentation.js';
