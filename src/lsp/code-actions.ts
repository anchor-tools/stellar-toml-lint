/**
 * LSP `textDocument/codeAction` providers — interactive quick fixes (#42).
 *
 * The implementation moved to ./code-actions-provider.ts (#332) when quick
 * fixes grew missing-field insertions, a SAC-derivation refactor, and a
 * "Fix all auto-fixable problems in file" source action. This module
 * re-exports the provider so existing imports keep working.
 */
export { codeActionsFor, offsetToPosition, toLspDiagnostic } from './code-actions-provider.js';
export { CODE_ACTION_KINDS } from './code-actions-provider.js';
export type {
  LspCodeAction,
  LspCodeActionKind,
  LspDiagnostic,
  LspPosition,
  LspRange,
  LspTextEdit,
  LspWorkspaceEdit,
} from './code-actions-provider.js';
