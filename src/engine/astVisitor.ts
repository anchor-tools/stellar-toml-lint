/**
 * AstVisitor interface and SemanticLintRule definitions.
 *
 * Provides lifecycle hooks for modular AST traversal and pluggable lint rules.
 */
import type { CstDocument, CstKeyValueEntry, CstTableEntry, CstValue } from '../cst/parser.js';
import type { Diagnostic, RuleCategory, Severity } from '../types.js';
import type { SourcePositions } from '../cst/lexer.js';

export interface AstRuleContext {
  ruleId: string;
  source: string;
  positions: SourcePositions;
  options: Record<string, unknown>;
  report(finding: {
    message: string;
    severity?: Severity;
    suggestion?: string;
    line?: number;
    column?: number;
    path?: string;
  }): void;
}

export type RuleContext = AstRuleContext;

export interface AstVisitor {
  enterDocument?(doc: CstDocument): void;
  exitDocument?(doc: CstDocument): void;
  enterTable?(entry: CstTableEntry, tableName: string): void;
  exitTable?(entry: CstTableEntry, tableName: string): void;
  visitKeyValue?(
    entry: CstKeyValueEntry,
    keyPath: string,
    value: CstValue | null,
    currentTable?: string,
  ): void;
  visitCurrency?(entry: CstTableEntry, fields: Map<string, string>): void;
  visitValidator?(entry: CstTableEntry, fields: Map<string, string>): void;
  visitDocumentation?(entry: CstTableEntry, fields: Map<string, string>): void;
}

export interface SemanticLintRule {
  id: string;
  category?: RuleCategory;
  severity?: Severity;
  description?: string;
  createVisitor(context: RuleContext): AstVisitor;
}

export interface RulePlugin {
  name: string;
  version?: string;
  rules: SemanticLintRule[];
}

export type PluggableDiagnostic = Diagnostic;
