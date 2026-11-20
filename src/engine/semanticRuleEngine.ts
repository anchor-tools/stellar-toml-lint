/**
 * Automated semantic AST lint rule engine and pluggable rule loader.
 *
 * Implements a high-performance single-pass AST visitor traversal engine
 * supporting external rule plugins, dynamic directory loading, and configurable
 * severities from `.stellartomllintrc.json`.
 */
import { readdir } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseCst, type CstDocument, type CstTableEntry } from '../cst/parser.js';
import { SourcePositions } from '../cst/lexer.js';
import type { Diagnostic, LintResult, Severity } from '../types.js';
import type { AstVisitor, RuleContext, RulePlugin, SemanticLintRule } from './astVisitor.js';

export class SemanticRuleEngine {
  private readonly rules = new Map<string, SemanticLintRule>();
  private readonly severities = new Map<string, Severity | 'off'>();
  private readonly ruleOptions = new Map<string, Record<string, unknown>>();

  /**
   * Registers a single semantic lint rule with schema validation.
   */
  public registerRule(rule: SemanticLintRule): void {
    if (!rule || typeof rule.id !== 'string' || !rule.id.trim()) {
      throw new Error('Invalid rule: rule must have a non-empty string id');
    }
    if (typeof rule.createVisitor !== 'function') {
      throw new Error(`Invalid rule '${rule.id}': createVisitor must be a function`);
    }

    this.rules.set(rule.id, rule);
    if (rule.severity && !this.severities.has(rule.id)) {
      this.severities.set(rule.id, rule.severity);
    }
  }

  /**
   * Registers a third-party rule plugin containing multiple rules.
   */
  public registerPlugin(plugin: RulePlugin): void {
    if (!plugin || typeof plugin.name !== 'string' || !plugin.name.trim()) {
      throw new Error('Invalid plugin: plugin must have a non-empty string name');
    }
    if (!Array.isArray(plugin.rules)) {
      throw new Error(`Invalid plugin '${plugin.name}': rules must be an array`);
    }

    for (const rule of plugin.rules) {
      this.registerRule(rule);
    }
  }

  /**
   * Configures rule severities (e.g. from `.stellartomllintrc.json`).
   */
  public configureSeverities(config: Record<string, Severity | 'off'>): void {
    for (const [ruleId, severity] of Object.entries(config)) {
      this.severities.set(ruleId, severity);
    }
  }

  /**
   * Dynamically loads rule plugins from a directory of .js / .mjs files.
   */
  public async loadRulesFromDir(dirPath: string): Promise<number> {
    const fullPath = resolve(dirPath);
    let loadedCount = 0;

    try {
      const files = await readdir(fullPath);
      for (const file of files) {
        const ext = extname(file);
        if (ext === '.js' || ext === '.mjs') {
          const filePath = resolve(fullPath, file);
          const imported = await import(pathToFileURL(filePath).href);
          const pluginOrRule = imported.default ?? imported.rule ?? imported.plugin;

          if (pluginOrRule) {
            if (Array.isArray(pluginOrRule.rules)) {
              this.registerPlugin(pluginOrRule as RulePlugin);
              loadedCount += pluginOrRule.rules.length;
            } else if (typeof pluginOrRule.createVisitor === 'function') {
              this.registerRule(pluginOrRule as SemanticLintRule);
              loadedCount++;
            }
          }
        }
      }
    } catch (err) {
      throw new Error(`Failed to load rules from directory '${dirPath}': ${String(err)}`, {
        cause: err,
      });
    }

    return loadedCount;
  }

  /**
   * Dynamically loads an external rule plugin by module name or path.
   */
  public async loadPlugin(moduleOrPath: string): Promise<RulePlugin> {
    try {
      const isPath = moduleOrPath.startsWith('.') || moduleOrPath.startsWith('/');
      const target = isPath ? pathToFileURL(resolve(moduleOrPath)).href : moduleOrPath;
      const imported = await import(target);
      const plugin: RulePlugin = imported.default ?? imported.plugin ?? imported;

      this.registerPlugin(plugin);
      return plugin;
    } catch (err) {
      throw new Error(`Failed to load plugin '${moduleOrPath}': ${String(err)}`, { cause: err });
    }
  }

  /**
   * Returns all currently registered rule IDs.
   */
  public getRegisteredRules(): string[] {
    return Array.from(this.rules.keys());
  }

  /**
   * Runs all active semantic rules against the TOML source in a single AST visitor pass.
   */
  public run(sourceOrDoc: string | CstDocument): LintResult {
    const doc = typeof sourceOrDoc === 'string' ? parseCst(sourceOrDoc) : sourceOrDoc;
    const source = doc.source;
    const positions = new SourcePositions(source);
    const diagnostics: Diagnostic[] = [];

    // Filter active rules and instantiate visitors
    const activeVisitors: { ruleId: string; visitor: AstVisitor; defaultSeverity: Severity }[] = [];

    for (const [id, rule] of this.rules.entries()) {
      const configuredSeverity = this.severities.get(id);
      if (configuredSeverity === 'off') continue;

      const ruleSeverity: Severity = configuredSeverity ?? rule.severity ?? 'error';
      const context: RuleContext = {
        ruleId: id,
        source,
        positions,
        options: this.ruleOptions.get(id) ?? {},
        report: (finding) => {
          const sev = finding.severity ?? ruleSeverity;
          const line = finding.line ?? 1;
          const column = finding.column ?? 1;

          diagnostics.push({
            rule: id,
            category: rule.category ?? 'general',
            severity: sev,
            message: finding.message,
            suggestion: finding.suggestion,
            path: finding.path,
            position: { line, column },
          });
        },
      };

      try {
        const visitor = rule.createVisitor(context);
        activeVisitors.push({ ruleId: id, visitor, defaultSeverity: ruleSeverity });
      } catch (err) {
        diagnostics.push({
          rule: id,
          category: 'general',
          severity: 'error',
          message: `Rule '${id}' failed to initialize: ${String(err)}`,
          position: { line: 1, column: 1 },
        });
      }
    }

    const safeCall = (fn?: () => void, ruleId?: string) => {
      if (!fn) return;
      try {
        fn();
      } catch (err) {
        diagnostics.push({
          rule: ruleId ?? 'plugin-runtime',
          category: 'general',
          severity: 'error',
          message: `Plugin execution error in rule '${ruleId}': ${String(err)}`,
          position: { line: 1, column: 1 },
        });
      }
    };

    // 1. enterDocument
    for (const v of activeVisitors) {
      safeCall(() => v.visitor.enterDocument?.(doc), v.ruleId);
    }

    // 2. Single-pass entry traversal
    let currentTableEntry: CstTableEntry | undefined = undefined;
    let currentTableName: string | undefined = undefined;
    let currentTableFields = new Map<string, string>();

    const dispatchTableExit = () => {
      if (!currentTableEntry || !currentTableName) return;

      const upper = currentTableName.toUpperCase();
      for (const v of activeVisitors) {
        safeCall(() => {
          v.visitor.exitTable?.(currentTableEntry!, currentTableName!);
          if (upper === 'CURRENCIES')
            v.visitor.visitCurrency?.(currentTableEntry!, currentTableFields);
          else if (upper === 'VALIDATORS')
            v.visitor.visitValidator?.(currentTableEntry!, currentTableFields);
          else if (upper === 'DOCUMENTATION')
            v.visitor.visitDocumentation?.(currentTableEntry!, currentTableFields);
        }, v.ruleId);
      }
    };

    for (const entry of doc.entries) {
      if (entry.kind === 'table' || entry.kind === 'array-table') {
        dispatchTableExit();

        currentTableEntry = entry;
        currentTableName = entry.key?.path ?? 'anonymous';
        currentTableFields = new Map<string, string>();

        for (const v of activeVisitors) {
          safeCall(() => v.visitor.enterTable?.(entry, currentTableName!), v.ruleId);
        }
      } else if (entry.kind === 'key-value') {
        const keyName = entry.key?.path ?? '';
        const valStr =
          entry.value?.kind === 'string'
            ? entry.value.value
            : entry.value
              ? source.slice(entry.value.start, entry.value.end)
              : '';
        if (keyName) {
          currentTableFields.set(keyName.toLowerCase(), valStr);
        }

        for (const v of activeVisitors) {
          safeCall(
            () => v.visitor.visitKeyValue?.(entry, keyName, entry.value, currentTableName),
            v.ruleId,
          );
        }
      }
    }

    dispatchTableExit();

    // 3. exitDocument
    for (const v of activeVisitors) {
      safeCall(() => v.visitor.exitDocument?.(doc), v.ruleId);
    }

    const counts = {
      error: diagnostics.filter((d) => d.severity === 'error').length,
      warning: diagnostics.filter((d) => d.severity === 'warning').length,
      info: diagnostics.filter((d) => d.severity === 'info').length,
    };

    return {
      diagnostics,
      ok: counts.error === 0,
      counts,
    };
  }
}
