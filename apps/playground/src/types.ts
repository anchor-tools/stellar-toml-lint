export interface DiagnosticPosition {
  line: number;
  column: number;
}

export interface Diagnostic {
  rule: string;
  severity: 'error' | 'warning' | 'info';
  category: string;
  message: string;
  path?: string;
  position?: DiagnosticPosition;
  helpUri?: string;
  suggestion?: string;
}

export interface LintResult {
  ok: boolean;
  counts: { errors: number; warnings: number; infos: number };
  diagnostics: Diagnostic[];
}
