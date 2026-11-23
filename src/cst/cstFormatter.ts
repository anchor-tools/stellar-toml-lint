/**
 * Lossless Concrete Syntax Tree (CST) whitespace and comment-preserving formatter.
 *
 * Formats, cleans, and programmatically mutates `stellar.toml` documents
 * while preserving every comment, whitespace trivia, delimiter, and untouched node
 * byte-for-byte. Guarantees round-trip idempotency f(f(x)) = f(x).
 */
import { readFile, writeFile } from 'node:fs/promises';
import { parseCst, printCst } from './parser.js';
import type {
  CstDocument,
  CstEntry,
  CstKeyValueEntry,
  CstTableEntry,
  CstKey,
  CstStringValue,
  CstValue,
} from './parser.js';

export interface FormatterOptions {
  /** Ensure document ends with a trailing newline if true (default: true). */
  trailingNewline?: boolean;
}

export class LosslessCstFormatter {
  /**
   * Formats a TOML source string losslessly.
   * Unmutated documents retain 100% byte-for-byte fidelity with comments and trivia preserved.
   */
  public format(source: string, options: FormatterOptions = { trailingNewline: true }): string {
    const doc = parseCst(source);
    let out = printCst(doc);

    if (options.trailingNewline && out.length > 0 && !out.endsWith('\n')) {
      out += '\n';
    }
    return out;
  }

  /**
   * Reads, formats, and optionally writes back a stellar.toml file.
   */
  public async formatFile(
    filePath: string,
    write: boolean = false,
  ): Promise<{ formatted: string; changed: boolean }> {
    const original = await readFile(filePath, 'utf8');
    const formatted = this.format(original);
    const changed = original !== formatted;

    if (write && changed) {
      await writeFile(filePath, formatted, 'utf8');
    }

    return { formatted, changed };
  }

  /**
   * Serializes a CST document back to its exact string representation.
   */
  public serialize(document: CstDocument): string {
    return printCst(document);
  }

  /**
   * Updates or inserts a top-level SIGNING_KEY while preserving existing trivia and quotes.
   */
  public updateSigningKey(doc: CstDocument, newKey: string): void {
    this.setKeyValue(doc, 'SIGNING_KEY', newKey);
  }

  /**
   * Programmatically updates or inserts a key-value pair in the CST.
   * If targetTable is provided, the entry is placed/updated in that table.
   */
  public setKeyValue(
    doc: CstDocument,
    keyPath: string,
    value: string | number | boolean,
    targetTable?: string,
  ): void {
    const upperTarget = targetTable ? targetTable.toUpperCase() : undefined;
    let inTargetTable = targetTable === undefined;

    for (const entry of doc.entries) {
      if (entry.kind === 'table' || entry.kind === 'array-table') {
        const tName = entry.key?.path?.toUpperCase();
        inTargetTable = upperTarget !== undefined && tName === upperTarget;
        continue;
      }

      if (entry.kind === 'key-value' && inTargetTable) {
        if (entry.key?.path === keyPath) {
          // Mutate value in place while preserving whitespace and equal signs
          entry.value = this.createValueNode(value, entry.value?.start ?? 0);
          return;
        }
      }
    }

    // If not found, create a new key-value entry and insert it
    const newEntry = this.createKeyValueEntry(keyPath, value);
    if (!targetTable) {
      // Insert before first table or append to root
      const firstTableIdx = doc.entries.findIndex(
        (e) => e.kind === 'table' || e.kind === 'array-table',
      );
      if (firstTableIdx >= 0) {
        doc.entries.splice(firstTableIdx, 0, newEntry);
      } else {
        doc.entries.push(newEntry);
      }
    } else {
      // Find the end of target table and insert
      let insertIdx = -1;
      let matched = false;
      for (let i = 0; i < doc.entries.length; i++) {
        const e = doc.entries[i]!;
        if (e.kind === 'table' || e.kind === 'array-table') {
          if (matched) {
            insertIdx = i;
            break;
          }
          if (e.key?.path?.toUpperCase() === upperTarget) {
            matched = true;
          }
        }
      }
      if (matched && insertIdx === -1) {
        insertIdx = doc.entries.length;
      }

      if (insertIdx >= 0) {
        doc.entries.splice(insertIdx, 0, newEntry);
      } else {
        // Table doesn't exist, create it
        const tableEntry: CstTableEntry = {
          kind: 'table',
          open: { start: 0, end: 1, text: '[' },
          keyLeading: [],
          key: this.createKeyNode(targetTable),
          keyTrailing: [],
          close: { start: 0, end: 1, text: ']' },
          leading: [{ kind: 'newline', text: '\n\n', start: 0, end: 2, line: 1, column: 1 }],
          trailing: [{ kind: 'newline', text: '\n', start: 0, end: 1, line: 1, column: 1 }],
          leadingComments: [],
          errors: [],
          start: 0,
          end: 0,
        };
        doc.entries.push(tableEntry);
        doc.entries.push(newEntry);
      }
    }
  }

  /**
   * Appends an entire [[CURRENCIES]] array table entry with child fields.
   */
  public addCurrencyTable(
    doc: CstDocument,
    currency: {
      code: string;
      issuer?: string;
      status?: string;
      display_decimals?: number;
      [k: string]: unknown;
    },
  ): void {
    const tableHeader: CstTableEntry = {
      kind: 'array-table',
      open: { start: 0, end: 2, text: '[[' },
      keyLeading: [],
      key: this.createKeyNode('CURRENCIES'),
      keyTrailing: [],
      close: { start: 0, end: 2, text: ']]' },
      leading: [{ kind: 'newline', text: '\n\n', start: 0, end: 2, line: 1, column: 1 }],
      trailing: [{ kind: 'newline', text: '\n', start: 0, end: 1, line: 1, column: 1 }],
      leadingComments: [],
      errors: [],
      start: 0,
      end: 0,
    };

    doc.entries.push(tableHeader);

    // Standard currency field ordering
    const keys = [
      'code',
      'issuer',
      'status',
      'display_decimals',
      ...Object.keys(currency).filter(
        (k) => !['code', 'issuer', 'status', 'display_decimals'].includes(k),
      ),
    ];

    for (const k of keys) {
      const val = currency[k];
      if (val !== undefined && val !== null) {
        if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
          doc.entries.push(this.createKeyValueEntry(k, val));
        }
      }
    }
  }

  /**
   * Programmatically removes a key-value entry by path.
   */
  public removeKey(doc: CstDocument, keyPath: string, targetTable?: string): boolean {
    const upperTarget = targetTable ? targetTable.toUpperCase() : undefined;
    let inTargetTable = targetTable === undefined;

    for (let i = 0; i < doc.entries.length; i++) {
      const entry = doc.entries[i]!;
      if (entry.kind === 'table' || entry.kind === 'array-table') {
        const tName = entry.key?.path?.toUpperCase();
        inTargetTable = upperTarget !== undefined && tName === upperTarget;
        continue;
      }

      if (entry.kind === 'key-value' && inTargetTable) {
        if (entry.key?.path === keyPath) {
          doc.entries.splice(i, 1);
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Reorders top-level sections according to the provided list of table names.
   */
  public reorderSections(doc: CstDocument, sectionOrder: string[]): void {
    const normalizedOrder = sectionOrder.map((s) => s.toUpperCase());

    // Separate root key-values from tables
    const rootEntries: CstEntry[] = [];
    const sections: { name: string; entries: CstEntry[] }[] = [];

    let currentSection: { name: string; entries: CstEntry[] } | undefined;

    for (const entry of doc.entries) {
      if (entry.kind === 'table' || entry.kind === 'array-table') {
        const name = (entry.key?.path ?? '').toUpperCase();
        currentSection = { name, entries: [entry] };
        sections.push(currentSection);
      } else if (currentSection) {
        currentSection.entries.push(entry);
      } else {
        rootEntries.push(entry);
      }
    }

    // Sort sections according to normalizedOrder
    sections.sort((a, b) => {
      let idxA = normalizedOrder.indexOf(a.name);
      let idxB = normalizedOrder.indexOf(b.name);
      if (idxA === -1) idxA = 999;
      if (idxB === -1) idxB = 999;
      return idxA - idxB;
    });

    // Reconstruct entries
    const newEntries: CstEntry[] = [...rootEntries];
    for (const s of sections) {
      newEntries.push(...s.entries);
    }
    doc.entries = newEntries;
  }

  private createKeyNode(path: string): CstKey {
    return {
      kind: 'key',
      path,
      start: 0,
      end: path.length,
      segments: [
        {
          kind: 'key-segment',
          text: path,
          name: path,
          quoted: false,
          start: 0,
          end: path.length,
          leading: [],
          trailing: [],
        },
      ],
    };
  }

  private createValueNode(val: string | number | boolean, start: number): CstValue {
    if (typeof val === 'string') {
      const escaped = JSON.stringify(val);
      return {
        kind: 'string',
        style: 'basic',
        raw: escaped,
        value: val,
        start,
        end: start + escaped.length,
      } as CstStringValue;
    } else if (typeof val === 'number') {
      const raw = String(val);
      return {
        kind: Number.isInteger(val) ? 'integer' : 'float',
        raw,
        value: val,
        start,
        end: start + raw.length,
      };
    } else {
      const raw = val ? 'true' : 'false';
      return {
        kind: 'boolean',
        raw,
        value: val,
        start,
        end: start + raw.length,
      };
    }
  }

  private createKeyValueEntry(keyPath: string, val: string | number | boolean): CstKeyValueEntry {
    const valNode = this.createValueNode(val, 0);
    return {
      kind: 'key-value',
      key: this.createKeyNode(keyPath),
      keyTrailing: [{ kind: 'whitespace', text: ' ', start: 0, end: 1, line: 1, column: 1 }],
      equals: { start: 0, end: 1, text: '=' },
      valueLeading: [{ kind: 'whitespace', text: ' ', start: 0, end: 1, line: 1, column: 1 }],
      value: valNode,
      leading: [],
      trailing: [{ kind: 'newline', text: '\n', start: 0, end: 1, line: 1, column: 1 }],
      leadingComments: [],
      errors: [],
      start: 0,
      end: 0,
    };
  }
}
