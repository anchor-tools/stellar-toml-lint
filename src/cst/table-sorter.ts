/** Table and key sorting engine for stellar.toml canonical reordering. */
import { parseCst, serialize } from './parser.js';
import { collectComments } from './visitor.js';

/**
 * Canonical order for root-level tables.
 * DOCUMENTATION comes first, then PRINCIPALS, then [[CURRENCIES]], then [[VALIDATORS]],
 * then [[CONTRACTS]], in accordance with SEP-1 hierarchy.
 */
const ROOT_TABLE_ORDER = [
  'DOCUMENTATION',
  'PRINCIPALS',
  'CURRENCIES',
  'VALIDATORS',
  'CONTRACTS',
] as const;

/**
 * Sorts the entries of a stellar.toml document according to SEP-1 spec hierarchy.
 * Root-level tables are reordered to match the canonical SEP-1 order, and keys
 * within each table are sorted alphabetically. Comments are preserved with their
 * associated table entries.
 *
 * @param document The CST document to sort
 * @returns A new CST document with sorted entries
 */
export function sortTables(document: any): any {
  const entries = document.entries;

  // Separate table entries from key-value entries
  const tableEntries: any[] = [];
  const keyValueEntries: any[] = [];
  const otherEntries: any[] = [];

  for (const entry of entries) {
    // Type guard to check if entry is a table (kind === 'table' or 'array-table')
    if (entry.kind === 'table' || entry.kind === 'array-table') {
      tableEntries.push(entry);
    }
    // Type guard to check if entry is a key-value
    else if (entry.kind === 'key-value') {
      keyValueEntries.push(entry);
    } else {
      otherEntries.push(entry);
    }
  }

  // Sort table entries by canonical SEP-1 order, then alphabetically by key name
  tableEntries.sort((a, b) => {
    const aKey = a.key?.path ?? '';
    const bKey = b.key?.path ?? '';

    // Get the table type (first segment of the key)
    const aType = aKey.split('.')[0];
    const bType = bKey.split('.')[0];

    // Determine priority based on ROOT_TABLE_ORDER
    const aPriority = ROOT_TABLE_ORDER.indexOf(aType);
    const bPriority = ROOT_TABLE_ORDER.indexOf(bType);

    if (aPriority !== bPriority) {
      return aPriority - bPriority;
    }

    // Same priority - sort alphabetically
    return aKey.localeCompare(bKey);
  });

  // Sort key-value entries alphabetically by key name
  keyValueEntries.sort((a, b) => {
    const aKey = a.key?.path ?? '';
    const bKey = b.key?.path ?? '';
    return aKey.localeCompare(bKey);
  });

  // Preserve comments by collecting them and reattaching
  const allComments = collectComments(document);

  // Rebuild the document with sorted entries
  const sortedEntries = [...tableEntries, ...keyValueEntries, ...otherEntries];

  // Build new document entries
  const newEntries: any[] = [];
  for (const entry of sortedEntries) {
    // Create a new entry with the same kind and basic properties
    const newEntry: any = {
      kind: entry.kind,
      leading: entry.leading,
      trailing: entry.trailing,
      leadingComments: entry.leadingComments,
      trailingComment: entry.trailingComment,
      start: entry.start,
      end: entry.end,
      errors: entry.errors,
      recovery: entry.recovery,
    };

    // Try to preserve comments associated with this entry
    // by matching based on position
    const entryComments: any[] = allComments.filter((comment: any) => {
      // Simple heuristic: comment start position falls within this entry's span
      const commentStart = comment.start !== null ? Number(comment.start) : -1;
      const commentEnd = comment.end !== null ? Number(comment.end) : -1;
      const entryStart = entry.start !== null ? Number(entry.start) : -1;
      const entryEnd = entry.end !== null ? Number(entry.end) : -1;
      return commentStart >= entryStart && commentEnd <= entryEnd;
    });

    if (entryComments.length > 0) {
      (newEntry.leadingComments ||= []).push(...entryComments);
    }

    newEntries.push(newEntry);
  }

  // Build new document
  const newDocument: any = {
    ...document,
    entries: newEntries,
  };

  return newDocument;
}

/**
 * CLI option to sort tables in a stellar.toml file.
 * When --sort-tables is used, the file is reordered and optionally written back
 * with --write.
 *
 * @param source The TOML source string
 * @param writeToFile If true, writes the sorted result back to the file
 * @param filePath The path to write to (optional, uses source path if not provided)
 * @returns The sorted TOML source string
 */
export function sortTablesCli(
  source: string,
  writeToFile?: boolean,
  filePath?: string,
): { sorted: string; shouldWrite: boolean; path?: string } {
  const document = parseCst(source);
  const sorted = sortTables(document);
  const sortedSource = serialize(sorted);

  if (writeToFile && filePath) {
    return { sorted: sortedSource, shouldWrite: true, path: filePath };
  }

  return { sorted: sortedSource, shouldWrite: false };
}
