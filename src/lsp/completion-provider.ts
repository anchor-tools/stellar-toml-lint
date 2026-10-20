import { parseCst } from '../cst/parser.js';
import {
  CURRENCY_FIELDS,
  DOCUMENTATION_FIELDS,
  FIELD_DOCS,
  GLOBAL_FIELDS,
  ANCHOR_TITLES,
  PRINCIPAL_FIELDS,
  VALIDATOR_FIELDS,
  qualifiedFieldName,
  specUrl,
} from '../spec.js';

export interface CompletionItem {
  label: string;
  kind: number;
  detail: string;
  documentation: { kind: 'markdown'; value: string };
  insertText: string;
  insertTextFormat: 1 | 2;
}

export interface CompletionList {
  isIncomplete: boolean;
  items: CompletionItem[];
}

const FIELDS: Record<string, readonly string[]> = {
  '': [...GLOBAL_FIELDS, 'DEPOSIT_SERVER'],
  DOCUMENTATION: DOCUMENTATION_FIELDS,
  PRINCIPALS: PRINCIPAL_FIELDS,
  CURRENCIES: CURRENCY_FIELDS,
  VALIDATORS: VALIDATOR_FIELDS,
};

const SNIPPETS: CompletionItem[] = [
  {
    label: 'new-currency-anchored',
    kind: 15,
    detail: 'New anchored currency table',
    documentation: { kind: 'markdown', value: 'Insert a complete `[[CURRENCIES]]` entry.' },
    insertText:
      '[[CURRENCIES]]\ncode = "${1:USD}"\nissuer = "${2:G...}"\nstatus = "${3:live}"\ndisplay_decimals = ${4:2}',
    insertTextFormat: 2,
  },
  {
    label: 'new-contract-sac',
    kind: 15,
    detail: 'New Stellar Asset Contract currency',
    documentation: { kind: 'markdown', value: 'Insert a currency entry backed by a SAC.' },
    insertText:
      '[[CURRENCIES]]\ncode = "${1:XLM}"\ncontract = "${2:C...}"\nstatus = "${3:live}"\ndisplay_decimals = ${4:7}',
    insertTextFormat: 2,
  },
  {
    label: 'new-validator-node',
    kind: 15,
    detail: 'New validator node table',
    documentation: { kind: 'markdown', value: 'Insert a complete `[[VALIDATORS]]` entry.' },
    insertText:
      '[[VALIDATORS]]\nALIAS = "${1:validator}"\nDISPLAY_NAME = "${2:Validator}"\nPUBLIC_KEY = "${3:G...}"\nHOST = "${4:example.com:11625}"\nHISTORY = "${5:https://example.com/history}"',
    insertTextFormat: 2,
  },
];

/** Returns SEP-1 fields and starter templates appropriate to the cursor table. */
export function getCompletionItems(
  source: string,
  position: { line: number; character: number },
): CompletionList {
  const lines = source.split('\n');
  const cursorLine = Math.max(0, Math.min(position.line, lines.length - 1));
  const cursorOffset =
    lines.slice(0, cursorLine).reduce((size, line) => size + line.length + 1, 0) +
    Math.max(0, Math.min(position.character, lines[cursorLine]?.length ?? 0));
  const document = parseCst(source);
  const tables = document.entries.filter((entry) => entry.kind !== 'key-value');
  const currentTable = [...tables].reverse().find((entry) => entry.start <= cursorOffset);
  const section = currentTable?.key?.path ?? '';
  const nextTable = tables.find((entry) => entry.start > (currentTable?.start ?? -1));
  const tableEnd = nextTable?.start ?? source.length;
  const declared = new Set(
    document.entries
      .filter(
        (entry) =>
          entry.kind === 'key-value' &&
          entry.start >= (currentTable?.start ?? 0) &&
          entry.start < tableEnd &&
          entry.key !== null,
      )
      .map((entry) => (entry.kind === 'key-value' ? entry.key?.path.split('.')[0] : undefined))
      .filter((key): key is string => key !== undefined),
  );

  const candidates = (FIELDS[section] ?? []).filter((field) => !declared.has(field));
  const items = candidates.map((field): CompletionItem => {
    const doc = FIELD_DOCS.find(
      (candidate) => candidate.section === section && candidate.name === field,
    );
    const qualified = qualifiedFieldName(section, field);
    const anchorTitle = doc ? (ANCHOR_TITLES[doc.anchor] ?? 'SEP-1') : 'SEP-1';
    const documentation = doc
      ? `**${qualified}** - *${doc.type}*\n\n${doc.description}\n\n[SEP-1 - ${anchorTitle}](${specUrl(doc.anchor)})`
      : `SEP-1 field ${qualified}`;
    return {
      label: field,
      kind: 10,
      detail: doc?.type ?? 'SEP-1 field',
      documentation: { kind: 'markdown', value: documentation },
      insertText: `${field} = "\${1}"`,
      insertTextFormat: 2,
    };
  });

  if (section === '') items.push(...SNIPPETS);
  if (section === 'CURRENCIES') items.push(...SNIPPETS.slice(0, 2));
  if (section === 'VALIDATORS') items.push(SNIPPETS[2]!);
  return { isIncomplete: false, items };
}
