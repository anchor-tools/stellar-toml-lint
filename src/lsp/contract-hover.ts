/**
 * Contract error documentation for `textDocument/hover`.
 *
 * A Soroban contract's custom errors live in its own WASM: the
 * `contractspecv0` section carries every `#[contracterror]` enum as an
 * `ScSpecUdtErrorEnumV0` entry, with each case's integer code and doc
 * comment. Hovering a line that names a contract (`[[CURRENCIES]].contract`,
 * `WEB_AUTH_CONTRACT_ID`, or any `contract_id` key) turns those entries into a
 * Markdown table, so a failing `Error(Contract, #7)` can be read in the editor
 * instead of in the contract's Rust source.
 *
 * Resolving the WASM needs the Soroban RPC, so — like `--check-contracts` on
 * the command line — it only happens when the editor opts in. Results are
 * cached per contract ID for the life of the server.
 */
import { StrKey, cereal, xdr } from '@stellar/stellar-base';
import { wasmCustomSection } from '../soroban.js';
import type { Hover, HoverPosition } from './hover.js';

/** The WASM custom section Soroban stores a contract's spec entries in. */
const CONTRACT_SPEC_SECTION = 'contractspecv0';

/** A `C…` contract strkey anywhere on a line. */
const CONTRACT_ID_PATTERN = /\bC[A-Z2-7]{55}\b/g;

export interface ContractErrorCase {
  name: string;
  code: number;
  doc: string;
}

export interface ContractErrorEnum {
  name: string;
  doc: string;
  cases: ContractErrorCase[];
}

/**
 * The error enums a module's spec declares, or `undefined` when the module has
 * no readable spec section.
 */
export function contractErrorEnums(wasm: Buffer): ContractErrorEnum[] | undefined {
  const section = wasmCustomSection(wasm, CONTRACT_SPEC_SECTION);
  if (section === undefined) return undefined;

  try {
    const reader = new cereal.XdrReader(section);
    const enums: ContractErrorEnum[] = [];
    while (!reader.eof) {
      // Same cursor-based read as `specFunctionNames` in ../soroban.ts.
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      if (entry.switch().name !== 'scSpecEntryUdtErrorEnumV0') continue;
      const errorEnum = entry.udtErrorEnumV0();
      enums.push({
        name: errorEnum.name().toString(),
        doc: errorEnum.doc().toString(),
        cases: errorEnum.cases().map((c) => ({
          name: c.name().toString(),
          code: c.value(),
          doc: c.doc().toString(),
        })),
      });
    }
    return enums;
  } catch {
    return undefined;
  }
}

/** Keeps a doc comment on one table row: no pipes, no line breaks. */
function cell(text: string): string {
  return text
    .replace(/\|/g, '\\|')
    .replace(/\s*\n\s*/g, ' ')
    .trim();
}

/** Renders the error enums of `contractId` as the hover's Markdown. */
export function renderContractErrors(contractId: string, enums: ContractErrorEnum[]): string {
  const short = `${contractId.slice(0, 4)}…${contractId.slice(-4)}`;
  if (enums.length === 0) {
    return `**Contract errors** — \`${short}\`\n\nThe contract spec declares no custom error enums.`;
  }

  const parts = [`**Contract errors** — \`${short}\``];
  for (const errorEnum of enums) {
    const heading = errorEnum.doc
      ? `\`${errorEnum.name}\` — ${cell(errorEnum.doc)}`
      : `\`${errorEnum.name}\``;
    const rows = [...errorEnum.cases]
      .sort((a, b) => a.code - b.code)
      .map((c) => `| ${c.code} | \`${c.name}\` | ${cell(c.doc)} |`);
    parts.push(
      [heading, '', '| Code | Error | Description |', '| ---: | --- | --- |', ...rows].join('\n'),
    );
  }
  return parts.join('\n\n');
}

/** The contract ID on the hovered line, with its zero-based column span. */
export function contractIdAt(
  doc: string,
  position: HoverPosition,
): { id: string; start: number; end: number } | undefined {
  const line = doc.split(/\r?\n/)[position.line];
  if (line === undefined) return undefined;

  // Ignore anything after a comment marker so commented-out IDs don't resolve.
  const code = line.replace(/#.*$/, '');
  for (const match of code.matchAll(CONTRACT_ID_PATTERN)) {
    if (StrKey.isValidContract(match[0])) {
      return { id: match[0], start: match.index, end: match.index + match[0].length };
    }
  }
  return undefined;
}

/**
 * Resolves and caches contract error documentation. `loadWasm` is the only
 * network access, and is never called for a contract already looked up.
 */
export class ContractErrorDocs {
  private readonly cache = new Map<string, Promise<ContractErrorEnum[] | undefined>>();

  constructor(private readonly loadWasm: (contractId: string) => Promise<Buffer | undefined>) {}

  errorsFor(contractId: string): Promise<ContractErrorEnum[] | undefined> {
    let pending = this.cache.get(contractId);
    if (pending === undefined) {
      pending = this.loadWasm(contractId)
        .then((wasm) => (wasm === undefined ? undefined : contractErrorEnums(wasm)))
        .catch(() => undefined);
      this.cache.set(contractId, pending);
    }
    return pending;
  }
}

/**
 * Adds the contract's error table to `base` (the SEP-1 field hover, if any)
 * when the hovered line names a contract whose spec can be read. Returns
 * `base` unchanged otherwise.
 */
export async function withContractErrors(
  doc: string,
  position: HoverPosition,
  base: Hover | null,
  docs: ContractErrorDocs,
): Promise<Hover | null> {
  const target = contractIdAt(doc, position);
  if (target === undefined) return base;

  const enums = await docs.errorsFor(target.id);
  if (enums === undefined) return base;

  const errors = renderContractErrors(target.id, enums);
  if (base !== null) {
    return {
      ...base,
      contents: { kind: 'markdown', value: `${base.contents.value}\n\n---\n\n${errors}` },
    };
  }
  return {
    contents: { kind: 'markdown', value: errors },
    range: {
      start: { line: position.line, character: target.start },
      end: { line: position.line, character: target.end },
    },
  };
}
