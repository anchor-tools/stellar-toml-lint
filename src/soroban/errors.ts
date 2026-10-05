/**
 * The custom error catalogue a Soroban contract ships in its own spec.
 *
 * `#[contracterror]` enums are compiled into `contractspecv0` as
 * `ScSpecUdtErrorEnumV0` entries, and what reaches a wallet on a failed
 * invocation is a bare integer. Integrators therefore decode that integer
 * against the contract's own table, so the table has to be readable, unique,
 * and encodable: two cases sharing one code make the catalogue ambiguous, and a
 * code that does not fit the user range is read back as a *host* error rather
 * than as the contract's own.
 *
 * The reserved host ranges below are not hand-typed — they are read out of the
 * same XDR tables {@link https://github.com/stellar/stellar-xdr stellar-xdr}
 * ships, so the audit cannot drift away from the network's own definitions.
 */
import { xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { fetchContractWasm } from '../soroban.js';
import { extractContractSpecEntries } from './wasm-auditor.js';
import { declaredContractRoots, rpcUrlForDocument } from './dependency-graph.js';

const DUPLICATE_ERROR_CODE_RULE = 'soroban/duplicate-error-code';
const SYSTEM_ERROR_CODE_COLLISION_RULE = 'soroban/system-error-code-collision';

/**
 * Where a contract error is reported: the `contractspecv0` section is part of
 * the deployed WASM rather than of `stellar.toml`, so the file path alone is
 * what a maintainer can act on.
 */
const ERROR_HELP_URI = 'https://github.com/stellar/stellar-xdr';

/**
 * The largest code a contract error can carry.
 *
 * `ScError` reports a contract failure as a type plus a code, and the type is
 * one of the ten `ScErrorType` categories the host owns — `sceContract` for the
 * contract's own errors and the nine system categories beside it. Soroban packs
 * that category into the top 4 bits of the returned `uint32`, which leaves the
 * low 28 bits for user codes. A code above this limit is not a large user
 * error; it arrives already reinterpreted as one of the host categories, so the
 * contract's intended name is unrecoverable.
 */
export const MAX_USER_ERROR_CODE = 0x0fff_ffff;

/** Every `ScErrorType` the host reports, as `{ name, code }` rows. */
export interface HostErrorCategory {
  name: string;
  code: number;
}

/**
 * The error categories that are the host's, not the contract's — everything
 * except `sceContract`. Codes in these categories mean "the environment
 * failed", never "this contract rejected the call". Values come from the XDR
 * enum itself so the table cannot drift from the network's definitions.
 */
export const SYSTEM_ERROR_CATEGORIES: readonly HostErrorCategory[] = [
  xdr.ScErrorType.sceWasmVm(),
  xdr.ScErrorType.sceContext(),
  xdr.ScErrorType.sceStorage(),
  xdr.ScErrorType.sceObject(),
  xdr.ScErrorType.sceCrypto(),
  xdr.ScErrorType.sceEvents(),
  xdr.ScErrorType.sceBudget(),
  xdr.ScErrorType.sceValue(),
  xdr.ScErrorType.sceAuth(),
].map((category) => ({ name: category.name, code: category.value }));

/** One `#[contracterror]` enum case, as the spec declares it. */
export interface SorobanErrorCase {
  /** The enum the case belongs to, e.g. `Error`. */
  enumName: string;
  /** The case name integrators decode to, e.g. `NotAuthorized`. */
  name: string;
  /** The integer a failed invocation reports. */
  code: number;
  /** The doc string the contract ships with the case, possibly empty. */
  doc: string;
}

/** One error enum from a contract's spec. */
export interface SorobanErrorEnum {
  name: string;
  /** The crate the enum came from; empty for the contract's own. */
  lib: string;
  doc: string;
  cases: SorobanErrorCase[];
}

/** The flattened catalogue, plus everything wrong with it. */
export interface SorobanErrorMatrix {
  enums: SorobanErrorEnum[];
  /** Every case, sorted by code then name — the matrix a wallet reads. */
  cases: SorobanErrorCase[];
  /** Code groups claimed by more than one case. */
  duplicates: SorobanErrorCase[][];
  /** Cases whose code cannot survive the wire as a contract error. */
  colliding: SorobanErrorCase[];
  /** Cases shipped without a doc string. */
  undocumented: SorobanErrorCase[];
}

interface MatrixOptions {
  rules?: RuleOverrides;
  /** The file that named the contract, attached to every diagnostic. */
  path?: string;
  contractId?: string;
}

function text(value: Uint8Array | string | undefined): string {
  if (value === undefined) return '';
  return typeof value === 'string' ? value : Buffer.from(value).toString('utf8');
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * Every `ScSpecEntry` a contract's WASM carries. The reader is the one the SEP-41
 * auditor uses, so a gzip- or zlib-compressed code entry decodes here too.
 */
function specEntries(wasm: Buffer): xdr.ScSpecEntry[] {
  return extractContractSpecEntries(wasm) ?? [];
}

/**
 * The error enums a contract's WASM declares. An empty array means either that
 * the contract defines no errors or that its spec could not be read — the two
 * are deliberately not distinguished, because neither is a finding.
 */
export function parseContractErrorSpecs(wasm: Buffer): SorobanErrorEnum[] {
  const enums: SorobanErrorEnum[] = [];

  for (const entry of specEntries(wasm)) {
    if (entry.switch().name !== 'scSpecEntryUdtErrorEnumV0') continue;
    const errorEnum = entry.udtErrorEnumV0();
    const cases = (errorEnum.cases() ?? []).map((caseValue) => ({
      enumName: text(errorEnum.name()),
      name: text(caseValue.name()),
      code: Number(caseValue.value()),
      doc: text(caseValue.doc()),
    }));
    enums.push({
      name: text(errorEnum.name()),
      lib: text(errorEnum.lib()),
      doc: text(errorEnum.doc()),
      cases,
    });
  }

  return enums;
}

/** Cases sharing a code, in ascending code order, only where they collide. */
function duplicateGroups(cases: SorobanErrorCase[]): SorobanErrorCase[][] {
  const byCode = new Map<number, SorobanErrorCase[]>();
  for (const one of cases) {
    const group = byCode.get(one.code) ?? [];
    group.push(one);
    byCode.set(one.code, group);
  }
  return [...byCode.entries()]
    .filter(([, group]) => group.length > 1)
    .sort((a, b) => a[0] - b[0])
    .map(([, group]) => group);
}

/**
 * Flattens an enum list into the matrix a wallet decodes against, and reports
 * what is wrong with it. Pure: no network, no file access.
 */
export function buildErrorCodeMatrix(enums: SorobanErrorEnum[]): SorobanErrorMatrix {
  const cases = enums
    .flatMap((one) => one.cases)
    .sort(
      (a, b) =>
        a.code - b.code || a.enumName.localeCompare(b.enumName) || a.name.localeCompare(b.name),
    );

  return {
    enums,
    cases,
    duplicates: duplicateGroups(cases),
    colliding: cases.filter((one) => !Number.isInteger(one.code) || one.code > MAX_USER_ERROR_CODE),
    undocumented: cases.filter((one) => one.doc.trim() === ''),
  };
}

/** The diagnostics for one matrix: duplicates first, then collisions. */
export function errorCodeMatrixDiagnostics(
  matrix: SorobanErrorMatrix,
  options: MatrixOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const subject = options.contractId ?? 'the contract';

  for (const group of matrix.duplicates) {
    const severity = severityFor(DUPLICATE_ERROR_CODE_RULE, 'error', options.rules);
    if (severity === undefined) continue;
    const code = group[0]?.code as number;
    diagnostics.push({
      rule: DUPLICATE_ERROR_CODE_RULE,
      severity,
      category: 'network',
      message: `${subject} declares ${group
        .map((one) => `${one.enumName}::${one.name}`)
        .join(' and ')} with the same error code ${code}`,
      ...(options.path !== undefined ? { path: options.path } : {}),
      helpUri: ERROR_HELP_URI,
      suggestion:
        'A failed call reports only an integer, so integrators cannot tell two cases sharing it apart. Give each case its own code.',
    });
  }

  for (const one of matrix.colliding) {
    const severity = severityFor(SYSTEM_ERROR_CODE_COLLISION_RULE, 'error', options.rules);
    if (severity === undefined) continue;
    diagnostics.push({
      rule: SYSTEM_ERROR_CODE_COLLISION_RULE,
      severity,
      category: 'network',
      message: `${subject} error ${one.enumName}::${one.name} uses code ${one.code}, outside the ${
        MAX_USER_ERROR_CODE
      } codes a contract error can carry`,
      ...(options.path !== undefined ? { path: options.path } : {}),
      helpUri: ERROR_HELP_URI,
      suggestion: `The top bits of the returned code name the ${SYSTEM_ERROR_CATEGORIES.length} host error categories, so ${one.code} is read back as a system failure. Renumber it below ${MAX_USER_ERROR_CODE}.`,
    });
  }

  return diagnostics;
}

/**
 * Reads a contract's WASM and audits its error catalogue in one step.
 * `undefined` wasm — the contract is absent, archived, native, or the RPC did
 * not answer — yields no diagnostics, because there is nothing to judge.
 */
export function checkContractErrorCodes(
  wasm: Buffer | undefined,
  options: MatrixOptions = {},
): Diagnostic[] {
  if (wasm === undefined) return [];
  return errorCodeMatrixDiagnostics(buildErrorCodeMatrix(parseContractErrorSpecs(wasm)), options);
}

/** One declared contract, with the catalogue its deployed WASM ships. */
export interface ContractErrorCatalogue {
  contractId: string;
  /** The `stellar.toml` path that named the contract. */
  path: string;
  matrix: SorobanErrorMatrix;
}

interface CatalogueOptions {
  rules?: RuleOverrides;
  /** The RPC to read contract WASM from; defaults to the declared network's. */
  rpcUrl?: string;
}

/** The catalogues a file's contracts ship, and the findings across them. */
export interface ContractErrorAudit {
  catalogues: ContractErrorCatalogue[];
  diagnostics: Diagnostic[];
}

/**
 * The document-level entry point for `--check-contracts`: read the error
 * catalogue of every contract the file declares and audit them together.
 *
 * A contract whose WASM cannot be read is skipped rather than reported — the
 * absence is already a finding of the TTL and existence checks, and this rule
 * set is about codes, which an unreadable catalogue cannot speak to.
 */
export async function checkContractErrorCatalogues(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: CatalogueOptions = {},
): Promise<ContractErrorAudit> {
  const rpcUrl = options.rpcUrl ?? rpcUrlForDocument(doc);
  if (rpcUrl === undefined) return { catalogues: [], diagnostics: [] };

  const catalogues: ContractErrorCatalogue[] = [];
  for (const { id, path } of declaredContractRoots(doc)) {
    const wasm = await fetchContractWasm(id, rpcUrl, fetchImpl);
    if (wasm === undefined) continue;
    catalogues.push({
      contractId: id,
      path,
      matrix: buildErrorCodeMatrix(parseContractErrorSpecs(wasm)),
    });
  }

  return {
    catalogues,
    diagnostics: catalogues.flatMap(({ contractId, path, matrix }) =>
      errorCodeMatrixDiagnostics(matrix, {
        ...(options.rules === undefined ? {} : { rules: options.rules }),
        path,
        contractId,
      }),
    ),
  };
}

/** The catalogues as text, one block per contract, for `--show-help-urls`. */
export function formatContractErrorCatalogues(
  catalogues: readonly ContractErrorCatalogue[],
  options: { helpUrls?: boolean } = {},
): string {
  return catalogues
    .map(({ contractId, matrix }) =>
      formatErrorCodeMatrix(matrix, { contractId, helpUrls: options.helpUrls }),
    )
    .join('\n');
}

function pad(value: number, width: number): string {
  return String(value).padStart(width);
}

/**
 * Renders the catalogue as the text matrix `--format text --show-help-urls`
 * prints: one row per code, the host categories it must not be confused with,
 * and a footnote per case that has a doc string worth reading.
 */
export function formatErrorCodeMatrix(
  matrix: SorobanErrorMatrix,
  options: { contractId?: string; helpUrls?: boolean } = {},
): string {
  const lines: string[] = [];
  const title = options.contractId ?? 'Soroban contract';
  lines.push(`${title} error code matrix`);

  if (matrix.cases.length === 0) {
    lines.push('  (the contract declares no custom errors)');
    return `${lines.join('\n')}\n`;
  }

  const width = Math.max(4, ...matrix.cases.map((one) => String(one.code).length));
  for (const one of matrix.cases) {
    const marked = matrix.duplicates.some((group) => group.includes(one))
      ? '  <- duplicate'
      : matrix.colliding.includes(one)
        ? '  <- collides with a host error code'
        : '';
    lines.push(`  ${pad(one.code, width)}  ${one.enumName}::${one.name}${marked}`);
  }

  if (matrix.undocumented.length > 0) {
    lines.push('');
    lines.push(
      `  ${matrix.undocumented.length} case(s) ship without a doc string: ${matrix.undocumented
        .map((one) => `${one.enumName}::${one.name}`)
        .join(', ')}`,
    );
  }

  if (options.helpUrls) {
    lines.push('');
    lines.push(`  ${ERROR_HELP_URI}`);
    lines.push(
      `  host categories: ${SYSTEM_ERROR_CATEGORIES.map((one) => `${one.name}=${one.code}`).join(', ')}`,
    );
  }

  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sorobanErrorRules: Rule[] = [
  {
    id: DUPLICATE_ERROR_CODE_RULE,
    category: 'network',
    severity: 'error',
    description: "Two of a Soroban contract's custom errors share an integer code",
    run() {},
  },
  {
    id: SYSTEM_ERROR_CODE_COLLISION_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban custom error code falls into the range the host reserves for itself',
    run() {},
  },
];

/** Rule ids emitted by {@link errorCodeMatrixDiagnostics}. */
export const sorobanErrorRuleIds: readonly string[] = sorobanErrorRules.map((rule) => rule.id);
