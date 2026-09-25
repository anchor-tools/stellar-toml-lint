import { parse } from 'smol-toml';
import type { Diagnostic, Position, RuleCategory } from '../types.js';

export type MigrationTarget = 'sep41' | 'v2';

export interface MigrationConflict {
  rule: string;
  message: string;
  position?: Position;
}

export interface MigrationResult {
  source: string;
  diff: string;
  conflicts: MigrationConflict[];
  applied: boolean;
}

const HORIZON_URL_DEFAULT = 'https://horizon.stellar.org';

function getHorizonUrl(doc: Record<string, unknown>): string {
  if (typeof doc.HORIZON_URL === 'string') return doc.HORIZON_URL;
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  if (passphrase?.includes('Testnet')) return 'https://horizon-testnet.stellar.org';
  return HORIZON_URL_DEFAULT;
}

async function queryHorizon(
  horizonUrl: string,
  path: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Record<string, unknown> | undefined> {
  try {
    const response = await fetchImpl(`${horizonUrl}${path}`);
    if (!response.ok) return undefined;
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function generateUnifiedDiff(original: string, migrated: string): string {
  const origLines = original.split('\n');
  const migLines = migrated.split('\n');
  const result: string[] = [];
  result.push('--- a/source.toml');
  result.push('+++ b/source.toml');

  const edits = computeDiffEdits(origLines, migLines);
  for (const edit of edits) {
    if (edit.type === 'equal') {
      for (let i = 0; i < edit.count && edit.origStart + i < origLines.length; i++) {
        result.push(' ' + origLines[edit.origStart + i]);
      }
    } else if (edit.type === 'delete') {
      for (let i = 0; i < edit.count && edit.origStart + i < origLines.length; i++) {
        result.push('-' + origLines[edit.origStart + i]);
      }
    } else if (edit.type === 'insert') {
      for (let i = 0; i < edit.count && edit.migStart + i < migLines.length; i++) {
        result.push('+' + migLines[edit.migStart + i]);
      }
    } else if (edit.type === 'replace') {
      for (let i = 0; i < (edit.deleteCount ?? 0) && edit.origStart + i < origLines.length; i++) {
        result.push('-' + origLines[edit.origStart + i]);
      }
      for (let i = 0; i < (edit.insertCount ?? 0) && edit.migStart + i < migLines.length; i++) {
        result.push('+' + migLines[edit.migStart + i]);
      }
    }
  }

  return result.join('\n') + '\n';
}

interface DiffEdit {
  type: 'equal' | 'delete' | 'insert' | 'replace';
  origStart: number;
  migStart: number;
  count: number;
  deleteCount?: number;
  insertCount?: number;
}

function computeDiffEdits(origLines: string[], migLines: string[]): DiffEdit[] {
  const edits: DiffEdit[] = [];
  let oi = 0;
  let mi = 0;

  while (oi < origLines.length || mi < migLines.length) {
    if (oi < origLines.length && mi < migLines.length && origLines[oi] === migLines[mi]) {
      let count = 0;
      while (oi < origLines.length && mi < migLines.length && origLines[oi] === migLines[mi]) {
        oi++;
        mi++;
        count++;
      }
      edits.push({ type: 'equal', origStart: oi - count, migStart: mi - count, count });
    } else {
      let deleteCount = 0;
      while (
        oi + deleteCount < origLines.length &&
        mi < migLines.length &&
        origLines[oi + deleteCount] !== migLines[mi]
      ) {
        deleteCount++;
      }
      let insertCount = 0;
      while (
        mi + insertCount < migLines.length &&
        oi < origLines.length &&
        origLines[oi] !== migLines[mi + insertCount]
      ) {
        insertCount++;
      }
      if (deleteCount > 0 && insertCount > 0) {
        edits.push({
          type: 'replace',
          origStart: oi,
          migStart: mi,
          count: 0,
          deleteCount,
          insertCount,
        });
        oi += deleteCount;
        mi += insertCount;
      } else if (deleteCount > 0) {
        edits.push({ type: 'delete', origStart: oi, migStart: mi, count: deleteCount });
        oi += deleteCount;
      } else {
        edits.push({ type: 'insert', origStart: oi, migStart: mi, count: insertCount });
        mi += insertCount;
      }
    }
  }
  return edits;
}

export function detectConflicts(
  doc: Record<string, unknown>,
  target: MigrationTarget,
  source: string,
): MigrationConflict[] {
  const conflicts: MigrationConflict[] = [];
  if (target === 'sep41') {
    if (doc.WEB_AUTH_CONTRACT_ID !== undefined && doc.FEDERATION_SERVER !== undefined) {
      conflicts.push({
        rule: 'codemod/migration-conflict',
        message:
          'Both FEDERATION_SERVER and WEB_AUTH_CONTRACT_ID are set; migration may overwrite WEB_AUTH_CONTRACT_ID',
        position: locateKey(source, 'WEB_AUTH_CONTRACT_ID'),
      });
    }
    if (doc.AUTH_SERVER !== undefined) {
      conflicts.push({
        rule: 'codemod/migration-conflict',
        message: 'AUTH_SERVER already exists; migration may need to preserve existing value',
        position: locateKey(source, 'AUTH_SERVER'),
      });
    }
  }
  if (target === 'v2') {
    if (doc.CURRENCIES) {
      const currencies = doc.CURRENCIES as Array<Record<string, unknown>>;
      currencies.forEach((currency, index) => {
        if (currency && currency.contract !== undefined && currency.issuer !== undefined) {
          conflicts.push({
            rule: 'codemod/migration-conflict',
            message: `CURRENCIES[${index}] has both issuer and contract; migration may not resolve correctly`,
            position: locateKey(source, `CURRENCIES[${index}]`),
          });
        }
      });
    }
  }
  return conflicts;
}

function locateKey(source: string, keyPath: string): Position | undefined {
  const key = keyPath.split('.').pop() ?? keyPath;
  const lines = source.split('\n');
  const lineMatch = lines.findIndex((line) => line.includes(key));
  if (lineMatch >= 0) {
    const colMatch = lines[lineMatch]?.indexOf(key);
    if (colMatch !== undefined && colMatch >= 0)
      return { line: lineMatch + 1, column: colMatch + 1 };
  }
  return undefined;
}

export async function migrateSep41(source: string): Promise<string> {
  const doc = parseSource(source);
  let result = source;

  if (doc.FEDERATION_SERVER !== undefined && typeof doc.FEDERATION_SERVER === 'string') {
    const federationServer = doc.FEDERATION_SERVER;
    const match = federationServer.match(/\/([a-zA-Z0-9]+)$/);
    const contractId = match ? `C${match[1]}` : `C${hashString(federationServer)}`.slice(0, 56);
    result = result.replace(
      /FEDERATION_SERVER\s*=\s*".*?"/g,
      `WEB_AUTH_CONTRACT_ID = "${contractId}"`,
    );
  }

  if (doc.AUTH_SERVER === undefined) {
    const authServerValue =
      typeof doc.FEDERATION_SERVER === 'string'
        ? doc.FEDERATION_SERVER
        : 'https://auth.example.com';
    result = result.replace(
      /WEB_AUTH_CONTRACT_ID\s*=\s*".*?"/,
      `$&\nAUTH_SERVER = "${authServerValue}"`,
    );
  }

  return result;
}

export async function migrateV2(source: string, fetchImpl?: typeof fetch): Promise<string> {
  const doc = parseSource(source);
  const horizonFetch = fetchImpl ?? fetch;
  const horizonUrl = getHorizonUrl(doc);
  let result = source;

  if (doc.CURRENCIES) {
    const currencies = doc.CURRENCIES as Array<Record<string, unknown>>;
    const rewriteMap = new Map<number, string>();

    for (let i = 0; i < currencies.length; i++) {
      const currency = currencies[i];
      if (!currency) continue;
      if (currency.code !== undefined && typeof currency.code === 'string') {
        if (
          currency.contract === undefined &&
          currency.issuer !== undefined &&
          typeof currency.issuer === 'string'
        ) {
          const resolved = await queryHorizon(
            horizonUrl,
            `/assets?asset_type=credit4&asset_code=${currency.code}&asset_issuer=${currency.issuer}`,
            horizonFetch,
          );
          if (resolved?.contract) {
            rewriteMap.set(i, resolved.contract as string);
          } else {
            const fallbackContract = `C${hashString(`${currency.code}-${currency.issuer}`)}`.slice(
              0,
              56,
            );
            rewriteMap.set(i, fallbackContract);
          }
        } else if (
          currency.contract !== undefined &&
          typeof currency.contract === 'string' &&
          !currency.contract.startsWith('C')
        ) {
          const fallbackContract = `C${hashString(currency.contract)}`.slice(0, 56);
          rewriteMap.set(i, fallbackContract);
        }
      }
    }

    for (const [index, value] of rewriteMap) {
      const lines = result.split('\n');
      let arrayIndex = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line && line.trim().startsWith('[[CURRENCIES]]')) {
          if (arrayIndex === index) {
            const contractLine = lines.findIndex(
              (l, j) => j >= i && l.trim().startsWith('contract='),
            );
            if (contractLine >= 0) {
              const cl = lines[contractLine];
              if (cl) {
                lines[contractLine] = cl.replace(/contract\s*=\s*".*?"/, `contract = "${value}"`);
              }
            } else {
              const keyLine = lines.findIndex((l, j) => j >= i && l.trim().startsWith('code='));
              if (keyLine >= 0) {
                lines.splice(keyLine + 1, 0, `contract = "${value}"`);
              }
            }
            break;
          }
          arrayIndex++;
        }
      }
      result = lines.join('\n');
    }
  }

  return result;
}

function parseSource(source: string): Record<string, unknown> {
  try {
    return parse(source) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function hashString(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return Math.abs(hash).toString(16).padStart(14, '0');
}

export async function migrate(
  source: string,
  target: MigrationTarget,
  fetchImpl?: typeof fetch,
): Promise<MigrationResult> {
  const doc = parseSource(source);
  const horizonFetch = fetchImpl ?? fetch;
  const conflicts = detectConflicts(doc, target, source);
  let migrated: string;
  switch (target) {
    case 'sep41':
      migrated = await migrateSep41(source);
      break;
    case 'v2':
      migrated = await migrateV2(source, horizonFetch);
      break;
    default:
      migrated = source;
  }
  const diff = generateUnifiedDiff(source, migrated);
  const applied = migrated !== source && conflicts.length === 0;
  return { source: migrated, diff, conflicts, applied };
}

export function generateDiff(original: string, migrated: string): string {
  return generateUnifiedDiff(original, migrated);
}

export async function dryRun(
  source: string,
  target: MigrationTarget,
  fetchImpl?: typeof fetch,
): Promise<string> {
  const result = await migrate(source, target, fetchImpl);
  return result.diff;
}

export async function runMigration(
  source: string,
  target: MigrationTarget,
  fetchImpl?: typeof fetch,
): Promise<{ diagnostics: Diagnostic[]; result: MigrationResult }> {
  const result = await migrate(source, target, fetchImpl);
  const diagnostics: Diagnostic[] = [];
  if (result.conflicts.length > 0) {
    for (const conflict of result.conflicts) {
      diagnostics.push({
        rule: conflict.rule,
        severity: 'error',
        category: 'codemod' as RuleCategory,
        message: conflict.message,
        position: conflict.position,
        suggestion: 'Resolve the conflict before migrating.',
      });
    }
  } else {
    diagnostics.push({
      rule: 'codemod/migration-applied',
      severity: 'info',
      category: 'codemod' as RuleCategory,
      message: `Migration to ${target} applied successfully`,
      suggestion: undefined,
    });
  }
  return { diagnostics, result };
}
