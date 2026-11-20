import fs from 'node:fs';
import { parse as parseToml } from 'smol-toml';

export type DiffChangeType = 'added' | 'removed' | 'modified' | 'unchanged';

export interface SemanticDelta {
  path: string;
  type: DiffChangeType;
  oldValue?: unknown;
  newValue?: unknown;
  isBreaking: boolean;
  breakingReason?: string;
}

export interface BreakingChange {
  path: string;
  category: 'currency' | 'validator' | 'signing_key' | 'service_endpoint' | 'version' | 'schema';
  message: string;
  oldValue?: unknown;
  newValue?: unknown;
}

export interface SemanticDiffResult {
  hasDifferences: boolean;
  hasBreakingChanges: boolean;
  deltas: SemanticDelta[];
  breakingChanges: BreakingChange[];
  summary: {
    added: number;
    removed: number;
    modified: number;
    breaking: number;
  };
}

export interface DifferOptions {
  fetchImpl?: typeof fetch;
  color?: boolean;
}

const KNOWN_SEP_ENDPOINTS: Record<string, string> = {
  TRANSFER_SERVER: 'SEP-6 / SEP-24 Transfer Server',
  TRANSFER_SERVER_0_0_2: 'SEP-6 Transfer Server v0.0.2',
  KYC_SERVER: 'SEP-12 KYC Server',
  WEB_AUTH_ENDPOINT: 'SEP-10 Web Authentication Endpoint',
  FEDERATION_SERVER: 'SEP-2 Federation Server',
  ANCHOR_QUOTE_SERVER: 'SEP-38 Anchor RFQ/Quote Server',
  DIRECT_PAYMENT_SERVER: 'SEP-31 Direct Payment Server',
};

export class SemanticTomlDiffer {
  private fetchImpl: typeof fetch;

  constructor(options?: DifferOptions) {
    this.fetchImpl =
      options?.fetchImpl ??
      (typeof fetch !== 'undefined' ? fetch : (undefined as unknown as typeof fetch));
  }

  /**
   * Parse and compare two TOML string inputs semantically.
   */
  public diffTexts(sourceToml: string, targetToml: string): SemanticDiffResult {
    const sourceObj = this.safeParse(sourceToml, 'source');
    const targetObj = this.safeParse(targetToml, 'target');

    return this.diffObjects(sourceObj, targetObj);
  }

  /**
   * Load and compare two TOML files or HTTP URLs semantically.
   */
  public async diffFiles(
    sourcePathOrUrl: string,
    targetPathOrUrl: string,
  ): Promise<SemanticDiffResult> {
    const sourceContent = await this.readContent(sourcePathOrUrl);
    const targetContent = await this.readContent(targetPathOrUrl);
    return this.diffTexts(sourceContent, targetContent);
  }

  private async readContent(pathOrUrl: string): Promise<string> {
    if (pathOrUrl.startsWith('http://') || pathOrUrl.startsWith('https://')) {
      if (!this.fetchImpl) {
        throw new Error('fetch is not available in the current environment');
      }
      const resp = await this.fetchImpl(pathOrUrl);
      if (!resp.ok) {
        throw new Error(`Failed to fetch ${pathOrUrl}: HTTP ${resp.status} ${resp.statusText}`);
      }
      return await resp.text();
    }
    return await fs.promises.readFile(pathOrUrl, 'utf-8');
  }

  private safeParse(content: string, label: string): Record<string, unknown> {
    try {
      const parsed = parseToml(content);
      if (typeof parsed !== 'object' || parsed === null) {
        return {};
      }
      return parsed as Record<string, unknown>;
    } catch (err) {
      throw new Error(
        `Failed to parse ${label} TOML: ${err instanceof Error ? err.message : String(err)}`,
        {
          cause: err,
        },
      );
    }
  }

  /**
   * Compare two parsed TOML objects and compute semantic diff and breaking changes.
   */
  public diffObjects(
    source: Record<string, unknown>,
    target: Record<string, unknown>,
  ): SemanticDiffResult {
    const deltas: SemanticDelta[] = [];
    const breakingChanges: BreakingChange[] = [];

    // 1. Root / Top-level primitive scalar keys & known endpoints
    this.diffRootScalarsAndEndpoints(source, target, deltas, breakingChanges);

    // 2. DOCUMENTATION table
    this.diffSimpleTable('DOCUMENTATION', source['DOCUMENTATION'], target['DOCUMENTATION'], deltas);

    // 3. CURRENCIES array of tables
    this.diffCurrencies(source['CURRENCIES'], target['CURRENCIES'], deltas, breakingChanges);

    // 4. VALIDATORS array of tables
    this.diffValidators(source['VALIDATORS'], target['VALIDATORS'], deltas, breakingChanges);

    // 5. PRINCIPALS array of tables
    this.diffPrincipals(source['PRINCIPALS'], target['PRINCIPALS'], deltas);

    // 6. Generic check for any other arbitrary top-level tables or keys
    this.diffRemainingKeys(source, target, deltas);

    const counts = {
      added: deltas.filter((d) => d.type === 'added').length,
      removed: deltas.filter((d) => d.type === 'removed').length,
      modified: deltas.filter((d) => d.type === 'modified').length,
      breaking: breakingChanges.length,
    };

    return {
      hasDifferences: counts.added > 0 || counts.removed > 0 || counts.modified > 0,
      hasBreakingChanges: breakingChanges.length > 0,
      deltas,
      breakingChanges,
      summary: counts,
    };
  }

  private diffRootScalarsAndEndpoints(
    source: Record<string, unknown>,
    target: Record<string, unknown>,
    deltas: SemanticDelta[],
    breaking: BreakingChange[],
  ): void {
    const specialRootKeys = new Set([
      'VERSION',
      'SIGNING_KEY',
      'NETWORK_PASSPHRASE',
      'FEDERATION_SERVER',
      'AUTH_SERVER',
      'TRANSFER_SERVER',
      'TRANSFER_SERVER_0_0_2',
      'KYC_SERVER',
      'WEB_AUTH_ENDPOINT',
      'ANCHOR_QUOTE_SERVER',
      'DIRECT_PAYMENT_SERVER',
      'HORIZON_URL',
    ]);

    for (const key of specialRootKeys) {
      const oldVal = source[key];
      const newVal = target[key];

      if (oldVal === undefined && newVal !== undefined) {
        deltas.push({ path: key, type: 'added', newValue: newVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal === undefined) {
        let isBreak = false;
        let reason: string | undefined;

        if (key === 'SIGNING_KEY') {
          isBreak = true;
          reason = 'Signing key was removed from the anchor definition';
          breaking.push({
            path: key,
            category: 'signing_key',
            message: reason,
            oldValue: oldVal,
          });
        } else if (KNOWN_SEP_ENDPOINTS[key]) {
          isBreak = true;
          reason = `Supported service endpoint ${key} (${KNOWN_SEP_ENDPOINTS[key]}) was removed`;
          breaking.push({
            path: key,
            category: 'service_endpoint',
            message: reason,
            oldValue: oldVal,
          });
        }

        deltas.push({
          path: key,
          type: 'removed',
          oldValue: oldVal,
          isBreaking: isBreak,
          breakingReason: reason,
        });
      } else if (oldVal !== undefined && newVal !== undefined && !this.isEqual(oldVal, newVal)) {
        let isBreak = false;
        let reason: string | undefined;

        if (key === 'SIGNING_KEY') {
          isBreak = true;
          reason = `Signing key changed from ${String(oldVal)} to ${String(newVal)}`;
          breaking.push({
            path: key,
            category: 'signing_key',
            message: reason,
            oldValue: oldVal,
            newValue: newVal,
          });
        } else if (key === 'VERSION') {
          if (String(newVal) < String(oldVal)) {
            isBreak = true;
            reason = `Downgraded VERSION from ${String(oldVal)} to ${String(newVal)}`;
            breaking.push({
              path: key,
              category: 'version',
              message: reason,
              oldValue: oldVal,
              newValue: newVal,
            });
          }
        } else if (KNOWN_SEP_ENDPOINTS[key]) {
          isBreak = true;
          reason = `Service endpoint ${key} URL altered from ${String(oldVal)} to ${String(newVal)}`;
          breaking.push({
            path: key,
            category: 'service_endpoint',
            message: reason,
            oldValue: oldVal,
            newValue: newVal,
          });
        }

        deltas.push({
          path: key,
          type: 'modified',
          oldValue: oldVal,
          newValue: newVal,
          isBreaking: isBreak,
          breakingReason: reason,
        });
      }
    }
  }

  private diffSimpleTable(
    tableName: string,
    sourceTable: unknown,
    targetTable: unknown,
    deltas: SemanticDelta[],
  ): void {
    const src = (
      typeof sourceTable === 'object' && sourceTable !== null ? sourceTable : {}
    ) as Record<string, unknown>;
    const tgt = (
      typeof targetTable === 'object' && targetTable !== null ? targetTable : {}
    ) as Record<string, unknown>;

    const allKeys = new Set([...Object.keys(src), ...Object.keys(tgt)]);
    for (const key of allKeys) {
      const oldVal = src[key];
      const newVal = tgt[key];
      const path = `${tableName}.${key}`;

      if (oldVal === undefined && newVal !== undefined) {
        deltas.push({ path, type: 'added', newValue: newVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal === undefined) {
        deltas.push({ path, type: 'removed', oldValue: oldVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal !== undefined && !this.isEqual(oldVal, newVal)) {
        deltas.push({
          path,
          type: 'modified',
          oldValue: oldVal,
          newValue: newVal,
          isBreaking: false,
        });
      }
    }
  }

  private diffCurrencies(
    sourceCurrencies: unknown,
    targetCurrencies: unknown,
    deltas: SemanticDelta[],
    breaking: BreakingChange[],
  ): void {
    const srcList = Array.isArray(sourceCurrencies)
      ? (sourceCurrencies as Record<string, unknown>[])
      : [];
    const tgtList = Array.isArray(targetCurrencies)
      ? (targetCurrencies as Record<string, unknown>[])
      : [];

    const srcMap = new Map<string, Record<string, unknown>>();
    for (const cur of srcList) {
      const code = String(cur['code'] ?? '');
      const issuer = String(cur['issuer'] ?? '');
      const key = `${code}:${issuer}`;
      srcMap.set(key, cur);
    }

    const tgtMap = new Map<string, Record<string, unknown>>();
    for (const cur of tgtList) {
      const code = String(cur['code'] ?? '');
      const issuer = String(cur['issuer'] ?? '');
      const key = `${code}:${issuer}`;
      tgtMap.set(key, cur);
    }

    // Check for removed currencies or issuer mutations
    for (const [key, srcCur] of srcMap.entries()) {
      const code = String(srcCur['code'] ?? '');
      const issuer = String(srcCur['issuer'] ?? '');

      if (!tgtMap.has(key)) {
        // Check if currency code still exists but issuer changed
        const sameCodeMatch = Array.from(tgtMap.values()).find(
          (c) => String(c['code'] ?? '') === code,
        );
        if (sameCodeMatch) {
          const newIssuer = String(sameCodeMatch['issuer'] ?? '');
          const msg = `Asset issuer for currency ${code} changed from ${issuer} to ${newIssuer}`;
          breaking.push({
            path: `CURRENCIES[code=${code}].issuer`,
            category: 'currency',
            message: msg,
            oldValue: issuer,
            newValue: newIssuer,
          });
          deltas.push({
            path: `CURRENCIES[code=${code}].issuer`,
            type: 'modified',
            oldValue: issuer,
            newValue: newIssuer,
            isBreaking: true,
            breakingReason: msg,
          });
        } else {
          const msg = `Currency asset ${code}${issuer ? ` (issuer: ${issuer})` : ''} was removed`;
          breaking.push({
            path: `CURRENCIES[code=${code}]`,
            category: 'currency',
            message: msg,
            oldValue: srcCur,
          });
          deltas.push({
            path: `CURRENCIES[code=${code}]`,
            type: 'removed',
            oldValue: srcCur,
            isBreaking: true,
            breakingReason: msg,
          });
        }
      } else {
        // Exists in both: compare fields
        const tgtCur = tgtMap.get(key)!;
        this.diffCurrencyFields(code, srcCur, tgtCur, deltas, breaking);
      }
    }

    // Check for newly added currencies
    for (const [key, tgtCur] of tgtMap.entries()) {
      if (!srcMap.has(key)) {
        const code = String(tgtCur['code'] ?? '');
        const sameCodeInSrc = Array.from(srcMap.values()).some(
          (c) => String(c['code'] ?? '') === code,
        );
        if (!sameCodeInSrc) {
          deltas.push({
            path: `CURRENCIES[code=${code}]`,
            type: 'added',
            newValue: tgtCur,
            isBreaking: false,
          });
        }
      }
    }
  }

  private diffCurrencyFields(
    code: string,
    src: Record<string, unknown>,
    tgt: Record<string, unknown>,
    deltas: SemanticDelta[],
    breaking: BreakingChange[],
  ): void {
    const keys = new Set([...Object.keys(src), ...Object.keys(tgt)]);
    for (const k of keys) {
      if (k === 'code' || k === 'issuer') continue;
      const oldVal = src[k];
      const newVal = tgt[k];
      const path = `CURRENCIES[code=${code}].${k}`;

      if (oldVal === undefined && newVal !== undefined) {
        deltas.push({ path, type: 'added', newValue: newVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal === undefined) {
        deltas.push({ path, type: 'removed', oldValue: oldVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal !== undefined && !this.isEqual(oldVal, newVal)) {
        let isBreak = false;
        let reason: string | undefined;

        if (k === 'status' && String(oldVal) === 'live' && String(newVal) !== 'live') {
          isBreak = true;
          reason = `Currency ${code} status changed from ${String(oldVal)} to ${String(newVal)}`;
          breaking.push({
            path,
            category: 'currency',
            message: reason,
            oldValue: oldVal,
            newValue: newVal,
          });
        }

        deltas.push({
          path,
          type: 'modified',
          oldValue: oldVal,
          newValue: newVal,
          isBreaking: isBreak,
          breakingReason: reason,
        });
      }
    }
  }

  private diffValidators(
    sourceValidators: unknown,
    targetValidators: unknown,
    deltas: SemanticDelta[],
    breaking: BreakingChange[],
  ): void {
    const srcList = Array.isArray(sourceValidators)
      ? (sourceValidators as Record<string, unknown>[])
      : [];
    const tgtList = Array.isArray(targetValidators)
      ? (targetValidators as Record<string, unknown>[])
      : [];

    const srcMap = new Map<string, Record<string, unknown>>();
    for (const val of srcList) {
      const pk = String(val['PUBLIC_KEY'] ?? val['name'] ?? JSON.stringify(val));
      srcMap.set(pk, val);
    }

    const tgtMap = new Map<string, Record<string, unknown>>();
    for (const val of tgtList) {
      const pk = String(val['PUBLIC_KEY'] ?? val['name'] ?? JSON.stringify(val));
      tgtMap.set(pk, val);
    }

    for (const [pk, val] of srcMap.entries()) {
      if (!tgtMap.has(pk)) {
        const msg = `Validator ${pk} was removed from the trusted quorum set`;
        breaking.push({
          path: `VALIDATORS[${pk}]`,
          category: 'validator',
          message: msg,
          oldValue: val,
        });
        deltas.push({
          path: `VALIDATORS[${pk}]`,
          type: 'removed',
          oldValue: val,
          isBreaking: true,
          breakingReason: msg,
        });
      } else {
        const tgtVal = tgtMap.get(pk)!;
        const keys = new Set([...Object.keys(val), ...Object.keys(tgtVal)]);
        for (const k of keys) {
          const oldV = val[k];
          const newV = tgtVal[k];
          if (oldV !== undefined && newV !== undefined && !this.isEqual(oldV, newV)) {
            deltas.push({
              path: `VALIDATORS[${pk}].${k}`,
              type: 'modified',
              oldValue: oldV,
              newValue: newV,
              isBreaking: false,
            });
          }
        }
      }
    }

    for (const [pk, val] of tgtMap.entries()) {
      if (!srcMap.has(pk)) {
        deltas.push({
          path: `VALIDATORS[${pk}]`,
          type: 'added',
          newValue: val,
          isBreaking: false,
        });
      }
    }
  }

  private diffPrincipals(
    sourcePrincipals: unknown,
    targetPrincipals: unknown,
    deltas: SemanticDelta[],
  ): void {
    const srcList = Array.isArray(sourcePrincipals)
      ? (sourcePrincipals as Record<string, unknown>[])
      : [];
    const tgtList = Array.isArray(targetPrincipals)
      ? (targetPrincipals as Record<string, unknown>[])
      : [];

    const keyOf = (p: Record<string, unknown>) =>
      String(p['name'] ?? p['email'] ?? JSON.stringify(p));

    const srcKeys = new Set(srcList.map(keyOf));
    const tgtKeys = new Set(tgtList.map(keyOf));

    for (const p of srcList) {
      const k = keyOf(p);
      if (!tgtKeys.has(k)) {
        deltas.push({ path: `PRINCIPALS[${k}]`, type: 'removed', oldValue: p, isBreaking: false });
      }
    }

    for (const p of tgtList) {
      const k = keyOf(p);
      if (!srcKeys.has(k)) {
        deltas.push({ path: `PRINCIPALS[${k}]`, type: 'added', newValue: p, isBreaking: false });
      }
    }
  }

  private diffRemainingKeys(
    source: Record<string, unknown>,
    target: Record<string, unknown>,
    deltas: SemanticDelta[],
  ): void {
    const handledKeys = new Set([
      'VERSION',
      'SIGNING_KEY',
      'NETWORK_PASSPHRASE',
      'FEDERATION_SERVER',
      'AUTH_SERVER',
      'TRANSFER_SERVER',
      'TRANSFER_SERVER_0_0_2',
      'KYC_SERVER',
      'WEB_AUTH_ENDPOINT',
      'ANCHOR_QUOTE_SERVER',
      'DIRECT_PAYMENT_SERVER',
      'HORIZON_URL',
      'DOCUMENTATION',
      'CURRENCIES',
      'VALIDATORS',
      'PRINCIPALS',
    ]);

    const allKeys = new Set([...Object.keys(source), ...Object.keys(target)]);
    for (const k of allKeys) {
      if (handledKeys.has(k)) continue;
      const oldVal = source[k];
      const newVal = target[k];

      if (oldVal === undefined && newVal !== undefined) {
        deltas.push({ path: k, type: 'added', newValue: newVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal === undefined) {
        deltas.push({ path: k, type: 'removed', oldValue: oldVal, isBreaking: false });
      } else if (oldVal !== undefined && newVal !== undefined && !this.isEqual(oldVal, newVal)) {
        deltas.push({
          path: k,
          type: 'modified',
          oldValue: oldVal,
          newValue: newVal,
          isBreaking: false,
        });
      }
    }
  }

  private isEqual(a: unknown, b: unknown): boolean {
    if (a === b) return true;
    if (a === null || b === null || typeof a !== typeof b) return false;
    if (typeof a === 'object') {
      return JSON.stringify(a) === JSON.stringify(b);
    }
    return false;
  }

  /**
   * Render diff result in human-readable markdown / terminal format or JSON.
   */
  public renderReport(
    result: SemanticDiffResult,
    format: 'text' | 'markdown' | 'json' = 'text',
  ): string {
    if (format === 'json') {
      return JSON.stringify(result, null, 2);
    }

    const lines: string[] = [];
    const isMarkdown = format === 'markdown';

    if (isMarkdown) {
      lines.push('## Semantic TOML Diff Report');
      lines.push('');
      lines.push(
        `**Changes**: ${result.summary.added} added, ${result.summary.removed} removed, ${result.summary.modified} modified | **Breaking**: ${result.summary.breaking}`,
      );
      lines.push('');
    } else {
      lines.push('=== Semantic TOML Diff Report ===');
      lines.push(
        `Summary: +${result.summary.added} added, -${result.summary.removed} removed, ~${result.summary.modified} modified (${result.summary.breaking} breaking)`,
      );
      lines.push('');
    }

    if (!result.hasDifferences) {
      lines.push(
        isMarkdown
          ? '*No semantic differences found between TOML files.*'
          : 'No semantic differences found.',
      );
      return lines.join('\n');
    }

    if (result.hasBreakingChanges) {
      if (isMarkdown) {
        lines.push('> [!CRITICAL] BREAKING CHANGES DETECTED:');
        for (const bc of result.breakingChanges) {
          lines.push(`> - **${bc.path}**: ${bc.message}`);
        }
        lines.push('');
      } else {
        lines.push('🚨 CRITICAL BREAKING CHANGES:');
        for (const bc of result.breakingChanges) {
          lines.push(`  [!] ${bc.path}: ${bc.message}`);
        }
        lines.push('');
      }
    }

    lines.push(isMarkdown ? '### Detailed Deltas' : 'Detailed Deltas:');
    for (const delta of result.deltas) {
      const tag = delta.isBreaking ? '[BREAKING] ' : '';
      switch (delta.type) {
        case 'added':
          lines.push(`+ [added] ${tag}${delta.path}: ${JSON.stringify(delta.newValue)}`);
          break;
        case 'removed':
          lines.push(`- [removed] ${tag}${delta.path}: ${JSON.stringify(delta.oldValue)}`);
          break;
        case 'modified':
          lines.push(
            `~ [modified] ${tag}${delta.path}: ${JSON.stringify(delta.oldValue)} -> ${JSON.stringify(delta.newValue)}`,
          );
          break;
        default:
          break;
      }
    }

    return lines.join('\n');
  }
}
