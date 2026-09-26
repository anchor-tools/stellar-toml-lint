import type { Diagnostic, LintOptions, Rule } from '../types.js';
import { lint } from '../lint.js';
import { specUrl } from '../spec.js';

export const CIRCULAR_TOML_POINTER_RULE = 'currencies/circular-toml-pointer';

export const circularPointerRules: Rule[] = [
  {
    id: CIRCULAR_TOML_POINTER_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'Currency toml pointers must not contain circular references',
    run() {},
  },
];

/** Upper bound on linked documents fetched, so a long list cannot fan out. */
const MAX_POINTER_FETCHES = 20;

export function normalizePointerUrl(raw: string): string {
  try {
    const u = new URL(raw);
    let pathname = u.pathname.replace(/\/+$/, '');
    if (pathname === '/.well-known/stellar.toml') {
      pathname = '/stellar.toml';
    }
    return `${u.protocol}//${u.host.toLowerCase()}${pathname}`;
  } catch {
    return raw.trim().toLowerCase();
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Fetches every `toml` pointer under `CURRENCIES` and lints the linked
 * documents, detecting circular reference chains and halting traversal.
 */
export async function followTomlPointers(
  doc: Record<string, unknown>,
  options: LintOptions,
  fetchImpl: typeof fetch = globalThis.fetch,
  visited: Set<string> = new Set(),
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return diagnostics;

  const currentChain = new Set(visited);
  if (options.domain) {
    currentChain.add(normalizePointerUrl(`https://${options.domain}/.well-known/stellar.toml`));
    currentChain.add(normalizePointerUrl(`https://${options.domain}/stellar.toml`));
  }

  const pointers = currencies
    .map((entry, index) => ({ entry, path: `CURRENCIES[${index}]` }))
    .filter(
      ({ entry }) =>
        typeof entry === 'object' &&
        entry !== null &&
        typeof (entry as Record<string, unknown>).toml === 'string',
    )
    .slice(0, MAX_POINTER_FETCHES);

  for (const { entry, path } of pointers) {
    const url = (entry as Record<string, unknown>).toml as string;
    const normalized = normalizePointerUrl(url);

    // Circular reference check
    if (currentChain.has(normalized)) {
      diagnostics.push({
        rule: CIRCULAR_TOML_POINTER_RULE,
        severity: 'error',
        category: 'currencies',
        message: `Circular currency reference detected in toml pointer: ${url} has already been visited in resolution chain`,
        path: `${path}.toml`,
        helpUri: specUrl('currency-documentation'),
        suggestion: 'Remove circular toml pointer references between documents.',
      });
      continue;
    }

    let response: Response;
    try {
      response = await fetchImpl(url, { redirect: 'follow' });
    } catch (error) {
      diagnostics.push({
        rule: 'network/toml-pointer-fetch',
        severity: 'warning',
        category: 'network',
        message: `Could not fetch TOML pointer ${url}: ${errorMessage(error)}`,
        path: `${path}.toml`,
        helpUri: specUrl('currency-documentation'),
      });
      continue;
    }

    if (!response.ok) {
      diagnostics.push({
        rule: 'network/toml-pointer-fetch',
        severity: 'warning',
        category: 'network',
        message: `Could not fetch TOML pointer ${url}: HTTP ${response.status}`,
        path: `${path}.toml`,
        helpUri: specUrl('currency-documentation'),
      });
      continue;
    }

    const linkedText = await response.text();
    const linked = lint(linkedText, {
      ...options,
      checkNetwork: false,
      followLinks: false,
    });

    for (const diagnostic of linked.diagnostics) {
      diagnostics.push({ ...diagnostic, message: `[${url}] ${diagnostic.message}` });
    }

    if (linked.parsed) {
      const nextChain = new Set(currentChain);
      nextChain.add(normalized);
      const childDiagnostics = await followTomlPointers(
        linked.parsed,
        options,
        fetchImpl,
        nextChain,
      );
      diagnostics.push(...childDiagnostics);
    }
  }

  return diagnostics;
}
