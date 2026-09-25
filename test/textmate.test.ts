import { describe, expect, it, beforeAll } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { Registry, parseRawGrammar, type IGrammar } from 'vscode-textmate';
import { loadWASM, createOnigScanner, createOnigString } from 'vscode-oniguruma';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('TextMate Grammar', () => {
  let registry: Registry;
  let grammar: IGrammar | null;

  beforeAll(async () => {
    const wasmPath = path.join(__dirname, '../node_modules/vscode-oniguruma/release/onig.wasm');
    const wasmBin = await fs.readFile(wasmPath);
    await loadWASM(wasmBin.buffer);

    registry = new Registry({
      onigLib: Promise.resolve({
        createOnigScanner,
        createOnigString,
      }),
      loadGrammar: async (scopeName) => {
        if (scopeName === 'stellar.toml.injection') {
          const grammarPath = path.join(__dirname, '../syntaxes/stellar-toml.tmLanguage.json');
          const grammarContent = await fs.readFile(grammarPath, 'utf8');
          return parseRawGrammar(grammarContent, grammarPath);
        }
        return null;
      },
    });

    grammar = await registry.loadGrammar('stellar.toml.injection');
  });

  it('matches DOCUMENTATION', () => {
    const text = '[DOCUMENTATION]';
    const lineTokens = grammar!.tokenizeLine(text, null as any);
    const tokens = lineTokens.tokens;
    expect(tokens.length).toBeGreaterThan(0);
    // Find token with our scope
    const hasScope = tokens.some((t) => t.scopes.includes('entity.name.section.stellar'));
    expect(hasScope).toBe(true);
  });

  it('matches WEB_AUTH_ENDPOINT', () => {
    const text = 'WEB_AUTH_ENDPOINT="https://..."';
    const lineTokens = grammar!.tokenizeLine(text, null as any);
    const tokens = lineTokens.tokens;
    expect(tokens.length).toBeGreaterThan(0);
    const hasScope = tokens.some((t) =>
      t.scopes.includes('constant.language.network.endpoint.stellar'),
    );
    expect(hasScope).toBe(true);
  });

  it('matches Stellar keys', () => {
    const text = 'SIGNING_KEY="GB6QWA..."';
    const lineTokens = grammar!.tokenizeLine(text, null as any);
    // wait, SIGNING_KEY should be matched as global config
    const tokens = lineTokens.tokens;
    const hasGlobal = tokens.some((t) => t.scopes.includes('keyword.other.global.stellar'));
    expect(hasGlobal).toBe(true);
  });

  it('matches Stellar values', () => {
    const text = '"GB7BDSMMTIEZYZT6N6G6C2S3TGHGZY4L77B4KNTT54OQQF4PXVEMQ6L5"';
    const lineTokens = grammar!.tokenizeLine(text, null as any);
    const tokens = lineTokens.tokens;
    const hasCrypto = tokens.some((t) => t.scopes.includes('constant.other.crypto.key.stellar'));
    expect(hasCrypto).toBe(true);
  });
});
