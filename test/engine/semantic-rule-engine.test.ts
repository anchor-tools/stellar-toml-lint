import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SemanticRuleEngine } from '../../src/engine/semanticRuleEngine.js';
import type { SemanticLintRule } from '../../src/engine/astVisitor.js';

const SAMPLE_TOML = `
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"

[DOCUMENTATION]
ORG_NAME = "My Stellar Anchor"
ORG_URL = "https://anchor.example.com"

[[CURRENCIES]]
code = "USDC"
issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
status = "live"

[[VALIDATORS]]
ALIAS = "anchor-core"
HOST = "core.anchor.example.com:11625"
`;

describe('SemanticRuleEngine', () => {
  it('invokes all visitor lifecycle hooks on AST traversal', () => {
    const engine = new SemanticRuleEngine();
    const calls: string[] = [];

    const testRule: SemanticLintRule = {
      id: 'test-lifecycle-rule',
      description: 'Tracks visitor lifecycle',
      createVisitor: () => ({
        enterDocument: () => {
          calls.push('enterDocument');
        },
        exitDocument: () => {
          calls.push('exitDocument');
        },
        enterTable: (_entry, name) => {
          void _entry;
          calls.push(`enterTable:${name}`);
        },
        exitTable: (_entry, name) => {
          void _entry;
          calls.push(`exitTable:${name}`);
        },
        visitKeyValue: (_entry, key) => {
          void _entry;
          calls.push(`visitKeyValue:${key}`);
        },
        visitCurrency: (_entry, fields) => {
          void _entry;
          calls.push(`visitCurrency:${fields.get('code')}`);
        },
        visitValidator: (_entry, fields) => {
          void _entry;
          calls.push(`visitValidator:${fields.get('alias')}`);
        },
        visitDocumentation: (_entry, fields) => {
          void _entry;
          calls.push(`visitDocumentation:${fields.get('org_name')}`);
        },
      }),
    };

    engine.registerRule(testRule);
    const result = engine.run(SAMPLE_TOML);

    expect(calls).toContain('enterDocument');
    expect(calls).toContain('exitDocument');
    expect(calls).toContain('enterTable:DOCUMENTATION');
    expect(calls).toContain('exitTable:DOCUMENTATION');
    expect(calls).toContain('visitDocumentation:My Stellar Anchor');
    expect(calls).toContain('visitCurrency:USDC');
    expect(calls).toContain('visitValidator:anchor-core');
    expect(calls).toContain('visitKeyValue:VERSION');
    expect(result.ok).toBe(true);
  });

  it('validates rule and plugin schemas upon registration', () => {
    const engine = new SemanticRuleEngine();

    // Invalid rule id
    expect(() => {
      engine.registerRule({ id: '', createVisitor: () => ({}) });
    }).toThrow(/non-empty string id/);

    // Missing createVisitor
    expect(() => {
      engine.registerRule({ id: 'bad-rule' } as any);
    }).toThrow(/createVisitor must be a function/);

    // Invalid plugin name
    expect(() => {
      engine.registerPlugin({ name: '', rules: [] } as any);
    }).toThrow(/non-empty string name/);

    // Non-array rules
    expect(() => {
      engine.registerPlugin({ name: 'bad-plugin', rules: 'not-an-array' as any });
    }).toThrow(/rules must be an array/);
  });

  it('handles buggy rules gracefully without crashing the runner', () => {
    const engine = new SemanticRuleEngine();

    const buggyInitRule: SemanticLintRule = {
      id: 'buggy-init',
      createVisitor: () => {
        throw new Error('Boom in init!');
      },
    };

    const buggyVisitorRule: SemanticLintRule = {
      id: 'buggy-visitor',
      createVisitor: () => ({
        visitKeyValue: () => {
          throw new Error('Boom in visitKeyValue!');
        },
      }),
    };

    engine.registerRule(buggyInitRule);
    engine.registerRule(buggyVisitorRule);

    const result = engine.run(SAMPLE_TOML);
    expect(result.ok).toBe(false);
    expect(result.diagnostics.length).toBeGreaterThanOrEqual(2);

    const initDiag = result.diagnostics.find((d) => d.rule === 'buggy-init');
    expect(initDiag).toBeDefined();
    expect(initDiag?.message).toContain('Boom in init!');

    const visitorDiag = result.diagnostics.find((d) => d.rule === 'buggy-visitor');
    expect(visitorDiag).toBeDefined();
    expect(visitorDiag?.message).toContain('Boom in visitKeyValue!');
  });

  it('respects configured severities (error, warning, info, off)', () => {
    const engine = new SemanticRuleEngine();

    const rule1: SemanticLintRule = {
      id: 'rule-one',
      severity: 'error',
      createVisitor: (ctx) => ({
        visitKeyValue: (entry, key) => {
          if (key === 'VERSION') ctx.report({ message: 'Version check failed' });
        },
      }),
    };

    const rule2: SemanticLintRule = {
      id: 'rule-two',
      severity: 'error',
      createVisitor: (ctx) => ({
        visitKeyValue: (entry, key) => {
          if (key === 'VERSION') ctx.report({ message: 'Version info' });
        },
      }),
    };

    const rule3: SemanticLintRule = {
      id: 'rule-three',
      severity: 'error',
      createVisitor: (ctx) => ({
        visitKeyValue: (entry, key) => {
          if (key === 'VERSION') ctx.report({ message: 'Should not run' });
        },
      }),
    };

    engine.registerRule(rule1);
    engine.registerRule(rule2);
    engine.registerRule(rule3);

    engine.configureSeverities({
      'rule-one': 'warning',
      'rule-two': 'info',
      'rule-three': 'off',
    });

    const result = engine.run(SAMPLE_TOML);
    expect(result.diagnostics.length).toBe(2);

    const d1 = result.diagnostics.find((d) => d.rule === 'rule-one');
    expect(d1?.severity).toBe('warning');

    const d2 = result.diagnostics.find((d) => d.rule === 'rule-two');
    expect(d2?.severity).toBe('info');

    const d3 = result.diagnostics.find((d) => d.rule === 'rule-three');
    expect(d3).toBeUndefined();
  });

  it('dynamically loads rule plugins from a directory', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'stellar-rules-'));
    try {
      const pluginCode = `
export default {
  name: 'dynamic-plugin',
  rules: [
    {
      id: 'dynamic-currency-check',
      category: 'currency',
      severity: 'error',
      createVisitor(ctx) {
        return {
          visitCurrency(entry, fields) {
            if (fields.get('status') === 'live') {
              ctx.report({ message: 'Live currency detected in test' });
            }
          }
        };
      }
    }
  ]
};
`;
      await writeFile(join(tempDir, 'plugin.mjs'), pluginCode, 'utf8');

      const engine = new SemanticRuleEngine();
      const count = await engine.loadRulesFromDir(tempDir);
      expect(count).toBe(1);
      expect(engine.getRegisteredRules()).toContain('dynamic-currency-check');

      const result = engine.run(SAMPLE_TOML);
      expect(result.ok).toBe(false);
      expect(
        result.diagnostics.some((d) => d.message.includes('Live currency detected in test')),
      ).toBe(true);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('dynamically loads a plugin module file via loadPlugin', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'stellar-plugin-'));
    try {
      const pluginFilePath = join(tempDir, 'custom-plugin.mjs');
      const pluginCode = `
export default {
  name: 'standalone-plugin',
  rules: [
    {
      id: 'standalone-rule',
      createVisitor(ctx) {
        return {
          visitKeyValue(entry, key) {
            if (key === 'NETWORK_PASSPHRASE') {
              ctx.report({ message: 'Observed network passphrase' });
            }
          }
        };
      }
    }
  ]
};
`;
      await writeFile(pluginFilePath, pluginCode, 'utf8');

      const engine = new SemanticRuleEngine();
      await engine.loadPlugin(pluginFilePath);
      expect(engine.getRegisteredRules()).toContain('standalone-rule');

      const result = engine.run(SAMPLE_TOML);
      expect(result.diagnostics.some((d) => d.message === 'Observed network passphrase')).toBe(
        true,
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('benchmarks visitor traversal overhead to be under 10ms across 100+ rules', () => {
    const engine = new SemanticRuleEngine();

    for (let i = 0; i < 120; i++) {
      const rule: SemanticLintRule = {
        id: `bench-rule-${i}`,
        createVisitor: (ctx) => ({
          visitKeyValue: (_entry, key) => {
            void _entry;
            if (key === `KEY_${i}`) {
              ctx.report({ message: `Found ${key}` });
            }
          },
          visitCurrency: (entry, fields) => {
            const code = fields.get('code');
            if (code === 'INVALID') ctx.report({ message: 'Invalid' });
          },
          enterTable: () => {},
          exitTable: () => {},
        }),
      };
      engine.registerRule(rule);
    }

    expect(engine.getRegisteredRules().length).toBe(120);

    // Warm-up
    engine.run(SAMPLE_TOML);

    const start = performance.now();
    const result = engine.run(SAMPLE_TOML);
    const duration = performance.now() - start;

    expect(result.ok).toBe(true);
    // Requirement: Benchmark visitor traversal overhead, ensuring < 10ms execution across 100+ rules.
    expect(duration).toBeLessThan(10);
  });
});
