import { describe, expect, it } from 'vitest';
import { checkValidatorActivity } from '../src/validators/check-validator.js';

function documentedValidators(validators: unknown[] = []): Record<string, unknown> {
  return { VALIDATORS: validators };
}

function fetchResponse(body: unknown, status = 200): typeof fetch {
  return (async () => {
    const response = new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
    return response;
  }) as unknown as typeof fetch;
}

function fetchReject(error: unknown): typeof fetch {
  return (async () => {
    throw error;
  }) as unknown as typeof fetch;
}

const VALIDATOR = {
  ALIAS: 'core-au',
  PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS',
  HOST: 'core-au.anchor.example:11625',
};

describe('checkValidatorActivity', () => {
  it('passes cleanly when the crawler reports the key as active', async () => {
    const doc = documentedValidators([
      { ...VALIDATOR, PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS' },
    ]);
    const telemetry = {
      nodes: [
        {
          id: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS',
          active: true,
        },
      ],
    };

    const diagnostics = await checkValidatorActivity(
      doc,
      fetchResponse({ nodes: telemetry.nodes }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('reports validators/node-not-seen-on-overlay when the key is absent', async () => {
    const doc = documentedValidators([
      { ...VALIDATOR, PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS' },
    ]);
    const telemetry = {
      nodes: [
        {
          id: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZT',
          active: true,
        },
      ],
    };

    const diagnostics = await checkValidatorActivity(
      doc,
      fetchResponse({ nodes: telemetry.nodes }),
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('validators/node-not-seen-on-overlay');
    expect(diagnostics[0]?.severity).toBe('warning');
    expect(diagnostics[0]?.path).toBe('VALIDATORS[0].PUBLIC_KEY');
    expect(diagnostics[0]?.message).toContain('is not seen in the active overlay node index');
  });

  it('reports validators/node-consensus-stalled when the node is inactive for more than 7 days', async () => {
    const doc = documentedValidators([
      { ...VALIDATOR, PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS' },
    ]);
    const telemetry = {
      nodes: [
        {
          id: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS',
          active: false,
          stalls: 8,
        },
      ],
    };

    const diagnostics = await checkValidatorActivity(
      doc,
      fetchResponse({ nodes: telemetry.nodes }),
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('validators/node-consensus-stalled');
    expect(diagnostics[0]?.severity).toBe('warning');
    expect(diagnostics[0]?.path).toBe('VALIDATORS[0].PUBLIC_KEY');
    expect(diagnostics[0]?.message).toContain('failing consensus for more than 7 days');
  });

  it('degrades gracefully and never throws when the crawler API is unreachable', async () => {
    const doc = documentedValidators([
      { ...VALIDATOR, PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRRW462YFIK4BZS' },
    ]);

    const diagnostics = await checkValidatorActivity(doc, fetchReject(new Error('connect ECONNREFUSED')), { rules: {} });
    expect(diagnostics).toEqual([]);
  });

  it('degrades gracefully when the crawler returns a missing node index', async () => {
    const doc = documentedValidators([
      { ...VALIDATOR, PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRRW462YFIK4BZS' },
    ]);

    const diagnostics = await checkValidatorActivity(doc, fetchResponse({}), { rules: {} });
    expect(diagnostics).toEqual([]);
  });

  it('treats a fetch failure as graceful degradation', async () => {
    const doc = documentedValidators([
      { ...VALIDATOR, PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRRW462YFIK4BZS' },
    ]);

    const diagnostics = await checkValidatorActivity(doc, fetchReject(new TypeError('failed to fetch')), { rules: {} });
    expect(diagnostics).toEqual([]);
  });
});
