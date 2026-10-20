import { describe, expect, it } from 'vitest';
import { Keypair, Networks, TransactionBuilder } from '@stellar/stellar-base';
import {
  coordinateSep30Recovery,
  extractRecoveryServers,
  INSUFFICIENT_RECOVERY_SIGNATURES_RULE,
  SIGNATURE_COORDINATION_TIMEOUT_RULE,
} from '../../src/protocols/sep30-coordinator.js';

describe('SEP-30 multi-party recovery server threshold signature coordinator', () => {
  const rs1 = 'https://rs1.example.com';
  const rs2 = 'https://rs2.example.com';

  const doc = {
    RECOVERY_SERVER: `${rs1}, ${rs2}`,
    NETWORK_PASSPHRASE: Networks.TESTNET,
  };

  it('extracts recovery servers correctly from string, array, or SERVERS table', () => {
    expect(extractRecoveryServers({ RECOVERY_SERVER: 'https://a.com, https://b.com' })).toEqual([
      'https://a.com',
      'https://b.com',
    ]);
    expect(extractRecoveryServers({ RECOVERY_SERVER: ['https://c.com', 'https://d.com'] })).toEqual(
      ['https://c.com', 'https://d.com'],
    );
    expect(
      extractRecoveryServers({
        SERVERS: [{ RECOVERY_SERVER: 'https://e.com' }],
      }),
    ).toEqual(['https://e.com']);
  });

  it('passes cleanly when coordinated signing reaches the required threshold', async () => {
    const server1Kp = Keypair.random();
    const server2Kp = Keypair.random();

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = String(url);
      const body = init?.body ? JSON.parse(String(init.body)) : {};

      // Registration endpoint
      if (urlStr.includes('/accounts') && !urlStr.includes('/sign')) {
        if (urlStr.startsWith(rs1)) {
          return new Response(
            JSON.stringify({
              address: body.address,
              signer: server1Kp.publicKey(),
              weight: 1,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (urlStr.startsWith(rs2)) {
          return new Response(
            JSON.stringify({
              address: body.address,
              signer: server2Kp.publicKey(),
              weight: 1,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
      }

      // Signing endpoint
      if (urlStr.includes('/sign')) {
        const tx = TransactionBuilder.fromXDR(body.transaction, Networks.TESTNET);
        if (urlStr.startsWith(rs1)) {
          tx.sign(server1Kp);
          return new Response(JSON.stringify({ transaction: tx.toXDR() }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (urlStr.startsWith(rs2)) {
          tx.sign(server2Kp);
          return new Response(JSON.stringify({ transaction: tx.toXDR() }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }) as unknown as typeof fetch;

    const diagnostics = await coordinateSep30Recovery(doc, fetchImpl, {
      requiredThreshold: 2,
    });
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep30/insufficient-recovery-signatures when signature weight is below threshold', async () => {
    const server1Kp = Keypair.random();

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = String(url);
      const body = init?.body ? JSON.parse(String(init.body)) : {};

      if (urlStr.includes('/accounts') && !urlStr.includes('/sign')) {
        if (urlStr.startsWith(rs1)) {
          return new Response(
            JSON.stringify({
              signer: server1Kp.publicKey(),
              weight: 1,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        // rs2 returns no signer
        return new Response(JSON.stringify({}), { status: 200 });
      }

      if (urlStr.includes('/sign')) {
        if (urlStr.startsWith(rs1)) {
          const tx = TransactionBuilder.fromXDR(body.transaction, Networks.TESTNET);
          tx.sign(server1Kp);
          return new Response(JSON.stringify({ transaction: tx.toXDR() }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        // rs2 fails signing
        return new Response(JSON.stringify({ error: 'Server unavailable' }), { status: 500 });
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }) as unknown as typeof fetch;

    const diagnostics = await coordinateSep30Recovery(doc, fetchImpl, {
      requiredThreshold: 2,
    });

    const errorDiag = diagnostics.find((d) => d.rule === INSUFFICIENT_RECOVERY_SIGNATURES_RULE);
    expect(errorDiag).toBeDefined();
    expect(errorDiag?.severity).toBe('error');
    expect(errorDiag?.message).toContain(
      'Combined recovery signatures weight (1) is below the required account threshold (2)',
    );
  });

  it('asserts sep30/signature-coordination-timeout when a recovery server times out', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.startsWith(rs1)) {
        throw new Error('Connection timed out');
      }
      return new Response(JSON.stringify({}), { status: 504 });
    }) as unknown as typeof fetch;

    const diagnostics = await coordinateSep30Recovery(doc, fetchImpl, {
      requiredThreshold: 2,
    });

    const timeoutDiag = diagnostics.find((d) => d.rule === SIGNATURE_COORDINATION_TIMEOUT_RULE);
    expect(timeoutDiag).toBeDefined();
    expect(timeoutDiag?.severity).toBe('warning');
  });

  it('rejects forged/invalid Ed25519 signatures and asserts insufficient signatures', async () => {
    const validServerKp = Keypair.random();
    const attackerKp = Keypair.random(); // Untrusted key

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = String(url);
      const body = init?.body ? JSON.parse(String(init.body)) : {};

      if (urlStr.includes('/accounts') && !urlStr.includes('/sign')) {
        return new Response(
          JSON.stringify({
            signer: validServerKp.publicKey(),
            weight: 1,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      if (urlStr.includes('/sign')) {
        const tx = TransactionBuilder.fromXDR(body.transaction, Networks.TESTNET);
        // Signed with attacker key rather than validServerKp
        tx.sign(attackerKp);
        return new Response(JSON.stringify({ transaction: tx.toXDR() }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }) as unknown as typeof fetch;

    const diagnostics = await coordinateSep30Recovery(doc, fetchImpl, {
      servers: [rs1],
      requiredThreshold: 1,
    });

    expect(diagnostics.some((d) => d.rule === INSUFFICIENT_RECOVERY_SIGNATURES_RULE)).toBe(true);
  });

  it('returns empty diagnostics when document has no declared recovery servers', async () => {
    const diagnostics = await coordinateSep30Recovery({});
    expect(diagnostics).toEqual([]);
  });
});
