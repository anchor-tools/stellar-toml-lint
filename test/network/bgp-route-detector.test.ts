import { describe, expect, it } from 'vitest';
import {
  auditBgpRoutes,
  NETWORK_RPKI_INVALID_ROUTE_RULE,
  NETWORK_UNVERIFIED_BGP_RULE,
} from '../../src/network/bgp-route-detector.js';

describe('auditBgpRoutes', () => {
  it('accepts a valid RPKI route', async () => {
    const result = await auditBgpRoutes(
      { DOMAIN: 'anchor.example' },
      {
        resolveAddresses: async () => ['192.0.2.20'],
        fetchImpl: async (input) => {
          const url = new URL(String(input));
          return Response.json(
            url.pathname.includes('network-info')
              ? { data: { prefix: '192.0.2.0/24', asns: [64500] } }
              : { data: { status: 'valid' } },
          );
        },
      },
    );

    expect(result).toEqual([]);
  });

  it('reports an invalid RPKI route origin', async () => {
    const result = await auditBgpRoutes(
      { DOMAIN: 'anchor.example' },
      {
        resolveAddresses: async () => ['192.0.2.20'],
        fetchImpl: async (input) => {
          const url = new URL(String(input));
          return Response.json(
            url.pathname.includes('network-info')
              ? { data: { prefix: '192.0.2.0/24', asns: [64500] } }
              : { data: { status: 'invalid' } },
          );
        },
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(NETWORK_RPKI_INVALID_ROUTE_RULE);
  });

  it('warns when the RPKI route status is not found', async () => {
    const result = await auditBgpRoutes(
      { DOMAIN: 'anchor.example' },
      {
        resolveAddresses: async () => ['192.0.2.20'],
        fetchImpl: async (input) => {
          const url = new URL(String(input));
          return Response.json(
            url.pathname.includes('network-info')
              ? { data: { prefix: '192.0.2.0/24', asns: [64500] } }
              : { data: { status: 'not-found' } },
          );
        },
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(NETWORK_UNVERIFIED_BGP_RULE);
  });

  it('warns when the announced origin differs from the expected ASN', async () => {
    const result = await auditBgpRoutes(
      { DOMAIN: 'anchor.example' },
      {
        expectedAsns: ['AS64501'],
        resolveAddresses: async () => ['192.0.2.20'],
        fetchImpl: async (input) => {
          const url = new URL(String(input));
          return Response.json(
            url.pathname.includes('network-info')
              ? { data: { prefix: '192.0.2.0/24', asns: [64500] } }
              : { data: { status: 'valid' } },
          );
        },
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(NETWORK_UNVERIFIED_BGP_RULE);
  });
});
