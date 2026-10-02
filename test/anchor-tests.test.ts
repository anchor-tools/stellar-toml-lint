import { describe, expect, it, vi } from 'vitest';
import { generateAnchorTestsConfig } from '../src/integrations/anchor-tests.js';

describe('anchor-tests exporter', () => {
  it('extracts all fields properly for a full SEP-24 anchor fixture', () => {
    const doc = {
      HOME_DOMAIN: "test.com",
      SIGNING_KEY: "G12345",
      WEB_AUTH_ENDPOINT: "https://test.com/auth",
      TRANSFER_SERVER_SEP0024: "https://test.com/sep24",
      CURRENCIES: [
        { code: "USDC", issuer: "G98765" }
      ]
    };
    
    // Silence console.warn
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const config = generateAnchorTestsConfig(doc);
    expect(config.homeDomain).toBe('test.com');
    expect(config.SIGNING_KEY).toBe('G12345');
    expect(config.WEB_AUTH_ENDPOINT).toBe('https://test.com/auth');
    expect(config.TRANSFER_SERVER_SEP0024).toBe('https://test.com/sep24');
    expect(config.CURRENCIES).toEqual([{ code: "USDC", issuer: "G98765" }]);

    spy.mockRestore();
  });

  it('correctly populates homeDomain when domain is passed explicitly', () => {
    const doc = {};
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const config = generateAnchorTestsConfig(doc, 'explicit.com');
    expect(config.homeDomain).toBe('explicit.com');
    spy.mockRestore();
  });

  it('triggers informative warnings without crashing when missing endpoints', () => {
    const doc = {};
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const config = generateAnchorTestsConfig(doc);
    expect(config).toBeDefined();

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('WEB_AUTH_ENDPOINT is missing'));
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('SIGNING_KEY is missing'));
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('TRANSFER_SERVER_SEP0024 is missing'));

    warnSpy.mockRestore();
  });
});
