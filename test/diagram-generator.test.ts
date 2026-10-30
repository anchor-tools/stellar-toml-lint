import { describe, it, expect } from 'vitest';
import { generateDiagram, type DiagramOptions } from '../src/generators/diagram.js';

const sampleToml = {
  VERSION: '2.0.0',
  NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
  DOCUMENTATION: {
    ORG_NAME: 'Test Anchor',
    ORG_URL: 'https://example.com',
    ORG_OFFICIAL_EMAIL: 'contact@example.com',
    ORG_GITHUB: 'testanchor',
  },
  SIGNING_KEY: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
  SERVERS: [
    {
      WEB_AUTH_ENDPOINT: 'https://auth.example.com',
      TRANSFER_SERVER: 'https://transfer.example.com',
      TRANSFER_SERVER_SEP0024: 'https://transfer24.example.com',
      KYC_SERVER: 'https://kyc.example.com',
      ANCHOR_QUOTE_SERVER: 'https://quote.example.com',
    },
  ],
  CURRENCIES: [
    {
      code: 'USDC',
      issuer: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
      status: 'test',
      display_decimals: 2,
      regulated: true,
    },
    {
      code: 'EURC',
      issuer: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      status: 'live',
      display_decimals: 2,
    },
    {
      code: 'XLM',
      contract: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      is_asset_anchored: true,
      anchor_asset: 'USDC',
      anchor_asset_type: 'fiat',
    },
  ],
  VALIDATORS: [
    {
      ALIAS: 'validator1',
      PUBLIC_KEY: 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      HOST: 'validator1.example.com:11625',
      HISTORY: 'https://history.example.com/{0}',
    },
    {
      ALIAS: 'validator2',
      PUBLIC_KEY: 'GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
      HOST: 'validator2.example.com:11625',
    },
  ],
  WEB_AUTH_CONTRACT_ID: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB',
};

describe('Diagram Generator', () => {
  const baseOptions: DiagramOptions = { format: 'mermaid' };

  it('generates valid Mermaid diagram', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('```mermaid');
    expect(diagram).toContain('graph TD');
    expect(diagram).toContain('```');
  });

  it('generates valid DOT diagram', () => {
    const diagram = generateDiagram(sampleToml, { format: 'dot' });
    expect(diagram).toContain('digraph stellar_toml');
    expect(diagram).toContain('rankdir=TB');
    expect(diagram).toContain('}');
  });

  it('includes organization node', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('Test Anchor');
    expect(diagram).toContain('org');
  });

  it('includes server nodes', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('server_0');
    expect(diagram).toContain('serves');
  });

  it('includes asset nodes', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('asset_0');
    expect(diagram).toContain('USDC');
    expect(diagram).toContain('asset_1');
    expect(diagram).toContain('EURC');
  });

  it('includes issuer nodes', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('issuer_');
    expect(diagram).toContain('issued by');
  });

  it('includes contract nodes when enabled', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      includeContracts: true,
    });
    expect(diagram).toContain('contract_');
    expect(diagram).toContain('contract');
  });

  it('excludes contract nodes when disabled', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      includeContracts: false,
    });
    expect(diagram).not.toContain('contract_');
  });

  it('includes validator nodes when enabled', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      includeValidators: true,
    });
    expect(diagram).toContain('validator_0');
    expect(diagram).toContain('validator1');
    expect(diagram).toContain('validates');
  });

  it('excludes validator nodes when disabled', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      includeValidators: false,
    });
    expect(diagram).not.toContain('validator_');
  });

  it('includes signing key node', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('key_');
    expect(diagram).toContain('signs with');
  });

  it('includes web auth contract node', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      includeContracts: true,
    });
    expect(diagram).toContain('contract_');
    expect(diagram).toContain('auth contract');
  });

  it('includes anchored asset relationship', () => {
    const diagram = generateDiagram(sampleToml, baseOptions);
    expect(diagram).toContain('anchored to');
    expect(diagram).toContain('anchor_');
  });

  it('colors nodes by protocol when enabled', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      colorByProtocol: true,
    });
    expect(diagram).toContain('style ');
    expect(diagram).toContain('fill:');
  });

  it('does not color nodes when disabled', () => {
    const diagram = generateDiagram(sampleToml, {
      format: 'mermaid',
      colorByProtocol: false,
    });
    expect(diagram).not.toContain('style ');
  });

  it('generates valid DOT with proper escaping', () => {
    const diagram = generateDiagram(sampleToml, { format: 'dot' });
    expect(diagram).toContain('label=');
    expect(diagram).toContain('shape=');
  });

  it('includes edges between organization and servers', () => {
    const mermaid = generateDiagram(sampleToml, baseOptions);
    expect(mermaid).toContain('org -->');
    expect(mermaid).toContain('server_0');
  });

  it('includes edges between assets and issuers', () => {
    const mermaid = generateDiagram(sampleToml, baseOptions);
    expect(mermaid).toContain('asset_0 -->');
    expect(mermaid).toContain('issuer_');
  });
});
