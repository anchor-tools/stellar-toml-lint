import type { StellarToml } from '../types.js';

export type GraphFormat = 'mermaid' | 'dot';

export interface DiagramOptions {
  format: GraphFormat;
  includeContracts?: boolean;
  includeValidators?: boolean;
  colorByProtocol?: boolean;
}

interface Node {
  id: string;
  label: string;
  type: NodeType;
  metadata?: Record<string, string>;
}

type NodeType = 'organization' | 'server' | 'asset' | 'issuer' | 'contract' | 'validator';

interface Edge {
  from: string;
  to: string;
  label?: string;
  type: EdgeType;
}

type EdgeType = 'serves' | 'issues' | 'anchored-to' | 'validates' | 'contracts';

const PROTOCOL_COLORS: Record<string, string> = {
  'sep-1': '#1f77b4',
  'sep-10': '#ff7f0e',
  'sep-24': '#2ca02c',
  'sep-31': '#d62728',
  'sep-38': '#9467bd',
  'sep-45': '#8c564b',
  soroban: '#e377c2',
  validator: '#7f7f7f',
  default: '#bcbd22',
};

function getProtocolColor(protocols: string[]): string {
  for (const proto of protocols) {
    const color = PROTOCOL_COLORS[proto];
    if (color) return color;
  }
  return PROTOCOL_COLORS.default ?? '#bcbd22';
}

function sanitizeId(str: string): string {
  return str.replace(/[^a-zA-Z0-9_-]/g, '_');
}

interface ServerEntry {
  WEB_AUTH_ENDPOINT?: string;
  TRANSFER_SERVER?: string;
  TRANSFER_SERVER_SEP0024?: string;
  KYC_SERVER?: string;
  ANCHOR_QUOTE_SERVER?: string;
  DIRECT_PAYMENT_SERVER?: string;
  WEB_AUTH_CONTRACT_ID?: string;
  TLS_CERT?: string;
}

interface CurrencyEntry {
  code?: string;
  issuer?: string;
  contract?: string;
  status?: string;
  display_decimals?: number;
  is_asset_anchored?: boolean;
  anchor_asset_type?: string;
  anchor_asset?: string;
  regulated?: boolean;
}

interface ValidatorEntry {
  ALIAS?: string;
  PUBLIC_KEY?: string;
  HOST?: string;
  HISTORY?: string;
}

function getServerProtocols(server: ServerEntry): string[] {
  const protocols: string[] = [];
  if (server.WEB_AUTH_ENDPOINT) protocols.push('sep-10');
  if (server.TRANSFER_SERVER) protocols.push('sep-6');
  if (server.TRANSFER_SERVER_SEP0024) protocols.push('sep-24');
  if (server.KYC_SERVER) protocols.push('sep-12');
  if (server.ANCHOR_QUOTE_SERVER) protocols.push('sep-38');
  if (server.DIRECT_PAYMENT_SERVER) protocols.push('sep-31');
  if (server.WEB_AUTH_CONTRACT_ID) protocols.push('sep-45');
  return protocols;
}

function getAssetProtocols(currency: CurrencyEntry): string[] {
  const protocols: string[] = [];
  if (currency.contract) protocols.push('soroban');
  if (currency.is_asset_anchored) protocols.push('sep-38');
  if (currency.regulated) protocols.push('sep-8');
  return protocols;
}

export function generateDiagram(toml: StellarToml, options: DiagramOptions): string {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Organization node
  const orgId = 'org';
  nodes.push({
    id: orgId,
    label: toml.DOCUMENTATION?.ORG_NAME ?? 'Organization',
    type: 'organization',
    metadata: {
      url: toml.DOCUMENTATION?.ORG_URL ?? '',
      email: toml.DOCUMENTATION?.ORG_OFFICIAL_EMAIL ?? '',
    },
  });

  // Servers
  if (toml.SERVERS) {
    for (const [i, server] of Object.entries(toml.SERVERS)) {
      const serverId = `server_${i}`;
      const serverTyped = server as ServerEntry;
      const protocols = getServerProtocols(serverTyped);
      const color = options.colorByProtocol ? getProtocolColor(protocols) : undefined;

      nodes.push({
        id: serverId,
        label: `Server ${parseInt(i, 10) + 1}`,
        type: 'server',
        metadata: {
          protocols: protocols.join(', '),
          color: color ?? '',
        },
      });

      edges.push({
        from: orgId,
        to: serverId,
        type: 'serves',
        label: 'serves',
      });

      // Link assets to servers via protocols
      if (toml.CURRENCIES) {
        for (const [j, currency] of Object.entries(toml.CURRENCIES)) {
          const currencyTyped = currency as CurrencyEntry;
          const assetProtocols = getAssetProtocols(currencyTyped);
          const hasOverlap = protocols.some((p) => assetProtocols.includes(p));
          if (hasOverlap) {
            const assetId = `asset_${j}`;
            edges.push({
              from: serverId,
              to: assetId,
              type: 'serves',
              label: protocols.filter((p) => assetProtocols.includes(p)).join(', '),
            });
          }
        }
      }
    }
  }

  // Assets
  if (toml.CURRENCIES) {
    for (const [i, currency] of Object.entries(toml.CURRENCIES)) {
      const currencyTyped = currency as CurrencyEntry;
      const assetId = `asset_${i}`;
      const protocols = getAssetProtocols(currencyTyped);
      const color = options.colorByProtocol ? getProtocolColor(protocols) : undefined;

      const label = `${currencyTyped.code ?? 'Unknown'}${currencyTyped.issuer ? ` (${currencyTyped.issuer.slice(0, 8)}...)` : ''}${currencyTyped.contract ? ` [${currencyTyped.contract.slice(0, 12)}...]` : ''}`;

      nodes.push({
        id: assetId,
        label,
        type: 'asset',
        metadata: {
          protocols: protocols.join(', '),
          color: color ?? '',
        },
      });

      // Issuer
      if (currencyTyped.issuer) {
        const issuerId = `issuer_${sanitizeId(currencyTyped.issuer)}`;
        if (!nodes.find((n) => n.id === issuerId)) {
          nodes.push({
            id: issuerId,
            label: `Issuer ${currencyTyped.issuer.slice(0, 8)}...`,
            type: 'issuer',
            metadata: { account: currencyTyped.issuer },
          });
        }
        edges.push({
          from: assetId,
          to: issuerId,
          type: 'issues',
          label: 'issued by',
        });
      }

      // Contract
      if (currencyTyped.contract && options.includeContracts) {
        const contractId = `contract_${sanitizeId(currencyTyped.contract)}`;
        if (!nodes.find((n) => n.id === contractId)) {
          nodes.push({
            id: contractId,
            label: `Contract ${currencyTyped.contract.slice(0, 12)}...`,
            type: 'contract',
            metadata: { contractId: currencyTyped.contract },
          });
        }
        edges.push({
          from: assetId,
          to: contractId,
          type: 'contracts',
          label: 'contract',
        });
      }

      // Anchored asset
      if (currencyTyped.is_asset_anchored && currencyTyped.anchor_asset) {
        const anchorId = `anchor_${sanitizeId(currencyTyped.anchor_asset)}`;
        if (!nodes.find((n) => n.id === anchorId)) {
          nodes.push({
            id: anchorId,
            label: `Anchor: ${currencyTyped.anchor_asset}`,
            type: 'asset',
            metadata: { isAnchor: 'true' },
          });
        }
        edges.push({
          from: assetId,
          to: anchorId,
          type: 'anchored-to',
          label: 'anchored to',
        });
      }
    }
  }

  // Validators
  if (toml.VALIDATORS && options.includeValidators) {
    for (const [i, validator] of Object.entries(toml.VALIDATORS)) {
      const validatorTyped = validator as ValidatorEntry;
      const validatorId = `validator_${i}`;
      nodes.push({
        id: validatorId,
        label: `Validator ${validatorTyped.ALIAS ?? i}`,
        type: 'validator',
        metadata: {
          alias: validatorTyped.ALIAS ?? '',
          publicKey: validatorTyped.PUBLIC_KEY ?? '',
          host: validatorTyped.HOST ?? '',
        },
      });

      edges.push({
        from: orgId,
        to: validatorId,
        type: 'validates',
        label: 'validates',
      });
    }
  }

  // Signing key
  if (toml.SIGNING_KEY) {
    const keyId = `key_${sanitizeId(toml.SIGNING_KEY)}`;
    nodes.push({
      id: keyId,
      label: `Signing Key ${toml.SIGNING_KEY.slice(0, 8)}...`,
      type: 'issuer',
      metadata: { key: toml.SIGNING_KEY },
    });
    edges.push({
      from: orgId,
      to: keyId,
      type: 'issues',
      label: 'signs with',
    });
  }

  // WEB_AUTH_CONTRACT_ID
  if (toml.WEB_AUTH_CONTRACT_ID && options.includeContracts) {
    const contractId = `contract_${sanitizeId(toml.WEB_AUTH_CONTRACT_ID)}`;
    if (!nodes.find((n) => n.id === contractId)) {
      nodes.push({
        id: contractId,
        label: `Auth Contract ${toml.WEB_AUTH_CONTRACT_ID.slice(0, 12)}...`,
        type: 'contract',
        metadata: { contractId: toml.WEB_AUTH_CONTRACT_ID },
      });
    }
    edges.push({
      from: orgId,
      to: contractId,
      type: 'contracts',
      label: 'auth contract',
    });
  }

  if (options.format === 'mermaid') {
    return generateMermaid(nodes, edges);
  }
  return generateDot(nodes, edges);
}

function generateMermaid(nodes: Node[], edges: Edge[]): string {
  const lines: string[] = ['```mermaid', 'graph TD'];

  // Define nodes
  for (const node of nodes) {
    const shape = getMermaidShape(node.type);
    const color = node.metadata?.color;
    const style = color ? `style ${node.id} fill:${color},color:#fff` : '';
    lines.push(`  ${node.id}[${shape}${node.label}${shape}]`);
    if (style) lines.push(`  ${style}`);
  }

  lines.push('');

  // Define edges
  for (const edge of edges) {
    const label = edge.label ? `|${edge.label}|` : '';
    lines.push(`  ${edge.from} -->${label} ${edge.to}`);
  }

  lines.push('```');
  return lines.join('\n');
}

function getMermaidShape(type: NodeType): string {
  switch (type) {
    case 'organization':
      return '(( ';
    case 'server':
      return '[ ';
    case 'asset':
      return '{ ';
    case 'issuer':
      return '(( ';
    case 'contract':
      return '[[';
    case 'validator':
      return '(( ';
    default:
      return '[ ';
  }
}

function generateDot(nodes: Node[], edges: Edge[]): string {
  const lines: string[] = [
    'digraph stellar_toml {',
    '  rankdir=TB;',
    '  node [fontname="Arial", fontsize=10];',
    '  edge [fontname="Arial", fontsize=9];',
    '',
  ];

  // Define nodes
  for (const node of nodes) {
    const attrs = getDotAttributes(node);
    lines.push(`  ${node.id} [${attrs}];`);
  }

  lines.push('');

  // Define edges
  for (const edge of edges) {
    const label = edge.label ? ` label="${edge.label}"` : '';
    lines.push(`  ${edge.from} -> ${edge.to}[${label}];`);
  }

  lines.push('}');
  return lines.join('\n');
}

function getDotAttributes(node: Node): string {
  const attrs: string[] = [`label="${escapeDot(node.label)}"`, `shape=${getDotShape(node.type)}`];

  const color = node.metadata?.color;
  if (color) {
    attrs.push(`style=filled`);
    attrs.push(`fillcolor="${color}"`);
    attrs.push(`fontcolor=white`);
  }

  return attrs.join(', ');
}

function getDotShape(type: NodeType): string {
  switch (type) {
    case 'organization':
      return 'ellipse';
    case 'server':
      return 'box';
    case 'asset':
      return 'diamond';
    case 'issuer':
      return 'ellipse';
    case 'contract':
      return 'box3d';
    case 'validator':
      return 'hexagon';
    default:
      return 'box';
  }
}

function escapeDot(str: string): string {
  return str.replace(/"/g, '\\"').replace(/\n/g, '\\n');
}
