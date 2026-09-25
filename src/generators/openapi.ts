interface OpenApiDoc {
  openapi: string;
  info: { title: string; version: string; description: string };
  servers: { url: string; description: string }[];
  paths: Record<string, Record<string, PathOperation>>;
}

interface PathOperation {
  summary: string;
  operationId: string;
  tags: string[];
  responses: Record<string, { description: string }>;
  parameters?: { name: string; in: string; required: boolean; schema: { type: string } }[];
}

const SEP_ENDPOINTS: Record<
  string,
  { field: string; paths: { path: string; method: string; summary: string; tag: string }[] }
> = {
  sep6: {
    field: 'TRANSFER_SERVER',
    paths: [
      { path: '/deposit', method: 'get', summary: 'Initiate a SEP-6 deposit', tag: 'SEP-6' },
      { path: '/withdraw', method: 'get', summary: 'Initiate a SEP-6 withdrawal', tag: 'SEP-6' },
      { path: '/info', method: 'get', summary: 'Get SEP-6 server info', tag: 'SEP-6' },
      { path: '/transactions', method: 'get', summary: 'List SEP-6 transactions', tag: 'SEP-6' },
    ],
  },
  sep12: {
    field: 'KYC_SERVER',
    paths: [
      { path: '/customer', method: 'get', summary: 'Get customer KYC status', tag: 'SEP-12' },
      { path: '/customer', method: 'put', summary: 'Update customer KYC info', tag: 'SEP-12' },
    ],
  },
  sep24: {
    field: 'TRANSFER_SERVER_SEP0024',
    paths: [
      {
        path: '/transactions/deposit/interactive',
        method: 'post',
        summary: 'Initiate a SEP-24 interactive deposit',
        tag: 'SEP-24',
      },
      {
        path: '/transactions/withdraw/interactive',
        method: 'post',
        summary: 'Initiate a SEP-24 interactive withdrawal',
        tag: 'SEP-24',
      },
      { path: '/info', method: 'get', summary: 'Get SEP-24 server info', tag: 'SEP-24' },
      { path: '/transactions', method: 'get', summary: 'List SEP-24 transactions', tag: 'SEP-24' },
    ],
  },
  sep31: {
    field: 'DIRECT_PAYMENT_SERVER',
    paths: [
      {
        path: '/transactions',
        method: 'post',
        summary: 'Create a SEP-31 direct payment',
        tag: 'SEP-31',
      },
      {
        path: '/transactions/{id}',
        method: 'get',
        summary: 'Get SEP-31 transaction status',
        tag: 'SEP-31',
      },
    ],
  },
  sep38: {
    field: 'ANCHOR_QUOTE_SERVER',
    paths: [
      { path: '/info', method: 'get', summary: 'Get SEP-38 anchor info', tag: 'SEP-38' },
      { path: '/prices', method: 'get', summary: 'Get indicative prices', tag: 'SEP-38' },
      { path: '/price', method: 'get', summary: 'Get a firm quote price', tag: 'SEP-38' },
      { path: '/quote', method: 'post', summary: 'Request a firm quote', tag: 'SEP-38' },
      { path: '/quote/{id}', method: 'get', summary: 'Get an existing quote', tag: 'SEP-38' },
    ],
  },
};

export function generateOpenApiSpec(doc: Record<string, unknown>): OpenApiDoc {
  const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];
  const assetCodes = currencies
    .filter((c): c is Record<string, unknown> => typeof c === 'object' && c !== null)
    .map((c) => (typeof c.code === 'string' ? c.code : ''))
    .filter(Boolean);

  const servers: OpenApiDoc['servers'] = [];
  const paths: OpenApiDoc['paths'] = {};

  for (const [, sep] of Object.entries(SEP_ENDPOINTS)) {
    const baseUrl = doc[sep.field];
    if (typeof baseUrl !== 'string') continue;

    servers.push({ url: baseUrl, description: `${sep.paths[0]?.tag ?? 'SEP'} server` });

    for (const endpoint of sep.paths) {
      if (!paths[endpoint.path]) paths[endpoint.path] = {};
      const op: PathOperation = {
        summary: endpoint.summary,
        operationId: `${endpoint.tag.toLowerCase().replace('-', '')}_${endpoint.path.replace(/[/{}]/g, '_').replace(/^_/, '')}`,
        tags: [endpoint.tag],
        responses: {
          '200': { description: 'Successful response' },
          '400': { description: 'Bad request' },
        },
      };

      if (
        assetCodes.length > 0 &&
        (endpoint.path.includes('deposit') || endpoint.path.includes('withdraw'))
      ) {
        op.parameters = [
          { name: 'asset_code', in: 'query', required: true, schema: { type: 'string' } },
        ];
      }

      paths[endpoint.path]![endpoint.method] = op;
    }
  }

  return {
    openapi: '3.1.0',
    info: {
      title: 'Stellar Anchor API',
      version: '1.0.0',
      description: `Auto-generated OpenAPI specification from stellar.toml. Supported assets: ${assetCodes.join(', ') || 'none declared'}.`,
    },
    servers,
    paths,
  };
}
