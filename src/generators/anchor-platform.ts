export interface AnchorPlatformConfig {
  assets: AssetConfig[];
  sep10?: Record<string, string>;
  sep12?: Record<string, string>;
  sep24?: Record<string, string>;
  sep38?: Record<string, string>;
}

interface AssetConfig {
  code: string;
  issuer?: string;
  distribution_account?: string;
  schema: string;
  significant_decimals?: number;
  deposit?: { enabled: boolean };
  withdraw?: { enabled: boolean };
}

export function generateAnchorPlatformConfig(doc: Record<string, unknown>): AnchorPlatformConfig {
  const config: AnchorPlatformConfig = { assets: [] };

  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    for (const currency of currencies) {
      if (typeof currency !== 'object' || currency === null) continue;
      const c = currency as Record<string, unknown>;
      const code = typeof c.code === 'string' ? c.code : undefined;
      if (!code) continue;

      const asset: AssetConfig = {
        code,
        schema: `stellar:${code}`,
      };
      if (typeof c.issuer === 'string') {
        asset.issuer = c.issuer;
        asset.schema = `stellar:${code}:${c.issuer}`;
      }
      if (typeof c.display_decimals === 'number') {
        asset.significant_decimals = c.display_decimals;
      }
      const hasSep24 = typeof doc.TRANSFER_SERVER_SEP0024 === 'string';
      const hasSep6 = typeof doc.TRANSFER_SERVER === 'string';
      if (hasSep24 || hasSep6) {
        asset.deposit = { enabled: true };
        asset.withdraw = { enabled: true };
      }
      config.assets.push(asset);
    }
  }

  if (typeof doc.WEB_AUTH_ENDPOINT === 'string') {
    config.sep10 = {
      web_auth_endpoint: doc.WEB_AUTH_ENDPOINT as string,
    };
    if (typeof doc.SIGNING_KEY === 'string') {
      config.sep10.signing_key = doc.SIGNING_KEY as string;
    }
  }

  if (typeof doc.KYC_SERVER === 'string') {
    config.sep12 = { kyc_server: doc.KYC_SERVER as string };
  }

  if (typeof doc.TRANSFER_SERVER_SEP0024 === 'string') {
    config.sep24 = {
      interactive_url: doc.TRANSFER_SERVER_SEP0024 as string,
    };
  }

  if (typeof doc.ANCHOR_QUOTE_SERVER === 'string') {
    config.sep38 = {
      quote_server: doc.ANCHOR_QUOTE_SERVER as string,
    };
  }

  return config;
}

export function formatAnchorPlatformYaml(config: AnchorPlatformConfig): string {
  const lines: string[] = [];

  if (config.assets.length > 0) {
    lines.push('assets:');
    for (const asset of config.assets) {
      lines.push(`  - code: "${asset.code}"`);
      if (asset.issuer) lines.push(`    issuer: "${asset.issuer}"`);
      lines.push(`    schema: "${asset.schema}"`);
      if (asset.significant_decimals !== undefined) {
        lines.push(`    significant_decimals: ${asset.significant_decimals}`);
      }
      if (asset.deposit) lines.push(`    deposit:\n      enabled: ${asset.deposit.enabled}`);
      if (asset.withdraw) lines.push(`    withdraw:\n      enabled: ${asset.withdraw.enabled}`);
    }
  }

  if (config.sep10) {
    lines.push('sep10:');
    for (const [k, v] of Object.entries(config.sep10)) {
      lines.push(`  ${k}: "${v}"`);
    }
  }

  if (config.sep12) {
    lines.push('sep12:');
    for (const [k, v] of Object.entries(config.sep12)) {
      lines.push(`  ${k}: "${v}"`);
    }
  }

  if (config.sep24) {
    lines.push('sep24:');
    for (const [k, v] of Object.entries(config.sep24)) {
      lines.push(`  ${k}: "${v}"`);
    }
  }

  if (config.sep38) {
    lines.push('sep38:');
    for (const [k, v] of Object.entries(config.sep38)) {
      lines.push(`  ${k}: "${v}"`);
    }
  }

  return lines.join('\n') + '\n';
}
