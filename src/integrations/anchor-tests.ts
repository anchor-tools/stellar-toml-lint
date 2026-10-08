export interface AnchorTestsConfig {
  homeDomain?: string;
  seps: number[];
  assetCode?: string;
  sepConfig?: Record<string, unknown>;
  [key: string]: unknown;
}

export function generateAnchorTestsConfig(
  doc: Record<string, unknown>,
  domain?: string,
): AnchorTestsConfig {
  const config: AnchorTestsConfig = {
    seps: [],
    sepConfig: {},
  };

  if (domain) {
    config.homeDomain = domain;
  } else if (typeof doc.HOME_DOMAIN === 'string') {
    config.homeDomain = doc.HOME_DOMAIN;
  }

  // To make it compatible with `@stellar/anchor-tests` CLI arguments format.
  // Actually, wait, let's just dump what's requested.
  // Extract home domain, SIGNING_KEY, WEB_AUTH_ENDPOINT, TRANSFER_SERVER_SEP0024, and all assets in [[CURRENCIES]].

  if (doc.SIGNING_KEY) {
    config.SIGNING_KEY = doc.SIGNING_KEY;
  }

  if (doc.WEB_AUTH_ENDPOINT) {
    config.WEB_AUTH_ENDPOINT = doc.WEB_AUTH_ENDPOINT;
  }

  if (doc.TRANSFER_SERVER_SEP0024) {
    config.TRANSFER_SERVER_SEP0024 = doc.TRANSFER_SERVER_SEP0024;
  }

  if (Array.isArray(doc.CURRENCIES) && doc.CURRENCIES.length > 0) {
    config.CURRENCIES = doc.CURRENCIES;
  }

  if (!doc.WEB_AUTH_ENDPOINT) {
    // eslint-disable-next-line no-console
    console.warn(
      'Warning: WEB_AUTH_ENDPOINT is missing. SEP-10 and other authenticated tests will be skipped.',
    );
  }
  if (!doc.SIGNING_KEY) {
    // eslint-disable-next-line no-console
    console.warn('Warning: SIGNING_KEY is missing. SEP-10 challenge verification will be skipped.');
  }
  if (!doc.TRANSFER_SERVER_SEP0024) {
    // eslint-disable-next-line no-console
    console.warn('Warning: TRANSFER_SERVER_SEP0024 is missing. SEP-24 tests will be skipped.');
  }

  return config;
}
