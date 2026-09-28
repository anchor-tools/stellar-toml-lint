/** Result of checking a validator's published Stellar history archive state. */
export type HistoryArchiveVerification =
  | { status: 'valid' }
  | { status: 'unreachable'; message: string }
  | { status: 'malformed'; message: string };

const METADATA_PATH = '.well-known/stellar-history.json';
const TEMPLATE = /\{[^}]*\}/g;

function metadataUrlFor(historyUrl: string): string | undefined {
  try {
    const root = new URL(historyUrl.replace(TEMPLATE, ''));
    root.search = '';
    root.hash = '';
    root.pathname = `${root.pathname.replace(/\/+$/, '')}/`;
    return new URL(METADATA_PATH, root).toString();
  } catch {
    return undefined;
  }
}

/**
 * Fetch and validate the HAS document published at a validator HISTORY URL.
 * Transport failures and non-200 responses are kept separate from invalid JSON
 * or schema so callers can report a useful, stable diagnostic.
 */
export async function verifyHistoryArchive(
  historyUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<HistoryArchiveVerification> {
  const metadataUrl = metadataUrlFor(historyUrl);
  if (!metadataUrl) return { status: 'unreachable', message: 'the HISTORY URL is invalid' };

  let response: Response;
  try {
    response = await fetchImpl(metadataUrl, { redirect: 'follow' });
  } catch {
    return { status: 'unreachable', message: 'the HAS file could not be fetched' };
  }
  if (response.status !== 200) {
    return { status: 'unreachable', message: `the HAS file returned HTTP ${response.status}` };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { status: 'malformed', message: 'the HAS file is not valid JSON' };
  }

  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { status: 'malformed', message: 'the HAS document must be a JSON object' };
  }
  const state = body as Record<string, unknown>;
  if (!Number.isInteger(state.version) || (state.version as number) < 1) {
    return {
      status: 'malformed',
      message: 'version must be an integer greater than or equal to 1',
    };
  }
  if (typeof state.server !== 'string' || state.server.trim() === '') {
    return { status: 'malformed', message: 'server must be a non-empty string' };
  }
  if (!Number.isInteger(state.currentLedger) || (state.currentLedger as number) <= 0) {
    return { status: 'malformed', message: 'currentLedger must be a positive integer' };
  }
  return { status: 'valid' };
}
