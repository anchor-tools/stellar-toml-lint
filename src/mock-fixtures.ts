/**
 * Offline fixture transport for the network-bound checks (`--mock-fixtures`).
 *
 * Enterprise CI pipelines and air-gapped development sandboxes cannot reach
 * Horizon, a SEP-38 quote server, or a Soroban RPC. Pointing the linter at
 * recorded responses lets those environments exercise the network checks — and
 * lets a test suite assert on them — without a single outbound request.
 *
 * The mapping used here mirrors how the endpoints look on the wire: a request
 * to `https://horizon.stellar.org/accounts/G...` is served from
 * `<fixturesDir>/horizon.stellar.org/accounts/G....json`, falling back to the
 * shorter host label (`<fixturesDir>/horizon/accounts/G....json`). A request
 * whose fixture is absent throws rather than falling through to the network,
 * so an incomplete fixture set fails loudly instead of quietly going online.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** The input type `fetch` accepts, without depending on a DOM lib name. */
type FetchInput = Parameters<typeof fetch>[0];

/**
 * The shape of a fixture file.
 *
 * A plain JSON document is served as the response body with status 200. Wrap it
 * in an object carrying a `body` key to also set `status` and `headers`:
 *
 * ```json
 * { "status": 404, "headers": { "content-type": "application/json" }, "body": {} }
 * ```
 */
export interface FixtureFile {
  status?: number;
  headers?: Record<string, string>;
  /** Parsed fixture JSON. */
  body: unknown;
}

/** A fixture file located on disk, plus how it was found. */
interface ResolvedFixture {
  /** Path relative to the fixtures directory, echoed in the response headers. */
  relative: string;
  fixture: FixtureFile;
}

/**
 * Raised when fixture mode is on and a request has no matching file.
 *
 * It deliberately names the URL and the candidate paths, because the usual
 * cause is a typo in the directory layout rather than a missing scenario.
 */
export class MissingFixtureError extends Error {
  readonly url: string;
  readonly fixturesDir: string;
  readonly tried: string[];

  constructor(url: string, fixturesDir: string, tried: string[]) {
    super(
      `No mock fixture for ${url} under ${fixturesDir}. Fixture mode makes no external ` +
        `requests, so the check cannot run. Expected one of: ${
          tried.length > 0 ? tried.join(', ') : '(no candidate paths — malformed URL)'
        }`,
    );
    this.name = 'MissingFixtureError';
    this.url = url;
    this.fixturesDir = fixturesDir;
    this.tried = tried;
  }
}

/**
 * Candidate fixture paths for a URL, relative to the fixtures directory, most
 * specific first.
 *
 * Both the full hostname (`horizon.stellar.org`) and its first label
 * (`horizon`) are accepted, because hand-organised fixture trees usually drop
 * the TLD. A path ending in `/` (or the host root) resolves to `index.json` so
 * a directory-style endpoint like `https://api.example.com/` has somewhere to
 * live. Query strings are ignored: fixtures match on host and path.
 */
export function fixtureCandidates(url: URL): string[] {
  const host = url.hostname.toLowerCase();
  const firstLabel = host.split('.')[0] ?? host;

  let pathname: string;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    // A malformed percent-escape is not a path this can map to a file.
    return [];
  }

  const rawSegments = pathname.split('/').filter((segment) => segment !== '');
  // Dot segments would let a fixture path escape the directory; URL parsing
  // removes the plain form, so only an encoded one can still be present here.
  const segments = rawSegments.filter((segment) => segment !== '.' && segment !== '..');
  if (segments.length !== rawSegments.length) return [];

  const leaf = segments.join('/');
  const isDirectory = leaf === '' || pathname.endsWith('/');
  const names = isDirectory
    ? [`${leaf === '' ? '' : `${leaf}/`}index.json`]
    : [`${leaf}.json`, leaf];

  const hostDirs = firstLabel === host ? [host] : [host, firstLabel];
  const candidates: string[] = [];
  for (const dir of hostDirs) {
    for (const name of names) candidates.push(`${dir}/${name}`);
  }
  return candidates;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function headerRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const headers: Record<string, string> = {};
  for (const [key, header] of Object.entries(value)) {
    if (typeof header === 'string') headers[key] = header;
  }
  return headers;
}

/**
 * Reads one fixture file.
 *
 * A document carrying a `body` key is treated as an envelope with `status` and
 * `headers`; anything else is the response body itself. Malformed JSON is a
 * loud error, since a silently-empty fixture would hide the very scenario the
 * fixture was recorded to prove.
 */
function readFixture(file: string, relative: string): ResolvedFixture {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(`Mock fixture ${file} could not be read: ${messageOf(error)}`);
  }

  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Mock fixture ${file} is not valid JSON: ${messageOf(error)}`);
  }

  if (isRecord(value) && 'body' in value) {
    const status = typeof value.status === 'number' ? value.status : undefined;
    const headers = headerRecord(value.headers);
    return {
      relative,
      fixture: {
        ...(status !== undefined ? { status } : {}),
        ...(headers !== undefined ? { headers } : {}),
        body: value.body,
      },
    };
  }

  return { relative, fixture: { body: value } };
}

/** Finds the first candidate that exists as a regular file. */
function resolveFixture(fixturesDir: string, url: URL): ResolvedFixture | undefined {
  for (const relative of fixtureCandidates(url)) {
    const file = join(fixturesDir, relative);
    if (!existsSync(file)) continue;
    try {
      if (!statSync(file).isFile()) continue;
    } catch {
      continue;
    }
    return readFixture(file, relative);
  }
  return undefined;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toUrl(input: FetchInput): URL {
  if (typeof input === 'string') return new URL(input);
  if (input instanceof URL) return input;
  return new URL(input.url);
}

/**
 * Serializes a fixture body.
 *
 * A string body is served verbatim so a fixture can stand in for a
 * `text/plain` response — which is what `lintDomain` reads back for
 * `/.well-known/stellar.toml`. Everything else is JSON-encoded.
 */
function serializeBody(body: unknown): string {
  return typeof body === 'string' ? body : JSON.stringify(body ?? null);
}

/** Builds the `Response` a fixture describes. */
function fixtureResponse(found: ResolvedFixture, method: string | undefined): Response {
  const isOptions = method?.toUpperCase() === 'OPTIONS';
  const status = isOptions ? 204 : (found.fixture.status ?? 200);
  // `Response` forbids a body on these statuses, and a fixture may use them.
  const body = status === 204 || status === 304 ? null : serializeBody(found.fixture.body);
  const headers = new Headers({
    'content-type': 'application/json',
    ...(isOptions
      ? {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'content-type, authorization',
        }
      : {}),
    ...(found.fixture.headers ?? {}),
    // Named last so a fixture cannot spoof which file answered the request.
    'x-mock-fixture': found.relative,
  });
  return new Response(body, { status, headers });
}

/**
 * Returns a `fetch` that serves network-check requests from `fixturesDir`.
 *
 * Every request is matched against the local tree; a URL with no fixture throws
 * a {@link MissingFixtureError} instead of reaching the network, which is what
 * makes the flag safe to rely on inside a hermetic sandbox. The only I/O the
 * returned function performs is reading files beneath `fixturesDir`.
 */
export function createFixtureFetch(fixturesDir: string): typeof fetch {
  if (!existsSync(fixturesDir)) {
    throw new Error(
      `--mock-fixtures directory ${fixturesDir} does not exist; create it and add the recorded responses.`,
    );
  }

  return async (input: FetchInput, init?: RequestInit): Promise<Response> => {
    const url = toUrl(input);
    const found = resolveFixture(fixturesDir, url);
    if (found === undefined) {
      throw new MissingFixtureError(url.toString(), fixturesDir, fixtureCandidates(url));
    }
    return fixtureResponse(found, init?.method);
  };
}
