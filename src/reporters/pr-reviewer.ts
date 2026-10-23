import { readFile } from 'node:fs/promises';
import { fix } from '../fix.js';
import type { Diagnostic } from '../types.js';

export interface PullRequestReviewSource {
  filename: string;
  source: string;
  diagnostics: Diagnostic[];
}

interface GitHubEvent {
  repository?: { name?: unknown; owner?: { login?: unknown } };
  pull_request?: { number?: unknown };
}

export interface PullRequestReviewPayload {
  event: 'COMMENT';
  body: string;
  comments: Array<{ path: string; line: number; side: 'RIGHT'; body: string }>;
}

function suggestionFor(source: string, diagnostic: Diagnostic): string | undefined {
  const corrected = fix(source, [diagnostic]);
  const edit = corrected.edits[0];
  if (edit === undefined || diagnostic.position === undefined) return undefined;
  let lineStart = 0;
  for (let line = 1; line < diagnostic.position.line; line++) {
    const newline = corrected.source.indexOf('\n', lineStart);
    if (newline === -1) return undefined;
    lineStart = newline + 1;
  }
  const lineEnd = corrected.source.indexOf('\n', lineStart);
  const fixedLine = corrected.source.slice(
    lineStart,
    lineEnd === -1 ? corrected.source.length : lineEnd,
  );
  return fixedLine;
}

export function buildPullRequestReviewPayload(
  event: GitHubEvent,
  files: PullRequestReviewSource[],
): PullRequestReviewPayload | undefined {
  const owner = event.repository?.owner?.login;
  const repository = event.repository?.name;
  const pullNumber = event.pull_request?.number;
  if (
    typeof owner !== 'string' ||
    typeof repository !== 'string' ||
    typeof pullNumber !== 'number' ||
    !Number.isInteger(pullNumber)
  ) {
    return undefined;
  }

  const comments = files.flatMap(({ filename, source, diagnostics }) =>
    diagnostics.flatMap((diagnostic) => {
      const line = diagnostic.position?.line;
      const suggestion = suggestionFor(source, diagnostic);
      if (line === undefined || suggestion === undefined) return [];
      return [
        {
          path: filename,
          line,
          side: 'RIGHT' as const,
          body: `${diagnostic.rule}: ${diagnostic.message}\n\n\`\`\`suggestion\n${suggestion}\n\`\`\`\n\n<!-- stellar-toml-lint:${encodeURIComponent(`${filename}:${line}:${diagnostic.rule}`)} -->`,
        },
      ];
    }),
  );
  if (comments.length === 0) return undefined;

  return {
    event: 'COMMENT',
    body: `stellar-toml-lint found ${comments.length} issue(s) with safe suggested fixes.`,
    comments,
  };
}

export interface PullRequestReviewResult {
  ok: boolean;
  reason?: string;
  status?: number;
}

export async function submitPullRequestReview(
  files: PullRequestReviewSource[],
  options: {
    eventPath?: string;
    token?: string;
    fetchImpl?: typeof fetch;
  } = {},
): Promise<PullRequestReviewResult> {
  const token = options.token ?? process.env.GITHUB_TOKEN;
  const eventPath = options.eventPath ?? process.env.GITHUB_EVENT_PATH;
  if (!token || !eventPath) return { ok: false, reason: 'GitHub Actions credentials are missing' };

  let event: GitHubEvent;
  try {
    event = JSON.parse(await readFile(eventPath, 'utf8')) as GitHubEvent;
  } catch {
    return { ok: false, reason: 'GitHub event payload could not be read' };
  }
  const owner = event.repository?.owner?.login;
  const repository = event.repository?.name;
  const pullNumber = event.pull_request?.number;
  if (
    typeof owner !== 'string' ||
    typeof repository !== 'string' ||
    typeof pullNumber !== 'number' ||
    !Number.isInteger(pullNumber)
  ) {
    return { ok: false, reason: 'Event is not a pull request' };
  }
  const payload = buildPullRequestReviewPayload(event, files);
  const apiRoot = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}`;
  const fetchImpl = options.fetchImpl ?? fetch;
  try {
    if (payload !== undefined) {
      const response = await fetchImpl(`${apiRoot}/pulls/${pullNumber}/reviews`, {
        method: 'POST',
        headers: {
          accept: 'application/vnd.github+json',
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'x-github-api-version': '2022-11-28',
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) return { ok: false, status: response.status };
    }

    const commentsResponse = await fetchImpl(
      `${apiRoot}/pulls/${pullNumber}/comments?per_page=100`,
      {
        headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json' },
      },
    );
    if (!commentsResponse.ok) return { ok: false, status: commentsResponse.status };
    const existing = (await commentsResponse.json()) as Array<{
      id?: unknown;
      user?: { type?: unknown };
      body?: unknown;
    }>;
    const desired = new Set(
      payload?.comments.map(
        ({ body }) => /<!-- stellar-toml-lint:([^>]+) -->/.exec(body)?.[1] ?? '',
      ) ?? [],
    );
    for (const comment of existing) {
      if (comment.user?.type !== 'Bot' || typeof comment.body !== 'string') continue;
      const marker = /<!-- stellar-toml-lint:([^>]+) -->/.exec(comment.body)?.[1];
      if (marker === undefined || desired.has(marker) || typeof comment.id !== 'number') continue;
      const deleted = await fetchImpl(`${apiRoot}/pulls/comments/${comment.id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json' },
      });
      if (!deleted.ok) return { ok: false, status: deleted.status };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: 'GitHub API request failed' };
  }
}
