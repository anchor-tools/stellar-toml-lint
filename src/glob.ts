/**
 * Cross-platform glob expansion for the CLI's positional file arguments.
 *
 * A POSIX shell expands a recursive pattern before the linter ever sees the
 * argument; PowerShell and CMD do not, so there the pattern arrives as one
 * literal filename and the run dies on `ENOENT`. Expanding here makes the
 * quoted pattern behave the same on every platform — and lets the run say what
 * went wrong when a pattern matches nothing, instead of quoting the OS.
 *
 * Deliberately hand-rolled rather than pulled from a dependency: the syntax is
 * the small subset people actually write for this — `*`, `?`, `[...]`, and the
 * `**` globstar — the walk never leaves the pattern's static prefix, and the
 * whole file is small enough to audit by eye, which is the point of a linter
 * that runs in other people's CI.
 */
import { readdir, stat } from 'node:fs/promises';
import { join, parse } from 'node:path';
import type { Dirent } from 'node:fs';

/** Characters that mean "this argument is a pattern, not a path". */
const MAGIC = /[*?[]/;

/**
 * True when the argument should be expanded rather than read as a literal
 * path. Backslashes are normalised first so a Windows-authored pattern like
 * `configs\*.toml` is recognised too.
 */
export function hasMagic(pattern: string): boolean {
  return MAGIC.test(pattern.replace(/\\/g, '/'));
}

/**
 * Resolves a glob to the files it matches, sorted and without duplicates —
 * the same tree should produce the same report order on every platform, and
 * `readdir` promises nothing about ordering. Returns `[]` for a pattern that
 * matches nothing, and the path itself for an argument with no magic in it.
 *
 * Only files come back: directories are never lintable, and a pattern like
 * `configs/*` should not hand the caller an `EISDIR` for every subdirectory it
 * walked past. Hidden entries are skipped unless the pattern names them, so
 * `**` cannot descend into `.git`.
 */
export async function expandGlob(pattern: string): Promise<string[]> {
  const normalised = pattern.replace(/\\/g, '/');
  const root = parse(normalised).root;
  // The root (`/`, `C:/`, `//server/share/`) is already the walk's starting
  // point; leaving it in the segments would join `C:` onto `C:/` and produce
  // a path that cannot be read on Windows.
  const segments = normalised
    .slice(root.length)
    .split('/')
    .filter((segment) => segment !== '');

  // A trailing `**` means "everything underneath", which is `**/*` — the
  // globstar alone would otherwise only ever match directories.
  if (segments[segments.length - 1] === '**') segments.push('*');

  // Everything up to the first magic segment is a directory that must exist;
  // starting there keeps `node_modules/**` from walking the whole filesystem.
  let base = root === '' ? '.' : root;
  let start = 0;
  while (start < segments.length && !hasMagic(segments[start] ?? '')) {
    base = join(base, segments[start] as string);
    start++;
  }

  const remaining = segments.slice(start);
  if (remaining.length === 0) return (await isFile(base)) ? [base] : [];

  const matches: string[] = [];
  await walk(base, remaining, matches);
  return [...new Set(matches)].sort();
}

/** Matches the remaining pattern segments against the tree under `dir`. */
async function walk(dir: string, segments: string[], matches: string[]): Promise<void> {
  const head = segments[0];
  if (head === undefined) return;

  const entries = await readDir(dir);
  if (entries.length === 0) return;
  const tail = segments.slice(1);

  // The globstar consumes zero segments (the rest may match right here) or
  // descends one directory at a time, staying a globstar as it goes.
  if (head === '**') {
    if (tail.length > 0) await walk(dir, tail, matches);
    for (const entry of entries) {
      if (!entry.isDirectory() || hidden(entry.name, head)) continue;
      await walk(join(dir, entry.name), segments, matches);
    }
    return;
  }

  const matchesSegment = segmentRegex(head);
  for (const entry of entries) {
    if (hidden(entry.name, head) || !matchesSegment.test(entry.name)) continue;

    const next = join(dir, entry.name);
    if (tail.length === 0) {
      // Symlinks count: an anchor's `stellar.toml` behind a link is still the
      // file the operator meant to lint.
      if (entry.isFile() || entry.isSymbolicLink()) matches.push(next);
      continue;
    }
    if (!entry.isDirectory()) continue;
    await walk(next, tail, matches);
  }
}

/** Dotfiles are opt-in, as they are in every shell glob. */
function hidden(name: string, segment: string): boolean {
  return name.startsWith('.') && !segment.startsWith('.');
}

/** Reads a directory, treating every failure as "nothing here can match". */
async function readDir(dir: string): Promise<Dirent[]> {
  try {
    return await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

/**
 * Compiles one path segment to a regular expression.
 *
 * `*` and `?` never cross a separator, `[...]` supports the `!` negation form,
 * and every other character is matched literally — a file called `a+b.toml`
 * must not be read as a regex quantifier.
 */
function segmentRegex(segment: string): RegExp {
  let source = '';

  for (let i = 0; i < segment.length; i++) {
    const char = segment[i] as string;

    if (char === '*') {
      source += '[^/]*';
      while (segment[i + 1] === '*') i++;
      continue;
    }
    if (char === '?') {
      source += '[^/]';
      continue;
    }
    if (char === '[') {
      const close = segment.indexOf(']', i + 1);
      if (close === -1) {
        source += '\\[';
        continue;
      }
      const body = segment.slice(i + 1, close);
      source += body.startsWith('!') ? `[^${body.slice(1)}]` : `[${body}]`;
      i = close;
      continue;
    }

    source += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  return new RegExp(`^${source}$`);
}
