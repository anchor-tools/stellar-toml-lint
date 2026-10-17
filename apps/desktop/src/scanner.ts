/**
 * Turning a list of files into a {@link ScanSnapshot} (issue #371).
 *
 * The reader and the linter are both injected. That is not test scaffolding for
 * its own sake: it means this module — the one that decides what "broken"
 * means for the tray — has no dependency on `node:fs` or on the built linter
 * bundle, so its behaviour on an unreadable file, an empty folder, or a file
 * that vanishes mid-scan is asserted directly rather than staged on disk.
 *
 * The one judgement encoded here is how a read or parse failure is reported.
 * `lint()` already returns a diagnostic for a file it cannot parse, so a
 * syntax error arrives as an ordinary error count. A file that cannot be *read*
 * — deleted between the watch event and the scan, or permission-denied —
 * produces no diagnostics at all, and reporting that as zero errors would turn
 * "your file disappeared" into a green tray. It is marked `unreadable`, which
 * {@link trayStateFor} counts as an error.
 */
import type { FileStatus, ScanSnapshot } from './status.js';

/** The error and warning counts one lint produced. */
export interface LintCounts {
  errors: number;
  warnings: number;
}

/** Reads a file's text, or throws the way `readFileSync` does. */
export type ReadFile = (path: string) => string;

/** Lints a source string. Supplied by `main.ts` from the built package. */
export type LintSource = (source: string, path: string) => LintCounts;

/** A clock, so a snapshot's timestamp is deterministic under test. */
export type Clock = () => number;

/**
 * Lints every path and returns one snapshot.
 *
 * Paths are sorted so two scans of the same folder produce entries in the same
 * order; `notificationsFor` keys on path rather than index, but a stable order
 * keeps the window's list from reshuffling under the user's cursor on every
 * save.
 */
export function scanFiles(
  paths: readonly string[],
  readFile: ReadFile,
  lintSource: LintSource,
  now: Clock = Date.now,
): ScanSnapshot {
  const files: FileStatus[] = [];

  for (const path of [...paths].sort()) {
    let source: string;
    try {
      source = readFile(path);
    } catch {
      files.push({ path, errors: 0, warnings: 0, unreadable: true });
      continue;
    }

    try {
      const counts = lintSource(source, path);
      files.push({ path, errors: counts.errors, warnings: counts.warnings });
    } catch {
      // A linter that throws is a bug in the linter, but the desktop app's job
      // is to keep watching: report the file as unreadable and carry on rather
      // than take the tray down with it.
      files.push({ path, errors: 0, warnings: 0, unreadable: true });
    }
  }

  return { files, scannedAt: now() };
}

/**
 * Merges a partial rescan into the previous snapshot.
 *
 * A save touches one file, so re-linting the whole folder on every keystroke
 * would make a 200-file directory unusable. The watcher reports which paths
 * changed, this re-lints only those, and the rest of the snapshot carries
 * forward — which is also what makes {@link notificationsFor}'s comparison
 * meaningful, since the untouched entries are genuinely unchanged rather than
 * re-measured.
 *
 * A path in `changed` that is no longer in `previous` is an added file and is
 * appended; a path whose file has disappeared is reported `unreadable` by
 * {@link scanFiles} and is dropped here instead, since a deleted file is not a
 * problem with the configuration.
 */
export function mergeScan(
  previous: ScanSnapshot,
  rescanned: ScanSnapshot,
  stillExists: (path: string) => boolean,
): ScanSnapshot {
  const updated = new Map(previous.files.map((file) => [file.path, file]));

  for (const file of rescanned.files) {
    if (!stillExists(file.path)) {
      updated.delete(file.path);
      continue;
    }
    updated.set(file.path, file);
  }

  return {
    files: [...updated.values()].sort((a, b) => a.path.localeCompare(b.path)),
    scannedAt: rescanned.scannedAt,
  };
}
