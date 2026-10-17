/**
 * Tray status and notification policy (issue #371).
 *
 * The app's whole value proposition is that it runs in the background and says
 * nothing until something breaks. That makes the notification *policy* the
 * feature — not the notification API — so it lives here as pure functions over
 * two snapshots, with no `electron` import, and the test suite drives it
 * directly.
 *
 * The rule the issue asks for is "notify when a configuration change
 * introduces an error", and the word that matters is *introduces*. A watcher
 * that notifies on every scan where errors exist would fire on every keystroke
 * in a file that is temporarily mid-edit, and a compliance officer would mute
 * it within the hour — at which point the tool is worse than nothing, because
 * it is installed and ignored. So {@link notificationsFor} compares against the
 * previous scan and speaks only about what changed:
 *
 * - a file that had no errors and now has some,
 * - a file whose error count grew,
 * - a file that had errors and now has none (one "resolved" notice, so the user
 *   learns the tray went green without having to look at it).
 *
 * A file whose errors are unchanged produces nothing, however many scans run.
 * Warnings never notify: they are what the tray badge and the window are for.
 */

/** One watched file's standing after the most recent lint. */
export interface FileStatus {
  /** Absolute path, which is also the identity of the entry across scans. */
  path: string;
  errors: number;
  warnings: number;
  /** Set when the file could not be read or parsed at all. */
  unreadable?: boolean;
}

/** The result of one scan of the watched folder. */
export interface ScanSnapshot {
  /** Statuses, in whatever order the scan produced them. */
  files: readonly FileStatus[];
  /** Epoch milliseconds the scan finished. */
  scannedAt: number;
}

/**
 * What the tray icon shows.
 *
 * `idle` is "no folder selected yet", which is distinct from `ok` — a green
 * check on an app that is watching nothing would be a lie.
 */
export type TrayState = 'idle' | 'scanning' | 'ok' | 'warning' | 'error';

/** A notification as `new Notification(...)` takes it. */
export interface NotificationSpec {
  title: string;
  body: string;
  /** The file the notice is about, so clicking it can reveal that file. */
  path: string;
  /** `true` for a recovery notice, which the tray renders differently. */
  resolved: boolean;
}

/** Totals across a snapshot. */
export interface ScanTotals {
  files: number;
  errors: number;
  warnings: number;
  filesWithErrors: number;
  unreadable: number;
}

/** Sums a snapshot, which both the tooltip and the tray state need. */
export function totalsFor(snapshot: ScanSnapshot): ScanTotals {
  let errors = 0;
  let warnings = 0;
  let filesWithErrors = 0;
  let unreadable = 0;

  for (const file of snapshot.files) {
    errors += file.errors;
    warnings += file.warnings;
    if (file.errors > 0) filesWithErrors++;
    if (file.unreadable === true) unreadable++;
  }

  return { files: snapshot.files.length, errors, warnings, filesWithErrors, unreadable };
}

/**
 * The tray state for a snapshot.
 *
 * An unreadable file counts as an error: a `stellar.toml` that does not parse
 * is the most broken state a file can be in, and reporting it as "ok" because
 * it produced no diagnostics would invert the signal.
 */
export function trayStateFor(snapshot: ScanSnapshot | undefined): TrayState {
  if (snapshot === undefined) return 'idle';
  if (snapshot.files.length === 0) return 'ok';

  const totals = totalsFor(snapshot);
  if (totals.errors > 0 || totals.unreadable > 0) return 'error';
  if (totals.warnings > 0) return 'warning';
  return 'ok';
}

/** Pluralises a count without a dependency: `1 error`, `2 errors`. */
function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

/** The last path segment, for a message that must stay inside a notification. */
function basename(path: string): string {
  const parts = path.split(/[/\\]/);
  return parts[parts.length - 1] ?? path;
}

/**
 * The tray tooltip, which is the only status a background app usually shows.
 *
 * Written to be read at a glance in a menu bar: the state first, the counts
 * second, the folder never — the tooltip has no room for a path, and the menu
 * already names the folder.
 */
export function tooltipFor(snapshot: ScanSnapshot | undefined, appTitle: string): string {
  if (snapshot === undefined) return `${appTitle} — no folder watched`;

  const totals = totalsFor(snapshot);
  if (totals.files === 0) return `${appTitle} — no stellar.toml found`;

  const scope = plural(totals.files, 'file');
  if (totals.errors === 0 && totals.unreadable === 0 && totals.warnings === 0) {
    return `${appTitle} — ${scope}, no problems`;
  }

  const parts: string[] = [];
  if (totals.errors > 0) parts.push(plural(totals.errors, 'error'));
  if (totals.unreadable > 0) parts.push(`${plural(totals.unreadable, 'file')} unreadable`);
  if (totals.warnings > 0) parts.push(plural(totals.warnings, 'warning'));
  return `${appTitle} — ${scope}, ${parts.join(', ')}`;
}

/**
 * The notifications a transition from `previous` to `current` should raise.
 *
 * `previous` is `undefined` on the first scan after a folder is chosen. That
 * first scan *does* notify about files that are already broken: the user just
 * pointed the app at a folder and the answer "this one is broken" is the whole
 * reason they did. Subsequent scans only speak about changes.
 *
 * At most {@link MAX_NOTIFICATIONS} are returned. A folder where fifty files
 * break at once is a `git checkout`, not fifty separate problems, so the
 * overflow collapses into one summary notice rather than fifty toasts.
 */
export function notificationsFor(
  previous: ScanSnapshot | undefined,
  current: ScanSnapshot,
): NotificationSpec[] {
  const before = new Map((previous?.files ?? []).map((file) => [file.path, file]));
  const raised: NotificationSpec[] = [];
  const resolved: NotificationSpec[] = [];

  for (const file of current.files) {
    const was = before.get(file.path);
    const wasErrors = was === undefined ? 0 : errorWeight(was);
    const nowErrors = errorWeight(file);

    if (nowErrors > wasErrors) {
      raised.push({
        title: wasErrors === 0 ? 'stellar.toml now has errors' : 'stellar.toml has more errors',
        body: bodyFor(file),
        path: file.path,
        resolved: false,
      });
      continue;
    }

    // Only a transition all the way to clean is worth interrupting for;
    // "fewer errors than before" is progress the user is already watching.
    if (wasErrors > 0 && nowErrors === 0) {
      resolved.push({
        title: 'stellar.toml errors resolved',
        body: `${basename(file.path)} now passes with no errors`,
        path: file.path,
        resolved: true,
      });
    }
  }

  const ordered = [...raised, ...resolved];
  if (ordered.length <= MAX_NOTIFICATIONS) return ordered;

  const summary: NotificationSpec = {
    title: `${raised.length} files now have errors`,
    body: `${plural(raised.length, 'file')} in the watched folder changed and now report errors`,
    path: raised[0]?.path ?? current.files[0]?.path ?? '',
    resolved: false,
  };
  return [summary];
}

/** How many individual notices one scan may raise before they collapse. */
export const MAX_NOTIFICATIONS = 3;

/**
 * The error count a file contributes, counting "unreadable" as one error.
 *
 * A file that stops parsing reports zero diagnostics, so without this an
 * edit that breaks the TOML syntax would look like a *fix*.
 */
function errorWeight(file: FileStatus): number {
  return file.unreadable === true ? Math.max(file.errors, 1) : file.errors;
}

/** The notification body: the file, then what is wrong with it. */
function bodyFor(file: FileStatus): string {
  const name = basename(file.path);
  if (file.unreadable === true) return `${name} could not be parsed`;
  const parts = [plural(file.errors, 'error')];
  if (file.warnings > 0) parts.push(plural(file.warnings, 'warning'));
  return `${name} — ${parts.join(', ')}`;
}
