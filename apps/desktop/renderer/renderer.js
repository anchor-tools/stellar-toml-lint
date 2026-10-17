/**
 * The window's view, in plain JavaScript (issue #371).
 *
 * The desktop app's purpose is the tray and the notifications; the window is
 * the place a user looks *after* being told something broke. A React bundle for
 * one table would add a build step, a dependency tree, and a chunk to ship, so
 * this is ~120 lines of DOM against the API the preload exposes.
 *
 * Note what the renderer cannot do. It has no `require`, no `fs`, and no path
 * it can act on: `reveal` sends an *index* into the snapshot the main process
 * produced, and the main process looks the path up itself. The text content of
 * every cell is set with `textContent`, never `innerHTML`, because a file path
 * is attacker-controlled input — a folder can be named anything.
 */
(() => {
  const api = window.stellarTomlLint;

  const el = {
    status: document.getElementById('status'),
    folder: document.getElementById('folder'),
    choose: document.getElementById('choose'),
    rescan: document.getElementById('rescan'),
    stop: document.getElementById('stop'),
    results: document.getElementById('results'),
    rows: document.getElementById('rows'),
    empty: document.getElementById('empty'),
    failure: document.getElementById('failure'),
  };

  const STATUS_LABELS = {
    ok: 'No problems',
    warning: 'Warnings only',
    error: 'Errors found',
    scanning: 'Scanning…',
    idle: 'Not watching',
  };

  /** Swaps the badge's state class and text. */
  function renderStatus(state) {
    el.status.className = `badge ${state}`;
    el.status.textContent = STATUS_LABELS[state] ?? state;
  }

  /** The last path segment, which is what identifies a file to a human. */
  function basename(path) {
    const parts = path.split(/[/\\]/);
    return parts[parts.length - 1] || path;
  }

  function renderRows(files) {
    el.rows.replaceChildren();

    files.forEach((file, index) => {
      const row = document.createElement('tr');
      if (file.errors > 0 || file.unreadable) row.className = 'has-errors';

      const nameCell = document.createElement('td');
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'path';
      // textContent, not innerHTML: a directory can be named `<img onerror=…>`.
      button.textContent = basename(file.path);
      button.title = file.path;
      button.addEventListener('click', () => {
        void api.revealFile({ index });
      });
      nameCell.append(button);

      const errorCell = document.createElement('td');
      errorCell.className = 'num errors';
      errorCell.textContent = file.unreadable ? 'unreadable' : String(file.errors);

      const warningCell = document.createElement('td');
      warningCell.className = 'num';
      warningCell.textContent = file.unreadable ? '—' : String(file.warnings);

      row.append(nameCell, errorCell, warningCell);
      el.rows.append(row);
    });
  }

  function render(payload) {
    if (!payload || payload.directory === undefined) {
      renderStatus('idle');
      el.folder.textContent = 'No folder watched. Choose one to start monitoring.';
      el.results.hidden = true;
      el.empty.hidden = true;
      el.rescan.disabled = true;
      el.stop.disabled = true;
      return;
    }

    renderStatus(payload.tray);
    el.rescan.disabled = false;
    el.stop.disabled = false;

    const note = payload.recursive ? '' : ' (subfolders not watched on this platform)';
    el.folder.textContent = `${payload.directory}${note}`;

    const files = payload.snapshot?.files ?? [];
    el.results.hidden = files.length === 0;
    el.empty.hidden = files.length > 0;
    renderRows(files);
  }

  function showFailure(message) {
    el.failure.textContent = message;
    el.failure.hidden = false;
  }

  el.choose.addEventListener('click', async () => {
    el.failure.hidden = true;
    render(await api.chooseFolder());
  });

  el.rescan.addEventListener('click', async () => {
    renderStatus('scanning');
    render(await api.rescan());
  });

  el.stop.addEventListener('click', async () => {
    await api.stopWatching();
    render(undefined);
  });

  api.onStatusChanged(render);
  api.onWatchFailed(showFailure);

  // The window may be opened long after a scan ran, so ask for the current
  // state rather than waiting for the next push.
  void api.currentStatus().then(render);
})();
