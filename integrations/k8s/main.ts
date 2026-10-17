/**
 * StellarInfoFile operator entrypoint.
 *
 * Runs the watch loop, reconciles on every event, and re-lists on a periodic
 * resync so a dropped watch cannot leave a resource permanently stale.
 *
 *   node dist/main.js            # uses KUBECONFIG / ~/.kube/config
 *   # in-cluster it picks up the service account automatically.
 */

import { fileURLToPath } from 'node:url';

import { reconcile, type ReconcileOutcome, type StellarInfoFile } from './controller.js';
import {
  createKubeApi,
  listStellarInfoFiles,
  loadKubeConfig,
  watchStellarInfoFiles,
} from './client.js';
import { formatOutcome } from './log.js';

/** Resync cadence: list everything and reconcile, healing missed events. */
const RESYNC_INTERVAL_MS = 5 * 60 * 1000;

/** Watch reconnect backoff: doubles up to this cap. */
const MAX_RECONNECT_DELAY_MS = 60_000;

export interface OperatorOptions {
  /** Injectable for tests; defaults to a 5-minute resync. */
  resyncIntervalMs?: number;
  /** Sink for structured log lines; defaults to stdout. */
  log?: (line: string) => void;
}

/**
 * One reconcile pass, with its outcome logged. Errors are contained: one
 * broken resource must not stop the operator from serving the others.
 */
async function reconcileOne(
  api: ReturnType<typeof createKubeApi>,
  cr: StellarInfoFile,
  log: (line: string) => void,
): Promise<void> {
  try {
    const outcome: ReconcileOutcome = await reconcile(api, cr);
    log(formatOutcome(outcome));
  } catch (err) {
    log(
      JSON.stringify({
        level: 'error',
        resource: `${cr.metadata?.namespace ?? '?'}/${cr.metadata?.name ?? '?'}`,
        error: err instanceof Error ? err.message : String(err),
      }),
    );
  }
}

/**
 * Starts the operator. Resolves with a stop function.
 */
export async function startOperator(options: OperatorOptions = {}): Promise<() => Promise<void>> {
  const log = options.log ?? ((line: string) => process.stdout.write(`${line}\n`));
  const resyncIntervalMs = options.resyncIntervalMs ?? RESYNC_INTERVAL_MS;

  const kc = loadKubeConfig();
  const api = createKubeApi(kc);
  let stopped = false;
  let stopWatch: (() => void) | undefined;

  const resync = async (): Promise<void> => {
    if (stopped) return;
    try {
      const items = await listStellarInfoFiles(kc);
      log(
        JSON.stringify({
          level: 'info',
          event: 'resync',
          resources: items.length,
        }),
      );
      for (const cr of items) {
        if (stopped) return;
        await reconcileOne(api, cr, log);
      }
    } catch (err) {
      log(
        JSON.stringify({
          level: 'error',
          event: 'resync-failed',
          error: err instanceof Error ? err.message : String(err),
        }),
      );
    }
  };

  const timer = setInterval(() => void resync(), resyncIntervalMs);
  // Do not hold the process open just for the resync timer.
  timer.unref?.();

  // The watch reconnects itself with capped exponential backoff until stopped.
  const runWatch = async (): Promise<void> => {
    let delay = 1_000;
    while (!stopped) {
      try {
        stopWatch = await watchStellarInfoFiles(kc, (type, cr) => {
          log(
            JSON.stringify({
              level: 'info',
              event: type.toLowerCase(),
              resource: `${cr.metadata.namespace}/${cr.metadata.name}`,
            }),
          );
          if (type !== 'DELETED') void reconcileOne(api, cr, log);
        });
        delay = 1_000; // a clean watch run resets the backoff
      } catch (err) {
        log(
          JSON.stringify({
            level: 'error',
            event: 'watch-failed',
            error: err instanceof Error ? err.message : String(err),
          }),
        );
      }
      if (stopped) return;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, MAX_RECONNECT_DELAY_MS);
    }
  };

  // Initial list so resources that predate the operator are covered.
  await resync();
  void runWatch();

  return async () => {
    stopped = true;
    clearInterval(timer);
    stopWatch?.();
  };
}

// Only self-start when executed directly (`node dist/main.js`), not when
// imported by tests.
const isDirectRun =
  process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isDirectRun) {
  startOperator().then(
    (stop) => {
      const shutdown = (): void => {
        void stop().then(() => process.exit(0));
      };
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
    },
    (err: unknown) => {
      process.stderr.write(`stellar-toml-lint: operator failed to start: ${String(err)}\n`);
      process.exit(1);
    },
  );
}
