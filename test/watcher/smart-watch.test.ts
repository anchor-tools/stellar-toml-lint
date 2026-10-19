import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createSmartWatchScheduler,
  createSourceChangeDetector,
} from '../../src/watcher/smart-watch.js';

describe('smart watch scheduler', () => {
  afterEach(() => vi.useRealTimers());

  it('ignores filesystem events whose source bytes have not changed', () => {
    const hasChanged = createSourceChangeDetector();
    expect(hasChanged('stellar.toml', 'VERSION = "2.0.0"')).toBe(true);
    expect(hasChanged('stellar.toml', 'VERSION = "2.0.0"')).toBe(false);
    expect(hasChanged('stellar.toml', 'VERSION = "3.0.0"')).toBe(true);
  });

  it('debounces offline checks and runs network checks after three seconds idle', async () => {
    vi.useFakeTimers();
    const runOffline = vi.fn(async () => undefined);
    const runNetwork = vi.fn(async () => undefined);
    const scheduler = createSmartWatchScheduler({ runOffline, runNetwork });

    scheduler.notifyChange('stellar.toml');
    await vi.advanceTimersByTimeAsync(200);
    scheduler.notifyChange('stellar.toml');
    await vi.advanceTimersByTimeAsync(299);
    expect(runOffline).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(runOffline).toHaveBeenCalledWith(['stellar.toml']);
    expect(runNetwork).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2_500);
    expect(runNetwork).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(300);
    expect(runNetwork).toHaveBeenCalledWith(['stellar.toml']);
    scheduler.close();
  });

  it('coalesces changed files and cancels pending work when closed', async () => {
    vi.useFakeTimers();
    const runOffline = vi.fn(async () => undefined);
    const runNetwork = vi.fn(async () => undefined);
    const scheduler = createSmartWatchScheduler({ runOffline, runNetwork });

    scheduler.notifyChange('a.toml');
    scheduler.notifyChange('b.toml');
    await vi.advanceTimersByTimeAsync(300);
    expect(runOffline).toHaveBeenCalledWith(['a.toml', 'b.toml']);
    scheduler.notifyChange('a.toml');
    scheduler.close();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(runNetwork).not.toHaveBeenCalled();
  });
});