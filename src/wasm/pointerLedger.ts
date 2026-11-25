/**
 * A ledger for host-to-guest pointers handed out during one session.
 *
 * Guest memory is not garbage collected: a host that allocates inside the
 * module and never calls `free` keeps the page alive, and the leak shows up as
 * a dangling pointer rather than as a JS object anyone can find. The ledger
 * records allocations and frees so the heap profiler can report exactly which
 * labels outlived the session, in bytes.
 */
export interface DanglingPointer {
  pointer: number;
  bytes: number;
  label: string;
}

export class PointerLedger {
  private readonly live = new Map<number, { bytes: number; label: string }>();

  allocate(pointer: number, bytes: number, label = `0x${pointer.toString(16)}`): void {
    this.live.set(pointer, { bytes, label });
  }

  free(pointer: number): boolean {
    return this.live.delete(pointer);
  }

  get size(): number {
    return this.live.size;
  }

  dangling(): DanglingPointer[] {
    return [...this.live.entries()].map(([pointer, entry]) => ({
      pointer,
      bytes: entry.bytes,
      label: entry.label,
    }));
  }

  reset(): void {
    this.live.clear();
  }
}
