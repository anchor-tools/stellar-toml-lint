/**
 * Error types shared by the WebAssembly sandbox tooling.
 *
 * Each failure carries a machine-readable `code` so the CLI can map it to the
 * right exit status and a structured reporter can name the boundary that held
 * without parsing prose.
 */
export type SandboxErrorCode = 'format' | 'import' | 'capability' | 'fuel' | 'trap' | 'memory';

export class FuelMeterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FuelMeterError';
  }
}

/** Raised when a sandboxed module leaves the capabilities it was granted. */
export class WasiSandboxError extends Error {
  constructor(
    readonly code: SandboxErrorCode,
    message: string,
    readonly syscall?: string,
  ) {
    super(message);
    this.name = 'WasiSandboxError';
  }
}
