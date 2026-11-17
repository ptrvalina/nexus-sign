/** Errors of the HSM adapters (PKCS#11 adapter and its worker host). */
export class HsmTimeoutError extends Error {
  constructor(operation: string, timeoutMs: number) {
    super(`HSM ${operation} timed out after ${timeoutMs} ms`);
    this.name = 'HsmTimeoutError';
  }
}

export class HsmBusyError extends Error {
  constructor(limit: number) {
    super(`HSM queue is full (${limit} calls waiting)`);
    this.name = 'HsmBusyError';
  }
}

export class HsmUnavailableError extends Error {
  constructor(reason: string) {
    super(`HSM unavailable: ${reason}`);
    this.name = 'HsmUnavailableError';
  }
}
