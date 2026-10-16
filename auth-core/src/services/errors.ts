/**
 * Domain errors with a defined HTTP status. Anything else reaching the error
 * handler is a 500, which a bank backend treats as retryable, so business-rule
 * rejections must use one of these.
 */

/** The request is well-formed but violates a business rule (400). */
export class ValidationError extends Error {
  constructor(message: string) { super(message); this.name = 'ValidationError'; }
}

/** The caller is not authenticated for this request (401). */
export class UnauthorizedError extends Error {
  constructor(message: string) { super(message); this.name = 'UnauthorizedError'; }
}

/** The caller is authenticated but the action is not permitted (403). */
export class ForbiddenError extends Error {
  constructor(message: string) { super(message); this.name = 'ForbiddenError'; }
}

/** The addressed resource does not exist for this caller (404). */
export class NotFoundError extends Error {
  constructor(message: string) { super(message); this.name = 'NotFoundError'; }
}

/** The request conflicts with current state (409): the resource exists,
 * is in the wrong lifecycle state, or an idempotency key is reused. */
export class ConflictError extends Error {
  /** Machine-readable reason, returned as `code`, when callers must branch on it. */
  constructor(message: string, readonly code?: string) { super(message); this.name = 'ConflictError'; }
}

/** The resource existed but its validity window has passed (410). */
export class GoneError extends Error {
  constructor(message: string) { super(message); this.name = 'GoneError'; }
}
