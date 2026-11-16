import type { NextFunction, Request, Response } from 'express';
import type { Logger } from 'pino';
import { ZodError } from 'zod';
import { DuplicateBankCustomerError, NexusIdentityNotFoundError } from '../services/nexusIdentityService';
import { AuthorizationNotFoundError } from '../services/authorizationRecord';
import { InvalidRecoveryProofError, RecoveryNotConfiguredError, RecoverySessionNotFoundError } from '../services/recoveryService';
import { CredentialNotFoundError } from '../services/credentialService';
import { CredentialIntegrityError } from '../services/credentialIntegrity';
import { ConflictError, ForbiddenError, GoneError, NotFoundError, UnauthorizedError, UnprocessableError, ValidationError } from '../services/errors';

type ErrorClass = abstract new (...args: never[]) => Error;

const STATUS_BY_ERROR: ReadonlyArray<readonly [ErrorClass, number]> = [
  [ValidationError, 400],
  [UnauthorizedError, 401],
  [InvalidRecoveryProofError, 401],
  [ForbiddenError, 403],
  [CredentialIntegrityError, 403],
  [NotFoundError, 404],
  [NexusIdentityNotFoundError, 404],
  [AuthorizationNotFoundError, 404],
  [CredentialNotFoundError, 404],
  [RecoverySessionNotFoundError, 404],
  [ConflictError, 409],
  [DuplicateBankCustomerError, 409],
  [RecoveryNotConfiguredError, 409],
  [GoneError, 410],
  [UnprocessableError, 422],
];

/**
 * Maps domain errors to HTTP status codes. Anything unrecognized is logged
 * and returned as a generic 500, so stack traces and SQL never reach the
 * caller. Route handlers pass errors on to this middleware.
 */
export function errorHandler(logger: Logger) {
  return (error: unknown, req: Request, res: Response, _next: NextFunction): void => {
    if (error instanceof ZodError) {
      res.status(400).json({
        error: 'Invalid request',
        details: error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
      });
      return;
    }

    const mapped = STATUS_BY_ERROR.find(([type]) => error instanceof type);
    if (mapped && error instanceof Error) {
      const code = error instanceof ConflictError || error instanceof UnprocessableError ? error.code : undefined;
      res.status(mapped[1]).json({ error: error.message, ...(code ? { code } : {}) });
      return;
    }

    // Body parser rejections (malformed JSON, body too large) carry their own
    // 4xx status and a fixed message.
    const parserStatus = bodyParserStatus(error);
    if (parserStatus) {
      res.status(parserStatus).json({ error: parserStatus === 413 ? 'Request body is too large' : 'Malformed request body' });
      return;
    }

    logger.error({ err: error, path: req.path, method: req.method }, 'Unhandled error');
    res.status(500).json({ error: 'Internal server error' });
  };
}

function bodyParserStatus(error: unknown): number | null {
  if (typeof error !== 'object' || error === null || !('type' in error) || !('status' in error)) return null;
  const { type, status } = error as { type: unknown; status: unknown };
  if (typeof type !== 'string' || !type.startsWith('entity.') && type !== 'encoding.unsupported' && type !== 'charset.unsupported') return null;
  return typeof status === 'number' && status >= 400 && status < 500 ? status : null;
}
