import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './support/load-ts.mjs';

const errors = loadTs('services/errors.ts');
class Named extends Error {}
const { errorHandler } = loadTs('middleware/errorHandler.ts', {
  stubs: {
    '../services/errors': errors,
    '../services/nexusIdentityService': { DuplicateBankCustomerError: Named, NexusIdentityNotFoundError: Named },
    '../services/authorizationRecord': { AuthorizationNotFoundError: Named },
    '../services/recoveryService': { InvalidRecoveryProofError: Named, RecoveryNotConfiguredError: Named, RecoverySessionNotFoundError: Named },
    '../services/credentialService': { CredentialNotFoundError: Named },
  },
});

function respond(error) {
  const logged = [];
  const out = {};
  const res = { status(code) { out.status = code; return this; }, json(body) { out.body = body; } };
  errorHandler({ error: (...args) => logged.push(args) })(error, { path: '/x', method: 'POST' }, res, () => {});
  return { ...out, logged };
}

test('domain errors map to their HTTP status', () => {
  assert.equal(respond(new errors.ValidationError('bad')).status, 400);
  assert.equal(respond(new errors.UnauthorizedError('who')).status, 401);
  assert.equal(respond(new errors.ForbiddenError('no')).status, 403);
  assert.equal(respond(new errors.NotFoundError('none')).status, 404);
  assert.equal(respond(new errors.ConflictError('state')).status, 409);
  assert.equal(respond(new errors.GoneError('late')).status, 410);
});

test('body parser rejections keep their 4xx status and are not logged as errors', () => {
  const tooLarge = Object.assign(new Error('request entity too large'), { type: 'entity.too.large', status: 413 });
  const malformed = Object.assign(new Error('Unexpected token'), { type: 'entity.parse.failed', status: 400 });
  assert.deepEqual([respond(tooLarge).status, respond(tooLarge).body.error], [413, 'Request body is too large']);
  assert.deepEqual([respond(malformed).status, respond(malformed).logged.length], [400, 0]);
});

test('anything else is a 500 without details', () => {
  const result = respond(new Error('Invalid input syntax for type uuid: SELECT ...'));
  assert.equal(result.status, 500);
  assert.deepEqual(result.body, { error: 'Internal server error' });
  assert.equal(result.logged.length, 1);
});
