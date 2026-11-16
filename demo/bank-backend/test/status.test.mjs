// The demo bank never presents a provisional offline confirmation,
// an unknown state or a failed lookup as a confirmed payment.
//
//   node --test demo/bank-backend/test/status.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { paymentStatus } from '../status.mjs';

test('only VERIFIED with confirmed: true is confirmed', () => {
  assert.equal(paymentStatus({ state: 'VERIFIED', confirmed: true }).confirmed, true);
  assert.equal(paymentStatus({ state: 'VERIFIED', confirmed: true }).css, 'ok');
  assert.equal(paymentStatus({ state: 'VERIFIED' }).confirmed, false, 'an older Auth Core without the flag is not trusted blindly');
  for (const state of ['OFFLINE_PROVISIONAL', 'OFFLINE_UNSIGNED', 'PENDING_USER', 'REJECTED', 'EXPIRED', 'CANCELLED', 'SOMETHING_NEW']) {
    const s = paymentStatus({ state, confirmed: true });
    assert.equal(s.confirmed, false, state);
    assert.notEqual(s.css, 'ok', state);
  }
  assert.match(paymentStatus({ state: 'OFFLINE_PROVISIONAL', confirmed: false }).label, /не исполнять/);
  assert.match(paymentStatus({ state: 'OFFLINE_UNSIGNED' }).label, /инцидент/);
});

test('a failed or malformed lookup is not confirmed', () => {
  assert.equal(paymentStatus(null, 502).confirmed, false);
  assert.equal(paymentStatus({}, 200).confirmed, false);
  assert.equal(paymentStatus({ state: 'VERIFIED', confirmed: true }, 500).confirmed, false);
});
