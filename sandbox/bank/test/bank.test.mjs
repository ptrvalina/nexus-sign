// Unit tests of the sandbox bank: ledger, idempotency, the bank's decision
// (evidence, binding) and the state machine. Auth Core is replaced by the
// test-only stand-in in support/fakeAuthCore.mjs; tests/e2e.test.mjs runs the
// same flows against the real Auth Core.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { openDatabase } from '../src/db.mjs';
import { seedIfEmpty } from '../src/seed.mjs';
import { createFaults } from '../src/faults.mjs';
import { createPayments } from '../src/payments.mjs';
import { createCustomers } from '../src/customers.mjs';
import { loadConfig } from '../src/config.mjs';
import { fakeAuthCore } from './support/fakeAuthCore.mjs';

const bankConfig = JSON.parse(readFileSync(new URL('../../config/bank.json', import.meta.url), 'utf8'));

async function setup({ faultInjection = true } = {}) {
  const db = openDatabase(':memory:');
  seedIfEmpty(db, bankConfig, 'test-password');
  const authCore = fakeAuthCore();
  const faults = createFaults(faultInjection);
  const payments = createPayments({ db, bank: bankConfig, authCore, faults });
  const customers = createCustomers({ db, authCore });
  let anna = customers.byId('cust-anna');
  anna = await customers.ensureIdentity(anna);
  anna = { ...anna, ...(await customers.completeEnrolment(anna, authCore.deviceOf(anna.nexus_id).credentialId)) };
  anna = customers.byId('cust-anna');
  const balance = (id) => db.prepare('SELECT balance_minor FROM accounts WHERE id = ?').get(id).balance_minor;
  const journals = (id) => db.prepare('SELECT COUNT(*) AS n FROM journals WHERE transaction_id = ?').get(id).n;
  const types = (id) => db.prepare('SELECT type FROM events WHERE transaction_id = ? ORDER BY id').all(id).map((r) => r.type);
  const ledgerOk = () => {
    const total = db.prepare('SELECT COALESCE(SUM(amount_minor), 0) AS t FROM ledger_entries').get().t;
    const off = db.prepare('SELECT COUNT(*) AS n FROM accounts a WHERE balance_minor <> (SELECT COALESCE(SUM(amount_minor), 0) FROM ledger_entries e WHERE e.account_id = a.id)').get().n;
    return total === 0 && off === 0;
  };
  return { db, authCore, faults, payments, customers, anna, balance, journals, types, ledgerOk };
}

const external = { sourceAccountId: 'acc-anna-main', beneficiaryName: 'Ион Попеску', beneficiaryIban: 'MD28AG000000022589630417', amountMinor: 50000 };

test('opening balances are ledger entries; the ledger sums to zero', async () => {
  const { balance, ledgerOk } = await setup();
  assert.equal(balance('acc-anna-main'), 1250000);
  assert.ok(ledgerOk());
});

test('a confirmed payment is executed once: verified evidence, matching terms, ledger, receipt, commit reported', async () => {
  const { payments, authCore, anna, balance, journals, types, ledgerOk, db } = await setup();
  const { transaction } = await payments.create(anna, external, randomUUID());
  assert.equal(transaction.state, 'AUTHORIZATION_PENDING');
  assert.equal(transaction.fee_minor, 100, 'external payment: 0.1 % with a 1.00 minimum');
  assert.equal(payments.pendingFor(anna).id, transaction.id);
  authCore.confirm(transaction.authorization_id);
  const done = await payments.reconcile(transaction.id);
  assert.equal(done.state, 'EXECUTED', done.failure_reason);
  assert.equal(done.commit_reported, 'COMMITTED');
  assert.equal(balance('acc-anna-main'), 1250000 - 50000 - 100);
  assert.equal(balance('BANK-FEES'), 100);
  assert.equal(balance('BANK-CLEARING'), 50000);
  assert.equal(journals(transaction.id), 1);
  assert.ok(ledgerOk());
  assert.ok(db.prepare('SELECT 1 FROM receipts WHERE transaction_id = ?').get(transaction.id));
  assert.deepEqual(types(transaction.id).filter((t) => ['TRANSACTION_CREATED', 'CHALLENGE_GENERATED', 'CHALLENGE_DELIVERED', 'CUSTOMER_CONFIRMED', 'EVIDENCE_RECEIVED', 'SIGNATURE_VERIFIED', 'BINDING_VERIFIED', 'AUTHORIZATION_DECISION', 'LEDGER_EXECUTED', 'RECEIPT_GENERATED', 'EVIDENCE_RECORDED'].includes(t)),
    ['TRANSACTION_CREATED', 'CHALLENGE_GENERATED', 'CHALLENGE_DELIVERED', 'CUSTOMER_CONFIRMED', 'EVIDENCE_RECEIVED', 'SIGNATURE_VERIFIED', 'BINDING_VERIFIED', 'AUTHORIZATION_DECISION', 'LEDGER_EXECUTED', 'RECEIPT_GENERATED', 'EVIDENCE_RECORDED']);
  // Reconciling again changes nothing.
  await payments.reconcile(transaction.id);
  assert.equal(journals(transaction.id), 1);
  assert.deepEqual(authCore.calls.filter((c) => c[0] === 'commitRequest').length, 1);
});

test('a payment to an account of this bank is booked internally, without commission', async () => {
  const { payments, authCore, anna, balance } = await setup();
  const { transaction } = await payments.create(anna, { sourceAccountId: 'acc-anna-main', beneficiaryName: 'x', beneficiaryIban: 'MD90VI000022241100000001', amountMinor: 1000 }, randomUUID());
  assert.equal(transaction.kind, 'INTERNAL_TRANSFER');
  authCore.confirm(transaction.authorization_id);
  await payments.reconcile(transaction.id);
  assert.equal(balance('acc-piotr-main'), 320000 + 1000);
});

test('idempotency: same key and order returns the same transaction; same key, other order is refused', async () => {
  const { payments, anna, authCore, db } = await setup();
  const key = randomUUID();
  const first = await payments.create(anna, external, key);
  const again = await payments.create(anna, external, key);
  assert.equal(again.transaction.id, first.transaction.id);
  assert.equal(again.replay, true);
  await assert.rejects(payments.create(anna, { ...external, amountMinor: 1 }, key), { code: 'IDEMPOTENCY_KEY_REUSED' });
  assert.equal(authCore.calls.filter((c) => c[0] === 'createAuthorization').length, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM transactions').get().n, 1);
});

test('signed terms that differ from the bank record are refused: no ledger entry', async () => {
  const { payments, anna, authCore, journals, balance } = await setup();
  authCore.alterNextSignedTerms = { amount_minor: '5' };
  const { transaction } = await payments.create(anna, external, randomUUID());
  authCore.confirm(transaction.authorization_id);
  const done = await payments.reconcile(transaction.id);
  assert.equal(done.state, 'FAILED');
  assert.match(done.failure_reason, /BINDING_MISMATCH.*amount_minor/);
  assert.equal(journals(transaction.id), 0);
  assert.equal(balance('acc-anna-main'), 1250000);
});

test('evidence sealed with a key the bank has not pinned is refused', async () => {
  const { payments, anna, authCore, journals } = await setup();
  const first = await payments.create(anna, external, randomUUID());
  authCore.confirm(first.transaction.authorization_id);
  assert.equal((await payments.reconcile(first.transaction.id)).state, 'EXECUTED');
  // Second payment: evidence from another sealing key (a forged seal).
  const { transaction } = await payments.create(anna, external, randomUUID());
  const { fakeAuthCore: other } = await import('./support/fakeAuthCore.mjs');
  const forger = other().maker;
  const device = authCore.deviceOf(anna.nexus_id);
  const evidence = forger.confirm({ ...device, enrolment: forger.device(anna.nexus_id).enrolment }, {
    authorizationId: transaction.authorization_id,
    terms: { transactionReference: transaction.reference, operationType: 'payment', amountMinor: '50000', currency: 'MDL', beneficiary: { name: 'Ион Попеску', iban: 'MD28AG000000022589630417', fee: '1.00 MDL' } },
  });
  authCore.confirm(transaction.authorization_id);
  authCore.replaceEvidence(transaction.authorization_id, { ...evidence, evidencePublicKeys: forger.evidenceKeys });
  const done = await payments.reconcile(transaction.id);
  assert.equal(done.state, 'FAILED');
  assert.match(done.failure_reason, /EVIDENCE_INVALID.*not pinned/);
  assert.equal(journals(transaction.id), 0);
});

test('a tampered copy of the evidence (sandbox fault) is refused', async () => {
  const { payments, anna, authCore, faults, journals } = await setup();
  const { transaction } = await payments.create(anna, external, randomUUID());
  faults.tamperEvidenceOf(transaction.id);
  authCore.confirm(transaction.authorization_id);
  const done = await payments.reconcile(transaction.id);
  assert.equal(done.state, 'FAILED');
  assert.equal(journals(transaction.id), 0);
});

test('confirmed=false from Auth Core is never executed', async () => {
  const { payments, anna, authCore, journals } = await setup();
  const { transaction } = await payments.create(anna, external, randomUUID());
  authCore.setState(transaction.authorization_id, 'VERIFIED', { confirmed: false });
  const done = await payments.reconcile(transaction.id);
  assert.equal(done.state, 'FAILED');
  assert.equal(journals(transaction.id), 0);
});

test('offline provisional is not executed; rejected, expired and cancelled end without ledger entries', async () => {
  const { payments, anna, authCore, journals } = await setup();
  const make = async () => (await payments.create(anna, external, randomUUID())).transaction;
  const p = await make();
  authCore.setState(p.authorization_id, 'OFFLINE_PROVISIONAL');
  assert.equal((await payments.reconcile(p.id)).state, 'OFFLINE_PROVISIONAL');
  assert.equal(journals(p.id), 0);
  const r = await make();
  authCore.setState(r.authorization_id, 'REJECTED');
  assert.equal((await payments.reconcile(r.id)).state, 'REJECTED');
  const x = await make();
  authCore.setState(x.authorization_id, 'EXPIRED');
  assert.equal((await payments.reconcile(x.id)).state, 'EXPIRED');
  const c = await make();
  assert.equal((await payments.cancel(anna, c.id)).state, 'CANCELLED');
  await assert.rejects(payments.cancel(anna, c.id), { code: 'NOT_CANCELLABLE' });
  for (const t of [r, x, c]) assert.equal(journals(t.id), 0);
});

test('orders are validated: funds, own account, IBAN, amount, limit', async () => {
  const { payments, anna } = await setup();
  await assert.rejects(payments.create(anna, { ...external, amountMinor: 99_000_000 }, randomUUID()), { code: 'LIMIT_EXCEEDED' });
  await assert.rejects(payments.create(anna, { ...external, amountMinor: 4_999_999 }, randomUUID()), { code: 'INSUFFICIENT_FUNDS' });
  await assert.rejects(payments.create(anna, { ...external, sourceAccountId: 'acc-piotr-main' }, randomUUID()), { code: 'ACCOUNT_NOT_FOUND' });
  await assert.rejects(payments.create(anna, { ...external, beneficiaryIban: 'nonsense' }, randomUUID()), { code: 'INVALID_IBAN' });
  await assert.rejects(payments.create(anna, { ...external, beneficiaryIban: 'MD29AG000000022589630417' }, randomUUID()), { code: 'INVALID_IBAN' }, 'wrong check digits');
  await assert.rejects(payments.create(anna, { ...external, amountMinor: -5 }, randomUUID()), { code: 'INVALID_AMOUNT' });
  await assert.rejects(payments.create(anna, external, undefined), { code: 'IDEMPOTENCY_KEY_REQUIRED' });
});

test('a suppressed notification (sandbox fault) is not delivered to the app', async () => {
  const { payments, anna, faults, db } = await setup();
  const { transaction } = await payments.create(anna, external, randomUUID());
  faults.suppressNotificationOf(transaction.id);
  db.prepare("UPDATE notifications SET state = 'SUPPRESSED' WHERE transaction_id = ?").run(transaction.id);
  assert.equal(payments.pendingFor(anna), null);
});

test('fault injection is refused when it is not enabled', async () => {
  const { faults } = await setup({ faultInjection: false });
  assert.throws(() => faults.tamperEvidenceOf('x'), /disabled/);
  assert.equal(faults.deviceNetworkDown(), false);
});

test('the audit log is append-only', async () => {
  const { db } = await setup();
  assert.throws(() => db.prepare("UPDATE events SET type = 'X'").run(), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM events').run(), /append-only/);
});

test('app login: wrong password refused, session token works, scenario customer cannot log in', async () => {
  const { customers } = await setup();
  assert.throws(() => customers.login('anna', 'wrong'), { code: 'BAD_CREDENTIALS' });
  const { token } = customers.login('anna', 'test-password');
  assert.equal(customers.fromToken(`Bearer ${token}`).id, 'cust-anna');
  assert.equal(customers.fromToken('Bearer nope'), null);
  assert.throws(() => customers.login('scenario-device', 'test-password'), { code: 'BAD_CREDENTIALS' });
});

test('configuration fails closed outside the sandbox', () => {
  const base = { SANDBOX_ENVIRONMENT: 'sandbox', AUTH_CORE_URL: 'http://auth-core:8080', SANDBOX_DATA_DIR: '/tmp/sbx', BANK_CLIENT_ID: 'b', BANK_CLIENT_SECRET: 's', CONSOLE_PASSWORD: 'p', DEMO_CUSTOMER_PASSWORD: 'd' };
  assert.ok(loadConfig(base));
  assert.throws(() => loadConfig({ ...base, SANDBOX_ENVIRONMENT: undefined }), /SANDBOX_ENVIRONMENT/);
  assert.throws(() => loadConfig({ ...base, AUTH_CORE_URL: 'https://auth.bank.example' }), /not a sandbox host/);
  assert.throws(() => loadConfig({ ...base, BANK_DB_PATH: '/var/lib/bank.sqlite' }), /inside SANDBOX_DATA_DIR/);
  assert.throws(() => loadConfig({ ...base, BANK_CLIENT_SECRET: '' }), /BANK_CLIENT_SECRET/);
});
