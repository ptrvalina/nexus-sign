// The bank app's API (/app/v1/*), served on the device port. Every answer is
// read from the bank's database; the app shows a payment as done only when
// the transaction state here is EXECUTED.
import { randomUUID } from 'node:crypto';
import { formatMinor } from './fees.mjs';
import { recordEvent } from './events.mjs';
import { BankError, validIban } from './payments.mjs';
import { now } from './db.mjs';
import { publicCustomer } from './customers.mjs';
import { readBody, sendJson } from './http.mjs';

export function createAppApi({ db, bank, customers, payments }) {
  const accountView = (a) => ({ id: a.id, name: a.name, iban: a.iban, currency: a.currency, balanceMinor: a.balance_minor, balance: formatMinor(a.balance_minor, a.currency) });
  const cardView = (c) => ({ id: c.id, accountId: c.account_id, last4: c.last4, brand: c.brand, expires: c.expires, status: c.status });

  function transactionView(t) {
    const receipt = db.prepare('SELECT id FROM receipts WHERE transaction_id = ?').get(t.id);
    return {
      id: t.id, reference: t.reference, kind: t.kind, state: t.state, sourceAccountId: t.source_account_id,
      beneficiaryName: t.beneficiary_name, beneficiaryIban: t.beneficiary_iban,
      amountMinor: t.amount_minor, feeMinor: t.fee_minor, totalMinor: t.amount_minor + t.fee_minor, currency: t.currency,
      amount: formatMinor(t.amount_minor, t.currency), fee: formatMinor(t.fee_minor, t.currency), total: formatMinor(t.amount_minor + t.fee_minor, t.currency),
      description: t.description, authorizationId: t.authorization_id, authorizationExpiresAt: t.authorization_expires_at,
      failureReason: t.failure_reason, receiptId: receipt?.id ?? null, createdAt: t.created_at, updatedAt: t.updated_at,
    };
  }

  function ownedTransaction(customer, id) {
    const t = payments.getTransaction(id);
    if (!t || t.customer_id !== customer.id) throw new BankError(404, 'NOT_FOUND', 'Операция не найдена');
    return t;
  }

  /** History of an account from its ledger entries (incoming and outgoing). */
  function history(customer, accountId) {
    const account = db.prepare('SELECT * FROM accounts WHERE id = ? AND customer_id = ?').get(accountId, customer.id);
    if (!account) throw new BankError(404, 'ACCOUNT_NOT_FOUND', 'Счёт не найден');
    return db.prepare(`SELECT e.amount_minor, e.currency, e.memo, j.created_at, j.kind, t.id AS transaction_id, t.reference, t.beneficiary_name
      FROM ledger_entries e JOIN journals j ON j.id = e.journal_id LEFT JOIN transactions t ON t.id = j.transaction_id
      WHERE e.account_id = ? ORDER BY e.id DESC LIMIT 200`).all(account.id)
      .map((r) => ({ ...r, amount: formatMinor(r.amount_minor, r.currency) }));
  }

  const routes = [
    ['POST', /^\/app\/v1\/session$/, false, async (req) => {
      const body = await readBody(req);
      return customers.login(body.login, body.password);
    }],
    ['DELETE', /^\/app\/v1\/session$/, true, (req) => { customers.logout(req.headers.authorization); return { ok: true }; }],
    ['GET', /^\/app\/v1\/bank$/, false, () => ({ branding: bank.branding, currency: bank.currency, support: bank.support })],
    ['GET', /^\/app\/v1\/profile$/, true, (req, c) => publicCustomer(c)],
    ['PATCH', /^\/app\/v1\/settings$/, true, async (req, c) => {
      const body = await readBody(req);
      const settings = { ...JSON.parse(c.settings) };
      for (const key of ['language', 'notifications', 'displayName']) if (key in body) settings[key] = body[key];
      db.prepare('UPDATE customers SET settings = ? WHERE id = ?').run(JSON.stringify(settings), c.id);
      return publicCustomer(customers.byId(c.id));
    }],
    ['POST', /^\/app\/v1\/enrolment\/bootstrap-token$/, true, (req, c) => customers.bootstrapToken(c)],
    ['POST', /^\/app\/v1\/enrolment\/complete$/, true, async (req, c) => {
      const { credentialId } = await readBody(req);
      if (typeof credentialId !== 'string' || !/^[0-9a-f-]{36}$/i.test(credentialId)) throw new BankError(400, 'INVALID', 'credentialId required');
      return customers.completeEnrolment(c, credentialId);
    }],
    ['GET', /^\/app\/v1\/accounts$/, true, (req, c) => db.prepare('SELECT * FROM accounts WHERE customer_id = ? ORDER BY created_at, id').all(c.id).map(accountView)],
    ['GET', /^\/app\/v1\/accounts\/([^/]+)\/history$/, true, (req, c, m) => history(c, m[1])],
    ['GET', /^\/app\/v1\/cards$/, true, (req, c) => db.prepare('SELECT k.* FROM cards k JOIN accounts a ON a.id = k.account_id WHERE a.customer_id = ?').all(c.id).map(cardView)],
    ['POST', /^\/app\/v1\/cards\/([^/]+)\/(freeze|unfreeze|block)$/, true, (req, c, m) => {
      const card = db.prepare('SELECT k.* FROM cards k JOIN accounts a ON a.id = k.account_id WHERE k.id = ? AND a.customer_id = ?').get(m[1], c.id);
      if (!card) throw new BankError(404, 'NOT_FOUND', 'Карта не найдена');
      if (card.status === 'BLOCKED') throw new BankError(409, 'CARD_BLOCKED', 'Карта заблокирована');
      const status = { freeze: 'FROZEN', unfreeze: 'ACTIVE', block: 'BLOCKED' }[m[2]];
      db.prepare('UPDATE cards SET status = ? WHERE id = ?').run(status, card.id);
      recordEvent(db, { type: 'CARD_STATUS_CHANGED', source: 'DEVICE', customerId: c.id, detail: { cardId: card.id, status } });
      return cardView({ ...card, status });
    }],
    ['GET', /^\/app\/v1\/favorites$/, true, (req, c) => db.prepare('SELECT id, name, iban FROM favorites WHERE customer_id = ? ORDER BY created_at').all(c.id)],
    ['POST', /^\/app\/v1\/favorites$/, true, async (req, c) => {
      const body = await readBody(req);
      const iban = String(body.iban ?? '').replace(/\s+/g, '').toUpperCase();
      const name = String(body.name ?? '').trim().slice(0, 140);
      if (!name || !validIban(iban)) throw new BankError(400, 'INVALID', 'Укажите название и IBAN');
      const id = randomUUID();
      db.prepare('INSERT INTO favorites (id, customer_id, name, iban, created_at) VALUES (?, ?, ?, ?, ?)').run(id, c.id, name, iban, now());
      return { id, name, iban };
    }],
    ['DELETE', /^\/app\/v1\/favorites\/([^/]+)$/, true, (req, c, m) => {
      db.prepare('DELETE FROM favorites WHERE id = ? AND customer_id = ?').run(m[1], c.id);
      return { ok: true };
    }],
    ['GET', /^\/app\/v1\/products$/, true, () => bank.products],
    ['GET', /^\/app\/v1\/support$/, false, () => bank.support],
    ['GET', /^\/app\/v1\/notifications$/, true, (req, c) => db.prepare("SELECT id, transaction_id AS transactionId, kind, title, body, state, created_at AS createdAt FROM notifications WHERE customer_id = ? AND state <> 'SUPPRESSED' ORDER BY created_at DESC LIMIT 100").all(c.id)],
    ['POST', /^\/app\/v1\/notifications\/([^/]+)\/read$/, true, (req, c, m) => {
      db.prepare("UPDATE notifications SET state = 'READ' WHERE id = ? AND customer_id = ? AND state <> 'SUPPRESSED'").run(m[1], c.id);
      return { ok: true };
    }],
    ['POST', /^\/app\/v1\/transactions\/quote$/, true, async (req, c) => payments.quote(c, await readBody(req))],
    ['POST', /^\/app\/v1\/transactions$/, true, async (req, c) => {
      const { transaction, replay } = await payments.create(c, await readBody(req), req.headers['idempotency-key']);
      return [replay ? 200 : 201, transactionView(transaction)];
    }],
    ['GET', /^\/app\/v1\/transactions$/, true, (req, c) => db.prepare('SELECT * FROM transactions WHERE customer_id = ? ORDER BY created_at DESC LIMIT 100').all(c.id).map(transactionView)],
    ['GET', /^\/app\/v1\/transactions\/([^/]+)$/, true, async (req, c, m) => {
      ownedTransaction(c, m[1]);
      return transactionView(await payments.reconcile(m[1]));
    }],
    ['POST', /^\/app\/v1\/transactions\/([^/]+)\/cancel$/, true, async (req, c, m) => transactionView(await payments.cancel(c, m[1], 'CUSTOMER_REQUEST', 'DEVICE'))],
    ['GET', /^\/app\/v1\/transactions\/([^/]+)\/receipt$/, true, (req, c, m) => {
      ownedTransaction(c, m[1]);
      const receipt = db.prepare('SELECT body FROM receipts WHERE transaction_id = ?').get(m[1]);
      if (!receipt) throw new BankError(404, 'NO_RECEIPT', 'Квитанция появится после исполнения операции');
      return JSON.parse(receipt.body);
    }],
    ['GET', /^\/app\/v1\/transactions\/([^/]+)\/offline-challenge$/, true, (req, c, m) => payments.offlineChallenge(c, m[1])],
    // The confirmation waiting for this customer (the app polls; push in milestone 4).
    ['GET', /^\/app\/v1\/pending-authorization$/, true, (req, c) => {
      const t = payments.pendingFor(c);
      return t ? { transaction: transactionView(t) } : { transaction: null };
    }],
  ];

  /** Answers true when the request was an app API request. */
  return async function handle(req, res, pathname) {
    if (!pathname.startsWith('/app/')) return false;
    for (const [method, pattern, authenticated, fn] of routes) {
      const match = pattern.exec(pathname);
      if (!match || req.method !== method) continue;
      let customer = null;
      if (authenticated) {
        customer = customers.fromToken(req.headers.authorization);
        if (!customer) throw new BankError(401, 'UNAUTHENTICATED', 'Войдите в приложение');
      }
      const result = await fn(req, customer, match);
      if (Array.isArray(result) && typeof result[0] === 'number') sendJson(res, result[0], result[1]);
      else sendJson(res, 200, result);
      return true;
    }
    throw new BankError(404, 'NOT_FOUND', 'Not found');
  };
}
