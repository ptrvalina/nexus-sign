// Every state change is an event row. The console's timeline and audit log
// are read from these rows only; nothing is derived in the browser.
import { now } from './db.mjs';

export function recordEvent(db, { type, source, customerId = null, transactionId = null, detail = {} }) {
  db.prepare('INSERT INTO events (at, type, source, customer_id, transaction_id, detail) VALUES (?, ?, ?, ?, ?, ?)')
    .run(now(), type, source, customerId, transactionId, JSON.stringify(detail));
}

export function transactionEvents(db, transactionId) {
  return db.prepare('SELECT * FROM events WHERE transaction_id = ? ORDER BY id').all(transactionId).map(parseEvent);
}

export function recentEvents(db, { limit = 200, customerId, type } = {}) {
  const where = [];
  const args = [];
  if (customerId) { where.push('customer_id = ?'); args.push(customerId); }
  if (type) { where.push('type = ?'); args.push(type); }
  const sql = `SELECT * FROM events ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`;
  return db.prepare(sql).all(...args, limit).map(parseEvent);
}

function parseEvent(row) {
  return { ...row, detail: JSON.parse(row.detail) };
}

/** The steps the console shows for a transaction, in order, with the event that completed each. */
export const TIMELINE = [
  ['TRANSACTION_CREATED', 'Транзакция создана'],
  ['CHALLENGE_GENERATED', 'Запрос подтверждения создан (Auth Core)'],
  ['CHALLENGE_DELIVERED', 'Запрос доставлен на устройство'],
  ['CUSTOMER_CONFIRMED', 'Клиент подтвердил'],
  ['EVIDENCE_RECEIVED', 'Доказательство получено от Auth Core'],
  ['SIGNATURE_VERIFIED', 'Подпись и печать HSM проверены банком'],
  ['BINDING_VERIFIED', 'Условия совпадают с подписанными'],
  ['AUTHORIZATION_DECISION', 'Решение банка'],
  ['LEDGER_EXECUTED', 'Проводка в демо-регистре'],
  ['RECEIPT_GENERATED', 'Квитанция сформирована'],
  ['EVIDENCE_RECORDED', 'Доказательство сохранено'],
];
