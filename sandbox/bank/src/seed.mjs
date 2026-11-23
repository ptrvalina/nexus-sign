// Demo data from config/bank.json, written once into an empty database.
// Opening balances are ledger entries against the bank's capital account,
// so every balance is the sum of its entries from the first day.
import { randomBytes, randomUUID } from 'node:crypto';
import { now, transaction } from './db.mjs';
import { recordEvent } from './events.mjs';
import { hashPassword } from './passwords.mjs';

export function seedIfEmpty(db, bank, customerPassword) {
  if (db.prepare('SELECT COUNT(*) AS n FROM customers').get().n > 0) return false;
  transaction(db, () => {
    const at = now();
    const insertAccount = db.prepare('INSERT INTO accounts (id, customer_id, name, iban, currency, kind, balance_minor, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)');
    for (const account of bank.bankAccounts) insertAccount.run(account.id, null, account.name, account.iban, bank.currency, 'BANK', at);
    const journal = randomUUID();
    db.prepare("INSERT INTO journals (id, transaction_id, kind, created_at) VALUES (?, NULL, 'OPENING', ?)").run(journal, at);
    const entry = db.prepare('INSERT INTO ledger_entries (journal_id, account_id, amount_minor, currency, memo) VALUES (?, ?, ?, ?, ?)');
    const move = db.prepare('UPDATE accounts SET balance_minor = balance_minor + ? WHERE id = ?');
    for (const customer of bank.customers) {
      db.prepare('INSERT INTO customers (id, login, display_name, device_kind, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(customer.id, customer.login, customer.displayName, customer.deviceKind, hashPassword(customerPassword), at);
      for (const account of customer.accounts) {
        insertAccount.run(account.id, customer.id, account.name, account.iban, bank.currency, 'CUSTOMER', at);
        if (account.openingMinor > 0) {
          entry.run(journal, account.id, account.openingMinor, bank.currency, 'Opening balance (test funds)');
          entry.run(journal, 'BANK-EQUITY', -account.openingMinor, bank.currency, `Opening balance of ${account.id}`);
          move.run(account.openingMinor, account.id);
          move.run(-account.openingMinor, 'BANK-EQUITY');
        }
      }
      for (const card of customer.cards) {
        db.prepare("INSERT INTO cards (id, account_id, last4, brand, expires, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
          .run(card.id, card.accountId, card.last4, card.brand, card.expires);
      }
      for (const favorite of customer.favorites) {
        db.prepare('INSERT INTO favorites (id, customer_id, name, iban, created_at) VALUES (?, ?, ?, ?, ?)')
          .run(randomUUID(), customer.id, favorite.name, favorite.iban, at);
      }
    }
    recordEvent(db, { type: 'SANDBOX_SEEDED', source: 'SYSTEM', detail: { customers: bank.customers.length, policyVersion: bank.policy.version } });
  });
  return true;
}

/** IBAN with valid ISO 13616 check digits: country, bank code, 18 random digits (24 characters, the Moldovan length). */
export function newIban(country = 'MD', bankCode = 'VX') {
  const bban = `${bankCode}${Array.from(randomBytes(18), (b) => String(b % 10)).join('')}`;
  const digits = `${bban}${country}00`.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rest = 0;
  for (const d of digits) rest = (rest * 10 + Number(d)) % 97;
  return `${country}${String(98 - rest).padStart(2, '0')}${bban}`;
}

export const newPassword = () => randomBytes(9).toString('base64url');

/**
 * A tester's own demo customer: login, one account with test funds (an
 * opening ledger entry against the bank's capital, like the seed), one card.
 * Returns the password once; only its hash is stored.
 */
export function addCustomer(db, bank, { login, displayName, openingMinor = 1_000_000 }) {
  login = String(login ?? '').trim().toLowerCase();
  displayName = String(displayName ?? '').trim();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(login)) throw new Error('логин: 3–32 символа, латиница, цифры, . _ -');
  if (displayName.length < 2 || displayName.length > 80) throw new Error('укажите имя клиента (2–80 символов)');
  if (!Number.isSafeInteger(openingMinor) || openingMinor < 0 || openingMinor > 100_000_000) throw new Error('начальный остаток: от 0 до 1 000 000.00');
  if (db.prepare('SELECT 1 FROM customers WHERE login = ?').get(login)) throw new Error(`логин ${login} уже занят`);
  const password = newPassword();
  const id = `cust-${randomUUID().slice(0, 8)}`;
  const accountId = `acc-${id.slice(5)}`;
  transaction(db, () => {
    const at = now();
    db.prepare("INSERT INTO customers (id, login, display_name, device_kind, password_hash, created_at) VALUES (?, ?, ?, 'PHONE', ?, ?)")
      .run(id, login, displayName, hashPassword(password), at);
    let iban;
    do { iban = newIban(); } while (db.prepare('SELECT 1 FROM accounts WHERE iban = ?').get(iban));
    db.prepare("INSERT INTO accounts (id, customer_id, name, iban, currency, kind, balance_minor, created_at) VALUES (?, ?, 'Основной счёт', ?, ?, 'CUSTOMER', 0, ?)")
      .run(accountId, id, iban, bank.currency, at);
    if (openingMinor > 0) {
      const journal = randomUUID();
      db.prepare("INSERT INTO journals (id, transaction_id, kind, created_at) VALUES (?, NULL, 'OPENING', ?)").run(journal, at);
      const entry = db.prepare('INSERT INTO ledger_entries (journal_id, account_id, amount_minor, currency, memo) VALUES (?, ?, ?, ?, ?)');
      entry.run(journal, accountId, openingMinor, bank.currency, 'Opening balance (test funds)');
      entry.run(journal, 'BANK-EQUITY', -openingMinor, bank.currency, `Opening balance of ${accountId}`);
      db.prepare('UPDATE accounts SET balance_minor = balance_minor + ? WHERE id = ?').run(openingMinor, accountId);
      db.prepare('UPDATE accounts SET balance_minor = balance_minor - ? WHERE id = ?').run(openingMinor, 'BANK-EQUITY');
    }
    db.prepare("INSERT INTO cards (id, account_id, last4, brand, expires, status) VALUES (?, ?, ?, 'VISA', ?, 'ACTIVE')")
      .run(`card-${id.slice(5)}`, accountId, String(1000 + (randomBytes(2).readUInt16BE() % 9000)), `${String(new Date().getMonth() + 1).padStart(2, '0')}/${String((new Date().getFullYear() + 3) % 100).padStart(2, '0')}`);
    recordEvent(db, { type: 'CUSTOMER_CREATED', source: 'CONSOLE', customerId: id, detail: { login, displayName, openingMinor, iban } });
  });
  return { id, login, displayName, password };
}

/** New password for a customer (the old one stops working; open app sessions end). */
export function resetPassword(db, customerId) {
  const customer = db.prepare('SELECT * FROM customers WHERE id = ?').get(customerId);
  if (!customer || customer.device_kind !== 'PHONE') throw new Error('клиент не найден');
  const password = newPassword();
  transaction(db, () => {
    db.prepare('UPDATE customers SET password_hash = ? WHERE id = ?').run(hashPassword(password), customerId);
    db.prepare('DELETE FROM app_sessions WHERE customer_id = ?').run(customerId);
    recordEvent(db, { type: 'CUSTOMER_PASSWORD_RESET', source: 'CONSOLE', customerId });
  });
  return { login: customer.login, password };
}
