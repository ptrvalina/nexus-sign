// Demo data from config/bank.json, written once into an empty database.
// Opening balances are ledger entries against the bank's capital account,
// so every balance is the sum of its entries from the first day.
import { randomUUID } from 'node:crypto';
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
