// Transaction lifecycle of the sandbox bank. One service for the mobile app,
// the console and the scenario engine: all of them create and follow
// transactions through these functions.
//
//   CREATED → AUTHORIZATION_PENDING ─(Auth Core VERIFIED)→ AUTHORIZING → EXECUTED
//                     │        └─(offline code accepted)→ OFFLINE_PROVISIONAL ─┘
//                     └→ REJECTED | EXPIRED | CANCELLED | FAILED
//
// A transaction is EXECUTED only after the bank has fetched the sealed
// evidence from Auth Core, verified the HSM seal and the device signature with
// the independent verifier, compared the signed terms with its own record,
// and posted the ledger entries in one database transaction.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { now, transaction as dbTransaction } from './db.mjs';
import { recordEvent } from './events.mjs';
import { commission, formatMinor } from './fees.mjs';
import { checkBinding, checkEvidence, signedTermsOf } from './evidenceCheck.mjs';
import { evidenceKeyId } from '../../../auth-core/scripts/lib/evidence.mjs';

export class BankError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

const OPEN_STATES = ['AUTHORIZATION_PENDING', 'OFFLINE_PROVISIONAL'];
const IBAN = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$/;

/** ISO 13616 check digits (mod 97), as Auth Core checks a beneficiary IBAN. */
export function validIban(value) {
  if (!IBAN.test(value)) return false;
  const digits = (value.slice(4) + value.slice(0, 4)).replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rest = 0;
  for (const d of digits) rest = (rest * 10 + Number(d)) % 97;
  return rest === 1;
}

export function createPayments({ db, bank, authCore, faults }) {
  const inFlight = new Set();

  const getTransaction = (id) => db.prepare('SELECT * FROM transactions WHERE id = ?').get(id);
  const event = (t, type, source, detail = {}) => recordEvent(db, { type, source, customerId: t.customer_id, transactionId: t.id, detail });

  function setState(t, state, extra = {}) {
    const fields = { state, updated_at: now(), ...extra };
    const sets = Object.keys(fields).map((k) => `${k} = ?`).join(', ');
    db.prepare(`UPDATE transactions SET ${sets} WHERE id = ?`).run(...Object.values(fields), t.id);
    return getTransaction(t.id);
  }

  /** Validates the order; returns the row to insert (not yet stored). */
  function prepare(customer, input) {
    const source = db.prepare("SELECT * FROM accounts WHERE id = ? AND customer_id = ? AND kind = 'CUSTOMER'").get(input.sourceAccountId, customer.id);
    if (!source) throw new BankError(404, 'ACCOUNT_NOT_FOUND', 'Счёт списания не найден');
    const amountMinor = Number(input.amountMinor);
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) throw new BankError(400, 'INVALID_AMOUNT', 'Сумма должна быть положительным целым числом минорных единиц');
    if (amountMinor > bank.policy.limits.maxSingleAmountMinor) throw new BankError(422, 'LIMIT_EXCEEDED', 'Сумма превышает лимит одной операции');
    let kind;
    let destination = null;
    let beneficiaryName;
    let beneficiaryIban;
    if (input.destinationAccountId) {
      destination = db.prepare("SELECT * FROM accounts WHERE id = ? AND kind = 'CUSTOMER'").get(input.destinationAccountId);
      if (!destination) throw new BankError(404, 'ACCOUNT_NOT_FOUND', 'Счёт зачисления не найден');
      if (destination.id === source.id) throw new BankError(400, 'SAME_ACCOUNT', 'Счета списания и зачисления совпадают');
      kind = 'INTERNAL_TRANSFER';
      beneficiaryName = db.prepare('SELECT display_name FROM customers WHERE id = ?').get(destination.customer_id).display_name;
      beneficiaryIban = destination.iban;
    } else {
      beneficiaryIban = String(input.beneficiaryIban ?? '').replace(/\s+/g, '').toUpperCase();
      beneficiaryName = String(input.beneficiaryName ?? '').trim();
      if (!validIban(beneficiaryIban)) throw new BankError(400, 'INVALID_IBAN', 'Неверный IBAN получателя');
      if (beneficiaryName.length < 1 || beneficiaryName.length > 140) throw new BankError(400, 'INVALID_BENEFICIARY', 'Укажите получателя');
      // A payment to an account of this bank is booked internally.
      destination = db.prepare("SELECT * FROM accounts WHERE iban = ? AND kind = 'CUSTOMER'").get(beneficiaryIban) ?? null;
      if (destination?.id === source.id) throw new BankError(400, 'SAME_ACCOUNT', 'Счета списания и зачисления совпадают');
      kind = destination ? 'INTERNAL_TRANSFER' : 'EXTERNAL_PAYMENT';
    }
    const feeMinor = commission(bank.policy, kind, amountMinor);
    if (source.balance_minor < amountMinor + feeMinor) throw new BankError(422, 'INSUFFICIENT_FUNDS', 'Недостаточно средств');
    const description = String(input.description ?? '').slice(0, 140);
    return { source, destination, kind, amountMinor, feeMinor, beneficiaryName, beneficiaryIban, description };
  }

  function requestHash(input) {
    const fields = ['sourceAccountId', 'destinationAccountId', 'beneficiaryIban', 'beneficiaryName', 'amountMinor', 'description'];
    return createHash('sha256').update(JSON.stringify(fields.map((f) => input[f] ?? null))).digest('hex');
  }

  /** Quote shown before the customer submits: amount, commission, total. */
  function quote(customer, input) {
    const p = prepare(customer, input);
    return {
      kind: p.kind, amountMinor: p.amountMinor, feeMinor: p.feeMinor, totalMinor: p.amountMinor + p.feeMinor, currency: p.source.currency,
      beneficiaryName: p.beneficiaryName, beneficiaryIban: p.beneficiaryIban,
    };
  }

  /**
   * Records the transaction and asks Auth Core for the customer's
   * confirmation. Idempotent per (customer, Idempotency-Key): the same key with
   * the same order returns the same transaction; with another order, 409.
   */
  async function create(customer, input, idempotencyKey, { scenarioRunId = null } = {}) {
    if (!idempotencyKey || String(idempotencyKey).length > 128) throw new BankError(400, 'IDEMPOTENCY_KEY_REQUIRED', 'Idempotency-Key is required');
    if (!customer.nexus_id || !customer.credential_id) throw new BankError(409, 'DEVICE_NOT_ENROLLED', 'Подключите телефон к NEXUS-SIGN, чтобы подтверждать операции');
    const hash = requestHash(input);
    const existing = db.prepare('SELECT * FROM idempotency_keys WHERE customer_id = ? AND key = ?').get(customer.id, idempotencyKey);
    if (existing) {
      if (existing.request_hash !== hash) {
        recordEvent(db, { type: 'IDEMPOTENCY_CONFLICT', source: 'BANK', customerId: customer.id, transactionId: existing.transaction_id, detail: { idempotencyKey } });
        throw new BankError(409, 'IDEMPOTENCY_KEY_REUSED', 'Этот ключ идемпотентности уже использован для другой операции');
      }
      const t = getTransaction(existing.transaction_id);
      event(t, 'IDEMPOTENT_REPLAY', 'BANK', { idempotencyKey });
      return { transaction: t, replay: true };
    }
    const p = prepare(customer, input);
    const at = now();
    const t = {
      id: randomUUID(),
      reference: `VX-${Date.now().toString(36).toUpperCase()}-${randomBytes(2).toString('hex').toUpperCase()}`,
    };
    dbTransaction(db, () => {
      db.prepare(`INSERT INTO transactions (id, reference, customer_id, kind, source_account_id, destination_account_id, beneficiary_name,
        beneficiary_iban, amount_minor, fee_minor, currency, description, state, scenario_run_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CREATED', ?, ?, ?)`)
        .run(t.id, t.reference, customer.id, p.kind, p.source.id, p.destination?.id ?? null, p.beneficiaryName, p.beneficiaryIban,
          p.amountMinor, p.feeMinor, p.source.currency, p.description, scenarioRunId, at, at);
      db.prepare('INSERT INTO idempotency_keys (customer_id, key, request_hash, transaction_id, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(customer.id, idempotencyKey, hash, t.id, at);
      recordEvent(db, { type: 'TRANSACTION_CREATED', source: 'BANK', customerId: customer.id, transactionId: t.id,
        detail: { kind: p.kind, amount: formatMinor(p.amountMinor, p.source.currency), fee: formatMinor(p.feeMinor, p.source.currency), beneficiaryIban: p.beneficiaryIban } });
    });
    let row = getTransaction(t.id);
    const terms = signedTermsOf(row);
    const created = await authCore.createAuthorization({
      nexusId: customer.nexus_id,
      credentialId: customer.credential_id,
      transactionReference: terms.transactionReference,
      operationType: terms.operationType,
      amountMinor: terms.amountMinor,
      currency: terms.currency,
      beneficiary: terms.beneficiary,
      policyReference: 'SANDBOX-DEFAULT',
      policyVersion: bank.policy.version,
      expiresInSeconds: input.expiresInSeconds ?? bank.policy.authorizationTtlSeconds,
      correlationId: row.id,
    }, row.id).catch((error) => ({ status: 0, text: error.message }));
    if (created.status !== 201 && created.status !== 200) {
      const why = created.json?.error ?? created.json?.message ?? created.json?.code ?? '';
      row = setState(row, 'FAILED', { failure_reason: `Auth Core refused the authorization request (HTTP ${created.status})${why ? `: ${String(why).slice(0, 200)}` : ''}` });
      event(row, 'CHALLENGE_REFUSED', 'AUTH_CORE', { httpStatus: created.status, body: created.json ?? created.text?.slice(0, 300) });
      return { transaction: row, replay: false };
    }
    row = setState(row, 'AUTHORIZATION_PENDING', {
      authorization_id: created.json.authorizationId,
      canonical_payload_hash: created.json.canonicalPayloadHash,
      authorization_expires_at: created.json.expiresAt,
      signed_terms: JSON.stringify(terms),
    });
    event(row, 'CHALLENGE_GENERATED', 'AUTH_CORE', { authorizationId: created.json.authorizationId, canonicalPayloadHash: created.json.canonicalPayloadHash, expiresAt: created.json.expiresAt });
    notify(row, 'AUTHORIZATION_REQUEST', 'Подтвердите операцию', `${formatMinor(row.amount_minor, row.currency)} → ${row.beneficiary_name}`);
    return { transaction: row, replay: false };
  }

  function notify(t, kind, title, body) {
    const suppressed = faults.notificationSuppressed(t.id);
    db.prepare('INSERT INTO notifications (id, customer_id, transaction_id, kind, title, body, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(randomUUID(), t.customer_id, t.id, kind, title, body, suppressed ? 'SUPPRESSED' : 'QUEUED', now());
    event(t, suppressed ? 'NOTIFICATION_SUPPRESSED' : 'NOTIFICATION_QUEUED', 'BANK', { kind, ...(suppressed ? { fault: 'push delivery failure (sandbox fault injection)' } : {}) });
  }

  /** The app asks for the confirmation waiting for its customer; this is delivery. */
  function pendingFor(customer) {
    const t = db.prepare(`SELECT * FROM transactions WHERE customer_id = ? AND state = 'AUTHORIZATION_PENDING'
      AND authorization_expires_at > ? ORDER BY created_at DESC LIMIT 1`).get(customer.id, now());
    if (!t) return null;
    const notification = db.prepare("SELECT * FROM notifications WHERE transaction_id = ? AND kind = 'AUTHORIZATION_REQUEST'").get(t.id);
    if (notification?.state === 'SUPPRESSED') return null;
    if (notification?.state === 'QUEUED') {
      db.prepare("UPDATE notifications SET state = 'DELIVERED', delivered_at = ? WHERE id = ?").run(now(), notification.id);
      event(t, 'CHALLENGE_DELIVERED', 'DEVICE', { via: 'bank app polling' });
    }
    return t;
  }

  async function cancel(customer, transactionId, reason = 'CUSTOMER_REQUEST', source = 'BANK') {
    const t = getTransaction(transactionId);
    if (!t || (customer && t.customer_id !== customer.id)) throw new BankError(404, 'NOT_FOUND', 'Операция не найдена');
    if (t.state !== 'AUTHORIZATION_PENDING') throw new BankError(409, 'NOT_CANCELLABLE', 'Операцию уже нельзя отменить');
    const result = await authCore.cancel(t.authorization_id, reason);
    if (result.status !== 200) {
      event(t, 'CANCEL_REFUSED', 'AUTH_CORE', { httpStatus: result.status, code: result.json?.code });
      await reconcile(t.id);
      throw new BankError(409, 'NOT_CANCELLABLE', 'Auth Core не отменил запрос: операция уже подтверждена, истекла или завершена');
    }
    const row = setState(t, 'CANCELLED', { failure_reason: `cancelled: ${reason}` });
    event(row, 'TRANSACTION_CANCELLED', source, { reason });
    return row;
  }

  /** Brings one open transaction up to date with Auth Core and executes it if confirmed. */
  async function reconcile(transactionId) {
    if (inFlight.has(transactionId)) return getTransaction(transactionId);
    inFlight.add(transactionId);
    try {
      let t = getTransaction(transactionId);
      if (t?.state === 'EXECUTED' && !t.commit_reported) await reportCommit(t, 'COMMITTED');
      if (!t || !OPEN_STATES.includes(t.state)) return t;
      const view = await authCore.authorization(t.authorization_id).catch((error) => ({ status: 0, text: error.message }));
      if (view.status !== 200) return t;
      const a = view.json;
      switch (a.state) {
        case 'PENDING_USER':
          return t;
        case 'OFFLINE_PROVISIONAL':
          if (t.state !== 'OFFLINE_PROVISIONAL') {
            t = setState(t, 'OFFLINE_PROVISIONAL');
            event(t, 'OFFLINE_CODE_ACCEPTED', 'AUTH_CORE', { offlineSignatureDeadline: a.offlineSignatureDeadline, note: 'not executed until the device signature arrives' });
          }
          return t;
        case 'REJECTED':
          t = setState(t, 'REJECTED', { failure_reason: 'declined by the customer on the device' });
          event(t, 'CUSTOMER_REJECTED', 'DEVICE', {});
          return t;
        case 'EXPIRED':
          t = setState(t, 'EXPIRED', { failure_reason: 'the confirmation request expired' });
          event(t, 'CHALLENGE_EXPIRED', 'AUTH_CORE', { expiresAt: a.expiresAt });
          return t;
        case 'CANCELLED':
          t = setState(t, 'CANCELLED', { failure_reason: 'cancelled in Auth Core' });
          event(t, 'TRANSACTION_CANCELLED', 'AUTH_CORE', {});
          return t;
        case 'OFFLINE_UNSIGNED':
          t = setState(t, 'FAILED', { failure_reason: `offline code without the device signature (${a.offlineUnsignedReason ?? 'deadline'})` });
          event(t, 'SECURITY_INCIDENT', 'AUTH_CORE', { state: a.state, reason: a.offlineUnsignedReason });
          return t;
        case 'VERIFIED':
          return await authorizeAndExecute(t, a);
        default:
          event(t, 'UNKNOWN_AUTHORIZATION_STATE', 'AUTH_CORE', { state: a.state });
          return t;
      }
    } finally {
      inFlight.delete(transactionId);
    }
  }

  async function authorizeAndExecute(t, view) {
    t = setState(t, 'AUTHORIZING');
    event(t, 'CUSTOMER_CONFIRMED', 'DEVICE', { confirmationMethod: view.confirmationMethod, verifiedAt: view.verifiedAt });
    const refuse = (code, problems) => {
      const row = setState(t, 'FAILED', { failure_reason: `${code}: ${problems.join('; ')}` });
      event(row, 'AUTHORIZATION_DECISION', 'BANK', { decision: 'REFUSED', code, problems });
      return row;
    };
    if (view.confirmed !== true) return refuse('NOT_CONFIRMED', [view.evidenceProblem ?? 'Auth Core reports confirmed=false']);

    const exported = await authCore.evidence(t.authorization_id).catch((error) => ({ status: 0, text: error.message }));
    if (exported.status !== 200) {
      // Not a refusal: the bank retries on the next reconciliation.
      t = setState(t, 'AUTHORIZATION_PENDING');
      event(t, 'EVIDENCE_UNAVAILABLE', 'AUTH_CORE', { httpStatus: exported.status });
      return t;
    }
    let record = exported.json;
    if (faults.takeEvidenceTamper(t.id)) {
      record = structuredClone(record);
      const signed = JSON.parse(Buffer.from(record.sealedPayload.signedPayloadBase64, 'base64').toString('utf8'));
      signed.amount_minor = String(Number(signed.amount_minor) + 100);
      record.sealedPayload.signedPayloadBase64 = Buffer.from(JSON.stringify(signed)).toString('base64');
      event(t, 'FAULT_INJECTED', 'SCENARIO', { fault: 'the bank\'s received copy of the evidence was altered (amount +1.00)' });
    }
    event(t, 'EVIDENCE_RECEIVED', 'AUTH_CORE', { evidenceHash: record.evidenceHash, chainSequence: record.chainSequence, sealKeyId: record.sealedPayload?.sealKeyId });

    const pinned = new Map(db.prepare('SELECT key_id, public_key_pem FROM evidence_keys').all().map((r) => [r.key_id, r.public_key_pem]));
    if (pinned.size === 0) {
      for (const pem of record.evidencePublicKeys ?? [record.evidencePublicKeyPem].filter(Boolean)) {
        const id = evidenceKeyId(pem);
        db.prepare('INSERT OR IGNORE INTO evidence_keys (key_id, public_key_pem, pinned_at) VALUES (?, ?, ?)').run(id, pem, now());
        pinned.set(id, pem);
        recordEvent(db, { type: 'EVIDENCE_KEY_PINNED', source: 'BANK', detail: { keyId: id, note: 'first key seen by this sandbox bank (trust on first use)' } });
      }
    }
    const { problems: evidenceProblems, signed } = checkEvidence(record, pinned);
    db.prepare('INSERT OR REPLACE INTO evidence (transaction_id, authorization_id, evidence_hash, chain_sequence, seal_key_id, record, problems, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(t.id, t.authorization_id, record.evidenceHash, record.chainSequence ?? null, record.sealedPayload?.sealKeyId ?? null, JSON.stringify(record), JSON.stringify(evidenceProblems), now());
    if (evidenceProblems.length > 0) {
      event(t, 'VERIFICATION_FAILED', 'BANK', { problems: evidenceProblems });
      return refuse('EVIDENCE_INVALID', evidenceProblems);
    }
    event(t, 'SIGNATURE_VERIFIED', 'BANK', { verifier: 'auth-core/scripts/lib/evidence.mjs', confirmationMethod: record.sealedPayload.confirmationMethod ?? 'DEVICE_SIGNATURE', sealKeyId: record.sealedPayload.sealKeyId });

    const customer = db.prepare('SELECT * FROM customers WHERE id = ?').get(t.customer_id);
    const bindingProblems = checkBinding(t, signed, { authorizationId: t.authorization_id, nexusId: customer.nexus_id, credentialId: record.sealedPayload.credentialId, canonicalPayloadHash: t.canonical_payload_hash }, record);
    if (bindingProblems.length > 0) {
      event(t, 'BINDING_MISMATCH', 'BANK', { problems: bindingProblems });
      return refuse('BINDING_MISMATCH', bindingProblems);
    }
    event(t, 'BINDING_VERIFIED', 'BANK', { signed: { amount_minor: signed.amount_minor, currency: signed.currency, beneficiary: signed.beneficiary, transaction_reference: signed.transaction_reference } });

    const commit = await authCore.commitRequest(t.authorization_id, t.reference).catch((error) => ({ status: 0, text: error.message }));
    if (commit.status !== 202) {
      if (commit.status === 0 || commit.status >= 500) {
        t = setState(t, 'AUTHORIZATION_PENDING');
        event(t, 'COMMIT_REQUEST_RETRY', 'AUTH_CORE', { httpStatus: commit.status });
        return t;
      }
      return refuse('COMMIT_REFUSED', [`Auth Core refused the commit request: ${commit.json?.code ?? commit.status}`]);
    }
    event(t, 'AUTHORIZATION_DECISION', 'BANK', { decision: 'APPROVED', policyVersion: bank.policy.version });

    try {
      t = execute(t, record);
    } catch (error) {
      const row = setState(t, 'FAILED', { failure_reason: `ledger: ${error.message}` });
      event(row, 'LEDGER_FAILED', 'BANK', { error: error.message });
      await reportCommit(row, 'FAILED', error.message);
      return row;
    }
    await reportCommit(t, 'COMMITTED');
    return getTransaction(t.id);
  }

  /** Ledger posting, balance update, receipt and events in one database transaction. */
  function execute(t, record) {
    return dbTransaction(db, () => {
      const source = db.prepare('SELECT * FROM accounts WHERE id = ?').get(t.source_account_id);
      if (source.balance_minor < t.amount_minor + t.fee_minor) throw new Error('insufficient funds at execution');
      const journal = randomUUID();
      db.prepare("INSERT INTO journals (id, transaction_id, kind, created_at) VALUES (?, ?, 'TRANSFER', ?)").run(journal, t.id, now());
      const entry = db.prepare('INSERT INTO ledger_entries (journal_id, account_id, amount_minor, currency, memo) VALUES (?, ?, ?, ?, ?)');
      const move = db.prepare('UPDATE accounts SET balance_minor = balance_minor + ? WHERE id = ?');
      const credit = t.destination_account_id ?? 'BANK-CLEARING';
      entry.run(journal, t.source_account_id, -t.amount_minor, t.currency, `${t.reference} to ${t.beneficiary_iban}`);
      entry.run(journal, credit, t.amount_minor, t.currency, `${t.reference} from ${source.iban}`);
      move.run(-t.amount_minor, t.source_account_id);
      move.run(t.amount_minor, credit);
      if (t.fee_minor > 0) {
        entry.run(journal, t.source_account_id, -t.fee_minor, t.currency, `${t.reference} commission`);
        entry.run(journal, 'BANK-FEES', t.fee_minor, t.currency, `${t.reference} commission`);
        move.run(-t.fee_minor, t.source_account_id);
        move.run(t.fee_minor, 'BANK-FEES');
      }
      const executedAt = now();
      db.prepare("UPDATE transactions SET state = 'EXECUTED', updated_at = ? WHERE id = ? AND state = 'AUTHORIZING'").run(executedAt, t.id);
      recordEvent(db, { type: 'LEDGER_EXECUTED', source: 'BANK', customerId: t.customer_id, transactionId: t.id, detail: { journal, debit: t.source_account_id, credit, amountMinor: t.amount_minor, feeMinor: t.fee_minor } });
      const receipt = {
        receiptId: randomUUID(),
        bank: bank.branding.name,
        reference: t.reference,
        executedAt,
        from: source.iban,
        to: { name: t.beneficiary_name, iban: t.beneficiary_iban },
        amount: formatMinor(t.amount_minor, t.currency),
        fee: formatMinor(t.fee_minor, t.currency),
        total: formatMinor(t.amount_minor + t.fee_minor, t.currency),
        confirmation: {
          authorizationId: t.authorization_id,
          method: record.sealedPayload.confirmationMethod ?? 'DEVICE_SIGNATURE',
          evidenceHash: record.evidenceHash,
          chainSequence: record.chainSequence ?? null,
        },
        notice: 'Демонстрационная операция с тестовыми средствами.',
      };
      db.prepare('INSERT INTO receipts (id, transaction_id, body, created_at) VALUES (?, ?, ?, ?)').run(receipt.receiptId, t.id, JSON.stringify(receipt), executedAt);
      recordEvent(db, { type: 'RECEIPT_GENERATED', source: 'BANK', customerId: t.customer_id, transactionId: t.id, detail: { receiptId: receipt.receiptId } });
      recordEvent(db, { type: 'EVIDENCE_RECORDED', source: 'BANK', customerId: t.customer_id, transactionId: t.id, detail: { evidenceHash: record.evidenceHash, chainSequence: record.chainSequence ?? null } });
      db.prepare('INSERT INTO notifications (id, customer_id, transaction_id, kind, title, body, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(randomUUID(), t.customer_id, t.id, 'EXECUTED', 'Операция выполнена', `${formatMinor(t.amount_minor, t.currency)} → ${t.beneficiary_name}`, 'QUEUED', executedAt);
      return getTransaction(t.id);
    });
  }

  async function reportCommit(t, state, error) {
    const result = await authCore.commitResult(t.authorization_id, state, error).catch((e) => ({ status: 0, text: e.message }));
    if (result.status === 200) {
      db.prepare('UPDATE transactions SET commit_reported = ? WHERE id = ?').run(state, t.id);
      event(t, 'COMMIT_RESULT_RECORDED', 'AUTH_CORE', { state });
    } else {
      event(t, 'COMMIT_RESULT_RETRY', 'AUTH_CORE', { state, httpStatus: result.status });
    }
  }

  /** Reconciles every open transaction; run by a timer. */
  async function reconcileOpen() {
    const open = db.prepare(`SELECT id FROM transactions WHERE state IN ('AUTHORIZATION_PENDING', 'OFFLINE_PROVISIONAL')
      OR (state = 'EXECUTED' AND commit_reported IS NULL)`).all();
    for (const { id } of open) await reconcile(id);
  }

  /** Offline (QR) confirmation: the QR content Auth Core issues for this transaction. */
  async function offlineChallenge(customer, transactionId) {
    const t = getTransaction(transactionId);
    if (!t || t.customer_id !== customer.id) throw new BankError(404, 'NOT_FOUND', 'Операция не найдена');
    if (t.state !== 'AUTHORIZATION_PENDING') throw new BankError(409, 'NOT_PENDING', 'Операция не ожидает подтверждения');
    const challenge = await authCore.offlineChallenge(t.authorization_id);
    if (challenge.status !== 200) throw new BankError(challenge.status, challenge.json?.code ?? 'AUTH_CORE', 'Auth Core не выдал QR-код');
    event(t, 'OFFLINE_QR_ISSUED', 'AUTH_CORE', { expiresAt: challenge.json.expiresAt });
    return { transactionId: t.id, authorizationId: t.authorization_id, qrPayload: challenge.json.qrPayload, expiresAt: challenge.json.expiresAt };
  }

  /** The 8-digit code read from the phone, entered at the bank (branch, console). */
  async function offlineCode(transactionId, code, source = 'CONSOLE') {
    const t = getTransaction(transactionId);
    if (!t) throw new BankError(404, 'NOT_FOUND', 'Операция не найдена');
    const digits = String(code ?? '').replace(/\s+/g, '');
    if (!/^\d{8}$/.test(digits)) throw new BankError(400, 'INVALID_CODE', 'Код — 8 цифр');
    const result = await authCore.offlineConfirmation(t.authorization_id, digits);
    event(t, 'OFFLINE_CODE_SUBMITTED', source, { httpStatus: result.status, status: result.json?.status ?? null, reason: result.json?.reason ?? null });
    await reconcile(t.id);
    return { status: result.json?.status ?? `HTTP ${result.status}`, reason: result.json?.reason ?? null, transaction: getTransaction(t.id) };
  }

  return { getTransaction, quote, create, pendingFor, cancel, reconcile, reconcileOpen, offlineChallenge, offlineCode };
}
