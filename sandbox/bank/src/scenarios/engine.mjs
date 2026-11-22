// Demonstration scenario engine. Every scenario drives the same services as
// the bank app (payments, customers) against the real Auth Core, with the
// software test device for the customer's side. Outcomes are read back from
// the bank's database and from Auth Core; a scenario passes only when the
// observed result equals the expected one.
import { randomUUID } from 'node:crypto';
import { now } from '../db.mjs';
import { recordEvent } from '../events.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function createScenarioEngine({ db, payments, customers, device, faults, authCore }) {
  let running = null;

  const scenarioCustomer = () => db.prepare("SELECT * FROM customers WHERE device_kind = 'SOFTWARE_TEST_DEVICE' LIMIT 1").get();
  const account = (customerId) => db.prepare("SELECT * FROM accounts WHERE customer_id = ? AND kind = 'CUSTOMER' ORDER BY id LIMIT 1").get(customerId);
  const journalCount = (transactionId) => db.prepare('SELECT COUNT(*) AS n FROM journals WHERE transaction_id = ?').get(transactionId).n;

  async function ensureEnrolled(ctx) {
    let customer = scenarioCustomer();
    const saved = device.current();
    if (customer.credential_id && saved?.credentialId === customer.credential_id) return customer;
    const { token, nexusId } = await customers.bootstrapToken(customer);
    const enrolled = await device.enrol(nexusId, token);
    customer = customers.byId(customer.id);
    await customers.completeEnrolment(customer, enrolled.credentialId);
    ctx.step(`software test device enrolled: credential ${enrolled.credentialId}`);
    return customers.byId(customer.id);
  }

  async function waitForState(transactionId, states, timeoutMs = 20_000) {
    const deadline = Date.now() + timeoutMs;
    let t;
    do {
      t = await payments.reconcile(transactionId);
      if (states.includes(t.state)) return t;
      await sleep(400);
    } while (Date.now() < deadline);
    return t;
  }

  async function newTransaction(ctx, customer, overrides = {}, key = randomUUID()) {
    const input = {
      sourceAccountId: account(customer.id).id,
      beneficiaryName: 'Ион Попеску', beneficiaryIban: 'MD07AG000000022589630417', amountMinor: 5000, description: `scenario ${ctx.id}`,
      ...overrides,
    };
    const { transaction } = await payments.create(customer, input, key, { scenarioRunId: ctx.runId });
    ctx.transactionId = transaction.id;
    ctx.step(`transaction ${transaction.reference} ${transaction.state}, authorization ${transaction.authorization_id ?? '—'}`);
    if (transaction.state !== 'AUTHORIZATION_PENDING') throw new Error(`transaction not pending: ${transaction.state} (${transaction.failure_reason})`);
    return transaction;
  }

  const expectHttp = (ctx, label, response, ok) => {
    ctx.step(`${label}: HTTP ${response.status}${response.json?.code ? ` ${response.json.code}` : ''}`);
    if (!ok(response.status)) throw new Error(`${label}: unexpected HTTP ${response.status} ${response.text?.slice(0, 200) ?? ''}`);
    return response;
  };

  /** Device takes the pending request from the bank (delivery), then acts. */
  async function deliver(ctx, customer) {
    const pending = payments.pendingFor(customer);
    ctx.step(pending ? `request delivered to the device (${pending.reference})` : 'no request delivered to the device');
    return pending;
  }

  const SCENARIOS = [
    {
      id: 'successful-transfer', title: 'Успешный перевод', initial: 'Клиент со счётом и зарегистрированным устройством',
      action: 'Клиент подтверждает перевод на свой счёт другому клиенту банка', expected: 'EXECUTED, одна проводка, квитанция',
      events: ['TRANSACTION_CREATED', 'CHALLENGE_GENERATED', 'CHALLENGE_DELIVERED', 'CUSTOMER_CONFIRMED', 'SIGNATURE_VERIFIED', 'BINDING_VERIFIED', 'AUTHORIZATION_DECISION', 'LEDGER_EXECUTED', 'RECEIPT_GENERATED', 'EVIDENCE_RECORDED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c, { beneficiaryIban: undefined, beneficiaryName: undefined, destinationAccountId: 'acc-anna-main', amountMinor: 2500 });
        await deliver(ctx, c);
        expectHttp(ctx, 'device signature', await device.approve(t.authorization_id), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { state: done.state, journals: journalCount(t.id), pass: done.state === 'EXECUTED' && journalCount(t.id) === 1 };
      },
    },
    {
      id: 'successful-payment', title: 'Успешный платёж', initial: 'Клиент со счётом', action: 'Клиент подтверждает платёж внешнему получателю (с комиссией)',
      expected: 'EXECUTED, комиссия списана на счёт доходов', events: ['LEDGER_EXECUTED', 'RECEIPT_GENERATED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c, { amountMinor: 120000 });
        await deliver(ctx, c);
        expectHttp(ctx, 'device signature', await device.approve(t.authorization_id), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { state: done.state, feeMinor: done.fee_minor, pass: done.state === 'EXECUTED' && done.fee_minor > 0 };
      },
    },
    {
      id: 'invalid-signature', title: 'Неверная подпись', initial: 'Ожидающая операция', action: 'Устройство подписывает чужим ключом',
      expected: 'Auth Core отвергает подпись, операция не исполняется', events: ['TRANSACTION_CANCELLED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        await deliver(ctx, c);
        const r = await device.signWithForeignKey(t.authorization_id);
        ctx.step(`signature with a foreign key: HTTP ${r.status} ${r.json?.code ?? ''}`);
        await payments.cancel(null, t.id, 'OTHER', 'SCENARIO');
        const done = payments.getTransaction(t.id);
        return { state: done.state, authCoreStatus: r.status, pass: r.status >= 400 && r.status < 500 && done.state === 'CANCELLED' && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'altered-transaction-data', title: 'Изменённые данные транзакции', initial: 'Ожидающая операция', action: 'Устройство подписывает байты с изменённой суммой',
      expected: 'Auth Core отвергает подпись, операция не исполняется', events: ['TRANSACTION_CANCELLED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        await deliver(ctx, c);
        const r = await device.signAlteredTerms(t.authorization_id);
        ctx.step(`signature over altered terms: HTTP ${r.status} ${r.json?.code ?? ''}`);
        await payments.cancel(null, t.id, 'ORDER_CHANGED', 'SCENARIO');
        const done = payments.getTransaction(t.id);
        return { state: done.state, authCoreStatus: r.status, pass: r.status >= 400 && r.status < 500 && done.state === 'CANCELLED' && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'expired-challenge', title: 'Истёкший запрос', initial: 'Операция со сроком 30 с', action: 'Клиент не отвечает; подпись после срока',
      expected: 'EXPIRED, поздняя подпись отвергается', events: ['CHALLENGE_EXPIRED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c, { expiresInSeconds: 30 });
        ctx.step('waiting 32 s for the request to expire');
        await sleep(32_000);
        const late = await device.approve(t.authorization_id).catch((error) => ({ status: 0, text: error.message }));
        ctx.step(`late signature: HTTP ${late.status}`);
        const done = await waitForState(t.id, ['EXPIRED'], 10_000);
        return { state: done.state, lateSignature: late.status, pass: done.state === 'EXPIRED' && late.status !== 200 && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'rejected-authorization', title: 'Клиент отклонил', initial: 'Ожидающая операция', action: 'Клиент нажимает «Это не я»',
      expected: 'REJECTED, без проводки', events: ['CUSTOMER_REJECTED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        await deliver(ctx, c);
        expectHttp(ctx, 'decline NOT_ME', await device.decline(t.authorization_id), (s) => s === 200);
        const done = await waitForState(t.id, ['REJECTED']);
        return { state: done.state, pass: done.state === 'REJECTED' && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'cancelled-transaction', title: 'Отменённая операция', initial: 'Ожидающая операция', action: 'Банк отменяет; клиент пытается подписать после отмены',
      expected: 'CANCELLED, подпись отвергается', events: ['TRANSACTION_CANCELLED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        await payments.cancel(null, t.id, 'CUSTOMER_REQUEST', 'SCENARIO');
        const late = await device.approve(t.authorization_id).catch((error) => ({ status: 0, text: error.message }));
        ctx.step(`signature after cancellation: HTTP ${late.status}`);
        const done = payments.getTransaction(t.id);
        return { state: done.state, lateSignature: late.status, pass: done.state === 'CANCELLED' && late.status !== 200 && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'push-delivery-failure', title: 'Сбой доставки уведомления', initial: 'Ожидающая операция', action: 'Уведомление банка не доставлено (сбой в песочнице)',
      expected: 'Запрос не доставлен, операция не исполнена; автоматическая эскалация — веха 4', events: ['NOTIFICATION_SUPPRESSED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        // The bank's notification for this request is lost (sandbox fault).
        faults.suppressNotificationOf(t.id);
        db.prepare("UPDATE notifications SET state = 'SUPPRESSED' WHERE transaction_id = ? AND kind = 'AUTHORIZATION_REQUEST' AND state = 'QUEUED'").run(t.id);
        recordEvent(db, { type: 'NOTIFICATION_SUPPRESSED', source: 'SCENARIO', customerId: c.id, transactionId: t.id, detail: { fault: 'push delivery failure (sandbox fault injection)' } });
        const delivered = await deliver(ctx, c);
        await payments.cancel(null, t.id, 'OTHER', 'SCENARIO');
        return { delivered: Boolean(delivered), escalation: 'not available until milestone 4', pass: !delivered && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'network-interruption', title: 'Обрыв сети', initial: 'Ожидающая операция', action: 'Сеть устройства пропадает на 4 с, затем устройство повторяет',
      expected: 'Первая попытка не доходит, повтор успешен, EXECUTED', events: ['LEDGER_EXECUTED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        await deliver(ctx, c);
        faults.dropDeviceNetwork(4000);
        const first = await device.approve(t.authorization_id).catch((error) => ({ status: 0, text: error.message }));
        ctx.step(`attempt during the outage: HTTP ${first.status}`);
        await sleep(4500);
        expectHttp(ctx, 'retry after the network is back', await device.approve(t.authorization_id), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { firstAttempt: first.status, state: done.state, pass: first.status !== 200 && done.state === 'EXECUTED' };
      },
    },
    {
      id: 'duplicate-request', title: 'Дублирующий запрос', initial: 'Операция создана с ключом идемпотентности', action: 'Тот же ключ, другая сумма',
      expected: '409 IDEMPOTENCY_KEY_REUSED, вторая операция не создана', events: ['IDEMPOTENCY_CONFLICT'],
      async run(ctx, c) {
        const key = randomUUID();
        const t = await newTransaction(ctx, c, {}, key);
        let code = null;
        try {
          await payments.create(c, { sourceAccountId: account(c.id).id, beneficiaryName: 'Ион Попеску', beneficiaryIban: 'MD07AG000000022589630417', amountMinor: 9999, description: `scenario ${ctx.id}` }, key);
        } catch (error) { code = error.code; }
        ctx.step(`second request with the same key: ${code ?? 'accepted'}`);
        const count = db.prepare('SELECT COUNT(*) AS n FROM idempotency_keys WHERE key = ?').get(key).n;
        await payments.cancel(null, t.id, 'OTHER', 'SCENARIO');
        return { code, transactionsForKey: count, pass: code === 'IDEMPOTENCY_KEY_REUSED' && count === 1 };
      },
    },
    {
      id: 'idempotent-retry', title: 'Идемпотентный повтор', initial: 'Операция создана', action: 'Повтор того же запроса (тот же ключ, те же данные), затем подтверждение',
      expected: 'Та же операция, одна авторизация, одна проводка', events: ['IDEMPOTENT_REPLAY', 'LEDGER_EXECUTED'],
      async run(ctx, c) {
        const key = randomUUID();
        const t = await newTransaction(ctx, c, {}, key);
        const again = await payments.create(c, { sourceAccountId: account(c.id).id, beneficiaryName: 'Ион Попеску', beneficiaryIban: 'MD07AG000000022589630417', amountMinor: 5000, description: `scenario ${ctx.id}` }, key);
        ctx.step(`retry returned ${again.transaction.id === t.id ? 'the same transaction' : 'a NEW transaction'}`);
        await deliver(ctx, c);
        expectHttp(ctx, 'device signature', await device.approve(t.authorization_id), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { sameTransaction: again.transaction.id === t.id, replay: again.replay, journals: journalCount(t.id), pass: again.transaction.id === t.id && again.replay && done.state === 'EXECUTED' && journalCount(t.id) === 1 };
      },
    },
    {
      id: 'qr-authorization', title: 'Подтверждение по QR', initial: 'Ожидающая операция', action: 'Банк показывает QR, устройство вычисляет код, код вводится в банке, подпись приходит следом',
      expected: 'Пока нет подписи — OFFLINE_PROVISIONAL и не исполняется; после подписи — EXECUTED', events: ['OFFLINE_QR_ISSUED', 'OFFLINE_CODE_ACCEPTED', 'LEDGER_EXECUTED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        const qr = await payments.offlineChallenge(c, t.id);
        ctx.step(`QR issued (${qr.qrPayload.slice(0, 5)}…)`);
        const { code, canonical } = device.offlineCode(qr.qrPayload);
        const submitted = await payments.offlineCode(t.id, code, 'SCENARIO');
        ctx.step(`code entered at the bank: ${submitted.status}`);
        const provisional = payments.getTransaction(t.id);
        const executedEarly = journalCount(t.id) > 0;
        expectHttp(ctx, 'deferred device signature', await device.uploadDeferredSignature(t.authorization_id, canonical), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { afterCode: provisional.state, executedBeforeSignature: executedEarly, state: done.state, pass: provisional.state === 'OFFLINE_PROVISIONAL' && !executedEarly && done.state === 'EXECUTED' };
      },
    },
    {
      id: 'offline-authorization', title: 'Подтверждение без сети', initial: 'QR получен, затем сеть устройства пропадает', action: 'Код вычисляется без сети, вводится в банке; сеть возвращается — подпись уходит',
      expected: 'Без сети подпись не доходит; операция ждёт; после восстановления — EXECUTED', events: ['OFFLINE_CODE_ACCEPTED', 'LEDGER_EXECUTED'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        const qr = await payments.offlineChallenge(c, t.id);
        faults.dropDeviceNetwork(5000);
        const { code, canonical } = device.offlineCode(qr.qrPayload);
        ctx.step('device offline: code computed locally');
        const submitted = await payments.offlineCode(t.id, code, 'SCENARIO');
        ctx.step(`code entered at the bank: ${submitted.status}`);
        const blocked = await device.uploadDeferredSignature(t.authorization_id, canonical).catch((error) => ({ status: 0, text: error.message }));
        ctx.step(`upload while offline: HTTP ${blocked.status}`);
        const stillProvisional = payments.getTransaction(t.id).state;
        await sleep(5500);
        expectHttp(ctx, 'upload after the network is back', await device.uploadDeferredSignature(t.authorization_id, canonical), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { whileOffline: stillProvisional, state: done.state, pass: blocked.status !== 200 && stillProvisional === 'OFFLINE_PROVISIONAL' && done.state === 'EXECUTED' };
      },
    },
    {
      id: 'audio-escalation', title: 'Эскалация на аудиозвонок', available: false, initial: '—', action: '—',
      expected: 'Веха 4: робот-звонок и автоматическая эскалация', events: [],
    },
    {
      id: 'video-escalation', title: 'Эскалация на видеозвонок', available: false, initial: '—', action: '—',
      expected: 'Веха 4: робот-видеозвонок и автоматическая эскалация', events: [],
    },
    {
      id: 'failed-verification', title: 'Проверка банка не прошла', initial: 'Auth Core подтвердил операцию', action: 'Копия доказательства, полученная банком, искажена (сбой в песочнице)',
      expected: 'Банк отказывает (FAILED), проводки нет', events: ['VERIFICATION_FAILED', 'AUTHORIZATION_DECISION'],
      async run(ctx, c) {
        const t = await newTransaction(ctx, c);
        faults.tamperEvidenceOf(t.id);
        await deliver(ctx, c);
        expectHttp(ctx, 'device signature', await device.approve(t.authorization_id), (s) => s === 200);
        const done = await waitForState(t.id, ['EXECUTED', 'FAILED']);
        return { state: done.state, reason: done.failure_reason, pass: done.state === 'FAILED' && journalCount(t.id) === 0 };
      },
    },
    {
      id: 'evidence-validation', title: 'Проверка цепочки доказательств', initial: 'У клиента есть подтверждённые операции', action: 'Банк выгружает цепочку из Auth Core и проверяет её закреплёнными ключами',
      expected: 'Цепочка без пропусков, печати и подписи верны, конец цепочки совпадает с сохранённым банком', events: [],
      async run(ctx, c) {
        const { checkChain } = await import('../evidenceCheck.mjs');
        const pinned = new Map(db.prepare('SELECT key_id, public_key_pem FROM evidence_keys').all().map((r) => [r.key_id, r.public_key_pem]));
        const head = db.prepare(`SELECT e.chain_sequence, e.evidence_hash FROM evidence e JOIN transactions t ON t.id = e.transaction_id
          WHERE t.customer_id = ? AND e.problems = '[]' ORDER BY e.chain_sequence DESC LIMIT 1`).get(c.id);
        const chain = await authCore.chain(c.nexus_id);
        const result = checkChain(chain.json, pinned, head ? { chainSequence: head.chain_sequence, evidenceHash: head.evidence_hash } : undefined);
        ctx.step(`${result.records} records checked, ${result.problems.length} problems`);
        return { records: result.records, problems: result.problems, pass: chain.status === 200 && result.records > 0 && result.problems.length === 0 };
      },
    },
  ];

  function list() {
    const last = new Map(db.prepare('SELECT * FROM scenario_runs ORDER BY started_at').all().map((r) => [r.scenario, r]));
    return SCENARIOS.map((s) => ({ ...s, run: undefined, available: s.available !== false, last: last.get(s.id) ?? null }));
  }

  async function run(id) {
    const scenario = SCENARIOS.find((s) => s.id === id);
    if (!scenario) throw new Error(`unknown scenario ${id}`);
    const runId = randomUUID();
    if (scenario.available === false) {
      db.prepare("INSERT INTO scenario_runs (id, scenario, state, expected, actual, started_at, finished_at) VALUES (?, ?, 'NOT_AVAILABLE', ?, ?, ?, ?)")
        .run(runId, id, scenario.expected, JSON.stringify({ note: 'not implemented in this milestone; nothing is simulated' }), now(), now());
      return runId;
    }
    if (running) throw new Error(`scenario ${running} is running`);
    running = id;
    const steps = [];
    const ctx = { id, runId, transactionId: null, step: (text) => steps.push({ at: now(), text }) };
    db.prepare("INSERT INTO scenario_runs (id, scenario, state, expected, started_at) VALUES (?, ?, 'RUNNING', ?, ?)").run(runId, id, scenario.expected, now());
    recordEvent(db, { type: 'SCENARIO_STARTED', source: 'SCENARIO', detail: { scenario: id, runId } });
    const finish = (state, actual) => {
      db.prepare('UPDATE scenario_runs SET state = ?, actual = ?, transaction_id = ?, steps = ?, finished_at = ? WHERE id = ?')
        .run(state, JSON.stringify(actual), ctx.transactionId, JSON.stringify(steps), now(), runId);
      recordEvent(db, { type: 'SCENARIO_FINISHED', source: 'SCENARIO', transactionId: ctx.transactionId, detail: { scenario: id, runId, state } });
    };
    (async () => {
      try {
        const customer = await ensureEnrolled(ctx);
        const actual = await scenario.run(ctx, customer);
        finish(actual.pass ? 'PASSED' : 'FAILED', actual);
      } catch (error) {
        steps.push({ at: now(), text: `error: ${error.message}` });
        finish('FAILED', { error: error.message });
      } finally {
        running = null;
      }
    })();
    return runId;
  }

  const getRun = (runId) => {
    const r = db.prepare('SELECT * FROM scenario_runs WHERE id = ?').get(runId);
    return r ? { ...r, actual: r.actual ? JSON.parse(r.actual) : null, steps: JSON.parse(r.steps) } : null;
  };

  return { list, run, getRun, isRunning: () => running };
}
