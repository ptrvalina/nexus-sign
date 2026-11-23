// Bank operations console (server-rendered). Every page reads the bank's
// database or asks Auth Core at request time; nothing on a page is computed
// in the browser. Login: CONSOLE_USERNAME / CONSOLE_PASSWORD from the
// sandbox's own configuration.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { escapeHtml as e, readBody, sendHtml, sendJson } from '../http.mjs';
import { recentEvents, transactionEvents, TIMELINE } from '../events.mjs';
import { formatMinor } from '../fees.mjs';
import { recordEvent } from '../events.mjs';
import { checkChain } from '../evidenceCheck.mjs';
import { addCustomer, resetPassword } from '../seed.mjs';
import { BankError } from '../payments.mjs';
import { badge, page, table, time } from './layout.mjs';

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export function createConsole({ db, config, payments, scenarios, authCore, faults }) {
  const sessions = new Map(); // token → { csrf, expiresAt }
  const branding = config.bank.branding;
  const money = (minor, currency) => e(formatMinor(minor, currency));

  function session(req) {
    const token = /(?:^|;\s*)sbx_console=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? '')?.[1];
    const s = token && sessions.get(token);
    if (!s || s.expiresAt < Date.now()) return null;
    return { token, ...s };
  }

  const same = (a, b) => {
    const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
    return x.length === y.length && timingSafeEqual(x, y);
  };

  function loginPage(message = '') {
    return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>${e(branding.name)} · консоль</title>
<style>body{font:14px system-ui,sans-serif;background:#0f2b33;display:grid;place-items:center;height:100vh;margin:0}
form{background:#fff;padding:28px 32px;border-radius:12px;width:320px}h1{font-size:18px;margin:0 0 4px}p{color:#6a7b88;font-size:12px;margin:0 0 16px}
input{width:100%;padding:8px;margin:6px 0 12px;border:1px solid #c7d3db;border-radius:6px;box-sizing:border-box}
button{width:100%;padding:10px;border:0;border-radius:6px;background:${e(branding.primaryColor)};color:#fff;font-weight:600}.m{color:#a02018}</style></head>
<body><form method="post" action="/login"><h1>${e(branding.name)} — консоль</h1><p>Песочница NEXUS-SIGN. Тестовые средства.</p>
${message ? `<p class="m">${e(message)}</p>` : ''}<label>Пользователь<input name="username" autocomplete="username"></label>
<label>Пароль<input name="password" type="password" autocomplete="current-password"></label><button>Войти</button></form></body></html>`;
  }

  const csrfField = (s) => `<input type="hidden" name="csrf" value="${e(s.csrf)}">`;
  const view = (res, s, path, title, body, refresh = 0) => sendHtml(res, 200, page({ title, path, body, branding, refresh, csrf: s.csrf }));

  // --- Pages ---------------------------------------------------------------

  async function overview(res, s) {
    const count = (sql, ...a) => db.prepare(sql).get(...a).n;
    const health = await authCore.health();
    const states = db.prepare('SELECT state, COUNT(*) AS n FROM transactions GROUP BY state').all();
    const recent = db.prepare('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 8').all();
    const body = `<div class="cards">
<div class="card"><div class="note">Auth Core</div><div class="n">${health.ok ? badge('EXECUTED').replace('EXECUTED', 'готов') : badge('FAILED').replace('FAILED', 'недоступен')}</div></div>
<div class="card"><div class="note">Клиенты</div><div class="n">${count('SELECT COUNT(*) AS n FROM customers')}</div></div>
<div class="card"><div class="note">Устройства подключены</div><div class="n">${count('SELECT COUNT(*) AS n FROM customers WHERE credential_id IS NOT NULL')}</div></div>
<div class="card"><div class="note">Ожидают клиента</div><div class="n">${count("SELECT COUNT(*) AS n FROM transactions WHERE state IN ('AUTHORIZATION_PENDING','OFFLINE_PROVISIONAL')")}</div></div>
<div class="card"><div class="note">Исполнено</div><div class="n">${count("SELECT COUNT(*) AS n FROM transactions WHERE state = 'EXECUTED'")}</div></div>
<div class="card"><div class="note">Отказано / ошибки</div><div class="n">${count("SELECT COUNT(*) AS n FROM transactions WHERE state IN ('FAILED','REJECTED')")}</div></div>
</div>
<h2>Состояния транзакций</h2>${table(['Состояние', 'Количество'], states.map((r) => [badge(r.state), String(r.n)]))}
<h2>Последние транзакции</h2>${transactionsTable(recent)}`;
    view(res, s, '/', 'Обзор', body, 5);
  }

  function transactionsTable(rows) {
    const name = (id) => db.prepare('SELECT display_name FROM customers WHERE id = ?').get(id)?.display_name ?? id;
    return table(['Создана', 'Референс', 'Клиент', 'Тип', 'Сумма', 'Комиссия', 'Получатель', 'Состояние'], rows.map((t) => [
      time(t.created_at), `<a href="/transactions/${e(t.id)}"><code>${e(t.reference)}</code></a>`, e(name(t.customer_id)), e(t.kind),
      money(t.amount_minor, t.currency), money(t.fee_minor, t.currency), `${e(t.beneficiary_name)}<br><code>${e(t.beneficiary_iban)}</code>`,
      `${badge(t.state)}${t.failure_reason ? `<div class="note">${e(t.failure_reason)}</div>` : ''}`,
    ]));
  }

  function customersPage(res, s, message = '') {
    const rows = db.prepare('SELECT * FROM customers ORDER BY created_at, id').all();
    const form = `<h2>Новый тестовый клиент</h2>
<form method="post" action="/customers/new">${csrfField(s)}
Логин <input name="login" placeholder="ivan" required pattern="[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}" size="14">
Имя <input name="displayName" placeholder="Иван Петров" required size="22">
Остаток, ${e(config.bank.currency)} <input name="opening" value="10000" size="9" inputmode="decimal">
<button>Создать</button></form>
<p class="note">Каждому тестировщику — свой клиент: свой счёт с тестовыми средствами, своя карта. Пароль показывается один раз.</p>`;
    view(res, s, '/customers', 'Клиенты', `${message}${form}<h2>Клиенты</h2>` + table(['Клиент', 'Логин', 'Устройство', 'NEXUS ID', 'Credential'], rows.map((c) => [
      `<a href="/customers/${e(c.id)}">${e(c.display_name)}</a>`, `<code>${e(c.login)}</code>`,
      c.device_kind === 'SOFTWARE_TEST_DEVICE' ? '<span class="badge muted">программное тест-устройство</span>' : 'телефон клиента',
      c.nexus_id ? `<code>${e(c.nexus_id)}</code>` : '—', c.credential_id ? `<code>${e(c.credential_id)}</code>` : '<span class="note">не подключено</span>',
    ])));
  }

  /** The new login and its one-time password, as a block to send to the tester. */
  function credentialsMessage(login, password, title) {
    const app = config.publicUrl ? `Адрес банка в приложении: ${config.publicUrl}\nСкачать приложение: ${config.publicUrl}/` : 'Адрес банка: порт устройств песочницы';
    return `<div class="msg"><b>${e(title)}</b><pre>${e(`${config.bank.branding.name} (демо)\nЛогин: ${login}\nПароль: ${password}\n${app}`)}</pre>
<span class="note">Скопируйте и отправьте тестировщику. Пароль больше нигде не показывается.</span></div>`;
  }

  async function customerPage(res, s, id) {
    const c = db.prepare('SELECT * FROM customers WHERE id = ?').get(id);
    if (!c) throw new BankError(404, 'NOT_FOUND', 'Клиент не найден');
    const accounts = db.prepare('SELECT * FROM accounts WHERE customer_id = ?').all(id);
    const cards = db.prepare('SELECT k.* FROM cards k JOIN accounts a ON a.id = k.account_id WHERE a.customer_id = ?').all(id);
    const devices = c.nexus_id ? await authCore.devices(c.nexus_id) : null;
    const tx = db.prepare('SELECT * FROM transactions WHERE customer_id = ? ORDER BY created_at DESC LIMIT 50').all(id);
    const body = `<p>Логин <code>${e(c.login)}</code> · NEXUS ID <code>${e(c.nexus_id ?? '—')}</code></p>
<h2>Счета</h2>${table(['Счёт', 'IBAN', 'Баланс'], accounts.map((a) => [e(a.name), `<code>${e(a.iban)}</code>`, money(a.balance_minor, a.currency)]))}
<h2>Карты</h2>${table(['Карта', 'Счёт', 'Срок', 'Статус'], cards.map((k) => [`${e(k.brand)} •••• ${e(k.last4)}`, `<code>${e(k.account_id)}</code>`, e(k.expires), badge(k.status === 'ACTIVE' ? 'EXECUTED' : 'CANCELLED').replace(/EXECUTED|CANCELLED/, e(k.status))]))}
<h2>Устройства в Auth Core</h2>${devices?.status === 200 ? table(['Credential', 'Платформа', 'Уровень защиты', 'Аттестация', 'Состояние', 'Подключено'], (devices.json.devices ?? []).map((d) => [
      `<code>${e(d.credentialId)}</code>`, e(d.platform), e(d.securityLevel), e(d.attestationStatus), e(d.state), time(d.enrolledAt)])) : '<p class="note">Нет NEXUS ID или Auth Core не ответил.</p>'}
${c.device_kind === 'PHONE' ? `<h2>Доступ</h2><form method="post" action="/customers/${e(c.id)}/reset-password">${csrfField(s)}<button class="secondary">Выдать новый пароль</button></form>` : ''}
${c.nexus_id ? `<h2>Цепочка доказательств</h2><form method="post" action="/customers/${e(c.id)}/verify-chain">${csrfField(s)}<button>Проверить цепочку закреплёнными ключами</button></form>` : ''}
<h2>Транзакции</h2>${transactionsTable(tx)}`;
    view(res, s, '/customers', c.display_name, body);
  }

  async function verifyChainPage(res, s, id) {
    const c = db.prepare('SELECT * FROM customers WHERE id = ?').get(id);
    if (!c?.nexus_id) throw new BankError(404, 'NOT_FOUND', 'Нет NEXUS ID');
    const pinned = new Map(db.prepare('SELECT key_id, public_key_pem FROM evidence_keys').all().map((r) => [r.key_id, r.public_key_pem]));
    const head = db.prepare(`SELECT e.chain_sequence, e.evidence_hash FROM evidence e JOIN transactions t ON t.id = e.transaction_id
      WHERE t.customer_id = ? AND e.problems = '[]' ORDER BY e.chain_sequence DESC LIMIT 1`).get(id);
    const chain = await authCore.chain(c.nexus_id);
    const result = chain.status === 200 ? checkChain(chain.json, pinned, head ? { chainSequence: head.chain_sequence, evidenceHash: head.evidence_hash } : undefined) : { records: 0, problems: [`Auth Core HTTP ${chain.status}`] };
    recordEvent(db, { type: 'EVIDENCE_CHAIN_CHECKED', source: 'CONSOLE', customerId: id, detail: { records: result.records, problems: result.problems } });
    view(res, s, '/customers', `Цепочка доказательств: ${c.display_name}`, `
<p>${result.problems.length === 0 ? badge('PASSED') : badge('FAILED')} Записей: ${result.records}. Проверено независимым верификатором <code>auth-core/scripts/lib/evidence.mjs</code> с ключами печати, закреплёнными банком${head ? `, ожидаемый конец цепочки №${head.chain_sequence}` : ''}.</p>
${result.problems.length ? `<pre>${e(result.problems.join('\n'))}</pre>` : ''}
<h2>Записи</h2>${table(['№', 'Тип', 'Хеш', 'Ключ печати'], (chain.json?.records ?? []).map((r) => [String(r.chainSequence ?? '—'), e(r.recordType ?? r.sealedPayload?.recordType ?? 'AUTHORIZATION'), `<code>${e(String(r.evidenceHash).slice(0, 16))}…</code>`, `<code>${e(String(r.sealedPayload?.sealKeyId ?? '').slice(0, 16))}…</code>`]))}
<p><a href="/customers/${e(id)}">← к клиенту</a></p>`);
  }

  function accountsPage(res, s) {
    const rows = db.prepare('SELECT a.*, c.display_name FROM accounts a LEFT JOIN customers c ON c.id = a.customer_id ORDER BY a.kind DESC, a.id').all();
    const cards = db.prepare('SELECT k.*, a.iban FROM cards k JOIN accounts a ON a.id = k.account_id ORDER BY k.id').all();
    const ledger = db.prepare('SELECT SUM(amount_minor) AS total, COUNT(*) AS n FROM ledger_entries').get();
    view(res, s, '/accounts', 'Счета и карты', `
<p>Записей в регистре: ${ledger.n}. Сумма всех проводок: <b>${e(String(ledger.total ?? 0))}</b> (двойная запись: всегда 0).</p>
${table(['Счёт', 'Владелец', 'IBAN', 'Тип', 'Баланс'], rows.map((a) => [`<code>${e(a.id)}</code> ${e(a.name)}`, e(a.display_name ?? 'банк'), `<code>${e(a.iban)}</code>`, e(a.kind), money(a.balance_minor, a.currency)]))}
<h2>Карты</h2>${table(['Карта', 'Счёт', 'Срок', 'Статус'], cards.map((k) => [`${e(k.brand)} •••• ${e(k.last4)}`, `<code>${e(k.iban)}</code>`, e(k.expires), e(k.status)]))}`, 10);
  }

  function transactionsPage(res, s) {
    view(res, s, '/transactions', 'Транзакции', transactionsTable(db.prepare('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 200').all()), 5);
  }

  async function transactionPage(res, s, id, message = '') {
    const t = await payments.reconcile(id);
    if (!t) throw new BankError(404, 'NOT_FOUND', 'Транзакция не найдена');
    const events = transactionEvents(db, id);
    const reached = new Map();
    for (const ev of events) if (!reached.has(ev.type)) reached.set(ev.type, ev);
    const failed = ['FAILED', 'REJECTED', 'EXPIRED', 'CANCELLED'].includes(t.state);
    const authView = t.authorization_id ? await authCore.authorization(t.authorization_id) : null;
    const evidence = db.prepare('SELECT * FROM evidence WHERE transaction_id = ?').get(id);
    const receipt = db.prepare('SELECT body FROM receipts WHERE transaction_id = ?').get(id);
    const decision = reached.get('AUTHORIZATION_DECISION');
    const steps = TIMELINE.map(([type, label]) => {
      const ev = reached.get(type);
      const refused = type === 'AUTHORIZATION_DECISION' && ev?.detail.decision === 'REFUSED';
      const css = ev ? (refused ? 'bad' : 'ok') : failed ? '' : 'wait';
      return `<li><span class="dot ${css}"></span><span>${e(label)}${ev ? `<div class="note">${time(ev.at)} · ${e(ev.source)}</div>` : ''}</span><span class="mono">${ev ? e(JSON.stringify(ev.detail)) : '—'}</span></li>`;
    }).join('');
    const body = `${message ? `<div class="msg">${e(message)}</div>` : ''}
<p>${badge(t.state)} <code>${e(t.reference)}</code> · ${money(t.amount_minor, t.currency)} + комиссия ${money(t.fee_minor, t.currency)} → ${e(t.beneficiary_name)} <code>${e(t.beneficiary_iban)}</code>
${t.failure_reason ? `<br><span class="note">${e(t.failure_reason)}</span>` : ''}</p>
${t.state === 'AUTHORIZATION_PENDING' ? `<p><form class="inline" method="post" action="/transactions/${e(t.id)}/cancel">${csrfField(s)}<button class="secondary">Отменить</button></form>
<form class="inline" method="post" action="/transactions/${e(t.id)}/offline-code">${csrfField(s)} <input name="code" placeholder="офлайн-код с телефона" inputmode="numeric" size="16"> <button>Ввести код</button></form></p>` : ''}
<h2>Хронология (из событий банка и Auth Core)</h2><ul class="timeline">${steps}</ul>
${decision?.detail.decision === 'REFUSED' ? `<p class="msg">Банк отказал: ${e(decision.detail.code)}</p>` : ''}
<h2>Все события</h2>${table(['Время', 'Событие', 'Источник', 'Детали'], events.map((ev) => [time(ev.at), `<code>${e(ev.type)}</code>`, e(ev.source), `<span class="mono">${e(JSON.stringify(ev.detail))}</span>`]))}
<h2>Сессия авторизации (Auth Core, сейчас)</h2>${authView ? `<pre>${e(JSON.stringify(authView.json ?? authView.text, null, 2))}</pre>` : '<p class="note">Нет.</p>'}
<h2>Привязка транзакции</h2><p class="note">Условия, которые банк попросил подписать (и сравнил с подписанными байтами):</p><pre>${e(JSON.stringify(t.signed_terms ? JSON.parse(t.signed_terms) : null, null, 2))}</pre>
<p class="note">Хеш канонических байтов при создании: <code>${e(t.canonical_payload_hash ?? '—')}</code></p>
<h2>Доказательство</h2>${evidence ? `<p>${JSON.parse(evidence.problems).length === 0 ? badge('PASSED') : badge('FAILED')} запись №${e(String(evidence.chain_sequence ?? '—'))}, ключ печати <code>${e(evidence.seal_key_id ?? '—')}</code></p>
${JSON.parse(evidence.problems).length ? `<pre>${e(JSON.parse(evidence.problems).join('\n'))}</pre>` : ''}<details><summary>Запись целиком</summary><pre>${e(JSON.stringify(JSON.parse(evidence.record), null, 2))}</pre></details>` : '<p class="note">Ещё нет.</p>'}
<h2>Квитанция</h2>${receipt ? `<pre>${e(JSON.stringify(JSON.parse(receipt.body), null, 2))}</pre>` : '<p class="note">Квитанция формируется только после исполнения.</p>'}`;
    view(res, s, '/transactions', `Транзакция ${t.reference}`, body, ['AUTHORIZATION_PENDING', 'OFFLINE_PROVISIONAL', 'AUTHORIZING'].includes(t.state) && !message ? 3 : 0);
  }

  function authorizationsPage(res, s) {
    const rows = db.prepare("SELECT * FROM transactions WHERE authorization_id IS NOT NULL ORDER BY created_at DESC LIMIT 100").all();
    view(res, s, '/authorizations', 'Сессии авторизации', table(['Authorization ID', 'Референс', 'Создана', 'Истекает', 'Состояние в банке', 'Способ'], rows.map((t) => {
      const confirmed = db.prepare("SELECT detail FROM events WHERE transaction_id = ? AND type = 'CUSTOMER_CONFIRMED' LIMIT 1").get(t.id);
      return [`<a href="/transactions/${e(t.id)}"><code>${e(t.authorization_id)}</code></a>`, `<code>${e(t.reference)}</code>`, time(t.created_at), time(t.authorization_expires_at), badge(t.state), e(confirmed ? JSON.parse(confirmed.detail).confirmationMethod : '—')];
    })), 5);
  }

  function notificationsPage(res, s) {
    const rows = db.prepare('SELECT n.*, c.display_name FROM notifications n JOIN customers c ON c.id = n.customer_id ORDER BY n.created_at DESC LIMIT 200').all();
    view(res, s, '/notifications', 'Доставка уведомлений', `<p class="note">Push через APNs/FCM требует ключей Apple Developer / Firebase и в песочнице не настроен. Приложение получает запросы опросом банка; доставкой считается момент, когда приложение забрало запрос.</p>
${table(['Создано', 'Клиент', 'Тип', 'Текст', 'Состояние', 'Доставлено'], rows.map((n) => [time(n.created_at), e(n.display_name), e(n.kind), `${e(n.title)}<div class="note">${e(n.body)}</div>`, e(n.state), time(n.delivered_at)]))}`, 5);
  }

  function evidencePage(res, s) {
    const rows = db.prepare('SELECT e.*, t.reference FROM evidence e JOIN transactions t ON t.id = e.transaction_id ORDER BY e.received_at DESC LIMIT 100').all();
    const keys = db.prepare('SELECT * FROM evidence_keys').all();
    view(res, s, '/evidence', 'Доказательства', `<h2>Закреплённые ключи печати</h2>${table(['Key ID', 'Закреплён'], keys.map((k) => [`<code>${e(k.key_id)}</code>`, time(k.pinned_at)]), 'Ещё нет: ключ закрепляется при первой подтверждённой операции.')}
<h2>Полученные записи</h2>${table(['Получена', 'Транзакция', '№ в цепочке', 'Хеш', 'Проверка банком'], rows.map((r) => [time(r.received_at), `<a href="/transactions/${e(r.transaction_id)}"><code>${e(r.reference)}</code></a>`, e(String(r.chain_sequence ?? '—')), `<code>${e(r.evidence_hash.slice(0, 20))}…</code>`, JSON.parse(r.problems).length ? `${badge('FAILED')}<div class="note">${e(JSON.parse(r.problems)[0])}</div>` : badge('PASSED')]))}`);
  }

  function policiesPage(res, s) {
    view(res, s, '/policies', 'Политики', `<p class="note">Политика из <code>sandbox/config/bank.json</code>, версия <code>${e(config.bank.policy.version)}</code>. Изменение — правкой файла и перезапуском песочницы.</p><pre>${e(JSON.stringify(config.bank.policy, null, 2))}</pre>`);
  }

  function auditPage(res, s, url) {
    const type = url.searchParams.get('type') || undefined;
    const rows = recentEvents(db, { limit: 300, type });
    view(res, s, '/audit', 'Журнал аудита', `<form method="get" action="/audit">Тип события: <input name="type" value="${e(type ?? '')}"> <button class="secondary">Фильтр</button></form><br>
${table(['№', 'Время', 'Событие', 'Источник', 'Клиент', 'Транзакция', 'Детали'], rows.map((ev) => [String(ev.id), time(ev.at), `<code>${e(ev.type)}</code>`, e(ev.source), e(ev.customer_id ?? ''), ev.transaction_id ? `<a href="/transactions/${e(ev.transaction_id)}">→</a>` : '', `<span class="mono">${e(JSON.stringify(ev.detail))}</span>`]))}
<p class="note">Таблица событий только дописывается: триггеры базы запрещают изменение и удаление строк.</p>`, 10);
  }

  async function healthPage(res, s) {
    const health = await authCore.health();
    const ledger = db.prepare('SELECT COALESCE(SUM(amount_minor), 0) AS total FROM ledger_entries').get().total;
    const balances = db.prepare('SELECT COUNT(*) AS n FROM accounts a WHERE balance_minor <> (SELECT COALESCE(SUM(amount_minor), 0) FROM ledger_entries e WHERE e.account_id = a.id)').get().n;
    const rows = [
      ['Auth Core', health.ok ? badge('PASSED') : badge('FAILED'), `<code>${e(config.authCoreUrl)}</code> /readyz → ${e(health.status ?? health.error)}`],
      ['Ревизия Auth Core', '', `<code>${e(config.pinnedRevision)}</code>`],
      ['HSM', '', e(config.hsmDescription)],
      ['База банка', badge('PASSED'), `SQLite <code>${e(config.dbPath)}</code>`],
      ['Регистр: сумма проводок', ledger === 0 ? badge('PASSED') : badge('FAILED'), e(String(ledger))],
      ['Регистр: балансы = сумма проводок', balances === 0 ? badge('PASSED') : badge('FAILED'), `расхождений: ${balances}`],
      ['Внесение сбоев', faults.enabled ? badge('RUNNING').replace('RUNNING', 'включено') : badge('CANCELLED').replace('CANCELLED', 'выключено'), 'только в банке песочницы'],
      ['Банковский клиент', '', `<code>${e(config.bankClientId)}</code>`],
    ];
    view(res, s, '/health', 'Состояние системы', table(['Компонент', 'Статус', 'Детали'], rows), 10);
  }

  function scenariosPage(res, s, message = '') {
    const list = scenarios.list();
    view(res, s, '/scenarios', 'Сценарии', `${message ? `<div class="msg">${e(message)}</div>` : ''}
<p class="note">Сценарии выполняются тем же банковским сервисом и тем же Auth Core, что и приложение. Сторону клиента играет программное тест-устройство (ключи node:crypto), а не телефон. ${scenarios.isRunning() ? `Сейчас выполняется: <b>${e(scenarios.isRunning())}</b>.` : ''}</p>
${table(['Сценарий', 'Исходное состояние', 'Действие клиента', 'Ожидаемые события', 'Ожидаемый результат', 'Последний запуск', ''], list.map((sc) => [
      `<b>${e(sc.title)}</b><div class="note"><code>${e(sc.id)}</code></div>`, e(sc.initial), e(sc.action), `<span class="mono">${e(sc.events.join(' → '))}</span>`, e(sc.expected),
      sc.last ? `<a href="/scenarios/runs/${e(sc.last.id)}">${badge(sc.last.state)}</a><div class="note">${time(sc.last.started_at)}</div>` : '—',
      sc.available ? `<form method="post" action="/scenarios/${e(sc.id)}/run">${csrfField(s)}<button>Запустить</button></form>` : '<span class="badge muted">веха 4</span>',
    ]))}`, scenarios.isRunning() ? 3 : 0);
  }

  function runPage(res, s, runId) {
    const r = scenarios.getRun(runId);
    if (!r) throw new BankError(404, 'NOT_FOUND', 'Запуск не найден');
    view(res, s, '/scenarios', `Сценарий ${r.scenario}`, `<p>${badge(r.state)} начат ${time(r.started_at)}, завершён ${time(r.finished_at)}
${r.transaction_id ? ` · <a href="/transactions/${e(r.transaction_id)}">транзакция →</a>` : ''}</p>
<h2>Ожидалось</h2><p>${e(r.expected)}</p><h2>Фактически</h2><pre>${e(JSON.stringify(r.actual, null, 2))}</pre>
<h2>Шаги</h2>${table(['Время', 'Шаг'], r.steps.map((st) => [time(st.at), e(st.text)]))}<p><a href="/scenarios">← все сценарии</a></p>`, r.state === 'RUNNING' ? 2 : 0);
  }

  /** JSON API for automation (CI, scripts): HTTP Basic with the console credentials. */
  async function api(req, res, path) {
    const basic = /^Basic (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    const [user, ...rest] = basic ? Buffer.from(basic, 'base64').toString('utf8').split(':') : [];
    if (!basic || !same(user, config.console.username) || !same(rest.join(':'), config.console.password)) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="sandbox"' });
      return res.end();
    }
    let m;
    if (req.method === 'GET' && path === '/api/health') {
      const health = await authCore.health();
      return sendJson(res, health.ok ? 200 : 503, { authCore: health, pinnedRevision: config.pinnedRevision, hsm: config.hsmDescription });
    }
    if (req.method === 'POST' && path === '/api/customers') {
      const body = await readBody(req);
      try {
        return sendJson(res, 201, addCustomer(db, config.bank, body));
      } catch (error) {
        return sendJson(res, 400, { code: 'INVALID', error: error.message });
      }
    }
    if (req.method === 'GET' && path === '/api/scenarios') return sendJson(res, 200, scenarios.list().map(({ run, ...rest }) => rest));
    if (req.method === 'POST' && (m = /^\/api\/scenarios\/([^/]+)\/run$/.exec(path))) return sendJson(res, 202, { runId: await scenarios.run(m[1]) });
    if (req.method === 'GET' && (m = /^\/api\/scenarios\/runs\/([^/]+)$/.exec(path))) {
      const r = scenarios.getRun(m[1]);
      return r ? sendJson(res, 200, r) : sendJson(res, 404, { code: 'NOT_FOUND' });
    }
    if (req.method === 'GET' && (m = /^\/api\/transactions\/([^/]+)$/.exec(path))) {
      const t = await payments.reconcile(m[1]);
      return t ? sendJson(res, 200, { transaction: t, events: transactionEvents(db, m[1]) }) : sendJson(res, 404, { code: 'NOT_FOUND' });
    }
    if (req.method === 'POST' && (m = /^\/api\/transactions\/([^/]+)\/offline-code$/.exec(path))) {
      const body = await readBody(req);
      return sendJson(res, 200, await payments.offlineCode(m[1], body.code, 'CONSOLE'));
    }
    if (req.method === 'GET' && path === '/api/ledger/check') {
      const total = db.prepare('SELECT COALESCE(SUM(amount_minor), 0) AS total FROM ledger_entries').get().total;
      const mismatched = db.prepare('SELECT COUNT(*) AS n FROM accounts a WHERE balance_minor <> (SELECT COALESCE(SUM(amount_minor), 0) FROM ledger_entries e WHERE e.account_id = a.id)').get().n;
      return sendJson(res, 200, { total, mismatchedAccounts: mismatched, ok: total === 0 && mismatched === 0 });
    }
    throw new BankError(404, 'NOT_FOUND', 'Not found');
  }

  // --- Routing ---------------------------------------------------------------

  return async function handle(req, res) {
    const url = new URL(req.url, 'http://console');
    const path = url.pathname;
    if (req.method === 'GET' && path === '/healthz') return sendJson(res, 200, { ok: true });
    if (path === '/login') {
      if (req.method === 'GET') return sendHtml(res, 200, loginPage());
      const body = await readBody(req);
      if (!same(body.username ?? '', config.console.username) || !same(body.password ?? '', config.console.password)) {
        recordEvent(db, { type: 'CONSOLE_LOGIN_FAILED', source: 'CONSOLE', detail: { username: String(body.username ?? '').slice(0, 64) } });
        return sendHtml(res, 401, loginPage('Неверный пользователь или пароль'));
      }
      const token = randomBytes(32).toString('base64url');
      sessions.set(token, { csrf: randomBytes(16).toString('base64url'), expiresAt: Date.now() + SESSION_TTL_MS });
      recordEvent(db, { type: 'CONSOLE_LOGIN', source: 'CONSOLE', detail: { username: config.console.username } });
      res.writeHead(303, { Location: '/', 'Set-Cookie': `sbx_console=${token}; HttpOnly; SameSite=Strict; Path=/${config.console.secureCookies ? '; Secure' : ''}` });
      return res.end();
    }
    if (path.startsWith('/api/')) return api(req, res, path);
    const s = session(req);
    if (!s) { res.writeHead(303, { Location: '/login' }); return res.end(); }

    if (req.method === 'POST') {
      const body = await readBody(req);
      if (!same(body.csrf ?? '', s.csrf)) throw new BankError(403, 'CSRF', 'Форма устарела: обновите страницу');
      if (path === '/logout') { sessions.delete(s.token); res.writeHead(303, { Location: '/login' }); return res.end(); }
      let m;
      if ((m = /^\/transactions\/([^/]+)\/cancel$/.exec(path))) {
        let message = 'Операция отменена.';
        try { await payments.cancel(null, m[1], 'OTHER', 'CONSOLE'); } catch (error) { message = error.message; }
        return transactionPage(res, s, m[1], message);
      }
      if ((m = /^\/transactions\/([^/]+)\/offline-code$/.exec(path))) {
        let message;
        try {
          const r = await payments.offlineCode(m[1], body.code, 'CONSOLE');
          message = r.status === 'PROVISIONAL' ? 'Код принят: операция ждёт подпись телефона и не исполняется до неё.' : r.status === 'VERIFIED' ? 'Код принят, подпись получена.' : `Код не принят (${r.reason ?? r.status}).`;
        } catch (error) { message = error.message; }
        return transactionPage(res, s, m[1], message);
      }
      if ((m = /^\/customers\/([^/]+)\/verify-chain$/.exec(path))) return verifyChainPage(res, s, m[1]);
      if (path === '/customers/new') {
        try {
          const opening = Math.round(Number(String(body.opening ?? '0').replace(',', '.')) * 100);
          const created = addCustomer(db, config.bank, { login: body.login, displayName: body.displayName, openingMinor: opening });
          return customersPage(res, s, credentialsMessage(created.login, created.password, `Клиент ${created.displayName} создан`));
        } catch (error) {
          return customersPage(res, s, `<div class="msg">${e(error.message)}</div>`);
        }
      }
      if ((m = /^\/customers\/([^/]+)\/reset-password$/.exec(path))) {
        try {
          const reset = resetPassword(db, m[1]);
          return customersPage(res, s, credentialsMessage(reset.login, reset.password, 'Новый пароль выдан; прежний больше не действует'));
        } catch (error) {
          return customersPage(res, s, `<div class="msg">${e(error.message)}</div>`);
        }
      }
      if ((m = /^\/scenarios\/([^/]+)\/run$/.exec(path))) {
        try {
          const runId = await scenarios.run(m[1]);
          res.writeHead(303, { Location: `/scenarios/runs/${runId}` });
          return res.end();
        } catch (error) { return scenariosPage(res, s, error.message); }
      }
      throw new BankError(404, 'NOT_FOUND', 'Not found');
    }

    let m;
    if (path === '/') return overview(res, s);
    if (path === '/customers') return customersPage(res, s);
    if ((m = /^\/customers\/([^/]+)$/.exec(path))) return customerPage(res, s, m[1]);
    if (path === '/accounts') return accountsPage(res, s);
    if (path === '/transactions') return transactionsPage(res, s);
    if ((m = /^\/transactions\/([^/]+)$/.exec(path))) return transactionPage(res, s, m[1]);
    if (path === '/authorizations') return authorizationsPage(res, s);
    if (path === '/notifications') return notificationsPage(res, s);
    if (path === '/evidence') return evidencePage(res, s);
    if (path === '/policies') return policiesPage(res, s);
    if (path === '/audit') return auditPage(res, s, url);
    if (path === '/health') return healthPage(res, s);
    if (path === '/scenarios') return scenariosPage(res, s);
    if ((m = /^\/scenarios\/runs\/([^/]+)$/.exec(path))) return runPage(res, s, m[1]);
    throw new BankError(404, 'NOT_FOUND', 'Страница не найдена');
  };
}
