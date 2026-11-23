import { escapeHtml as e } from '../http.mjs';

export const MODULES = [
  ['/', 'Обзор'],
  ['/customers', 'Клиенты'],
  ['/accounts', 'Счета и карты'],
  ['/transactions', 'Транзакции'],
  ['/authorizations', 'Сессии авторизации'],
  ['/notifications', 'Доставка уведомлений'],
  ['/evidence', 'Доказательства'],
  ['/policies', 'Политики'],
  ['/audit', 'Журнал аудита'],
  ['/health', 'Состояние системы'],
  ['/scenarios', 'Сценарии'],
];

const STATE_CLASS = {
  EXECUTED: 'ok', PASSED: 'ok', AUTHORIZATION_PENDING: 'wait', OFFLINE_PROVISIONAL: 'wait', AUTHORIZING: 'wait', CREATED: 'wait', RUNNING: 'wait',
  REJECTED: 'bad', EXPIRED: 'bad', CANCELLED: 'muted', FAILED: 'bad', NOT_AVAILABLE: 'muted',
};

export const badge = (state) => `<span class="badge ${STATE_CLASS[state] ?? 'muted'}">${e(state)}</span>`;

export function page({ title, path, body, branding, refresh = 0, csrf = '' }) {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
${refresh ? `<meta http-equiv="refresh" content="${refresh}">` : ''}
<title>${e(title)} · ${e(branding.name)} · консоль</title>
<style>
:root{--brand:${e(branding.primaryColor)};--ink:#14232f;--muted:#6a7b88;--line:#e2e9ee;--bg:#f5f8f9}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--ink);background:var(--bg)}
header{display:flex;align-items:center;gap:16px;padding:10px 20px;background:#0f2b33;color:#fff}
header b{font-size:15px}header .env{margin-left:auto;font-size:12px;padding:2px 8px;border:1px solid #f0b429;color:#f0b429;border-radius:10px}
.wrap{display:flex;min-height:calc(100vh - 44px)}nav{width:220px;background:#fff;border-right:1px solid var(--line);padding:12px 0}
nav a{display:block;padding:7px 18px;color:var(--ink);text-decoration:none}nav a.on{background:#e7f6f3;color:#0b6b5c;font-weight:600;border-left:3px solid var(--brand)}
main{flex:1;padding:18px 24px;max-width:1300px}h1{font-size:20px;margin:0 0 14px}h2{font-size:16px;margin:22px 0 8px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:8px}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{font-size:12px;color:var(--muted);font-weight:600;background:#fafcfd}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}.ok{background:#dcf5ea;color:#11683f}.wait{background:#fff3d1;color:#8a5a00}.bad{background:#fde2e1;color:#a02018}.muted{background:#edf0f2;color:#5b6872}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px 14px}.card .n{font-size:22px;font-weight:700}
.timeline{list-style:none;padding:0;margin:0;background:#fff;border:1px solid var(--line);border-radius:8px}
.timeline li{display:grid;grid-template-columns:28px 260px minmax(0,1fr);gap:8px;padding:8px 12px;border-bottom:1px solid var(--line)}
.dot{width:12px;height:12px;border-radius:6px;margin-top:4px;background:#cfd8de}.dot.ok{background:#21a67a}.dot.bad{background:#d64541}.dot.wait{background:#f0b429}
pre{background:#0f1d24;color:#d7e6ee;padding:12px;border-radius:8px;overflow:auto;max-height:420px;font-size:12px}
form.inline{display:inline}button,.btn{background:var(--brand);color:#fff;border:0;border-radius:6px;padding:6px 12px;font-weight:600;cursor:pointer}
button.secondary{background:#e7eef2;color:var(--ink)}input,select{padding:5px 8px;border:1px solid #c7d3db;border-radius:6px}
.note{color:var(--muted);font-size:12px}.msg{background:#fff7e0;border:1px solid #f3d98b;padding:8px 12px;border-radius:6px;margin-bottom:12px}
</style></head><body>
<header><b>${e(branding.name)}</b><span>Консоль банка · NEXUS-SIGN</span><span class="env">ПЕСОЧНИЦА · тестовые средства</span>
${csrf ? `<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="${e(csrf)}"><button class="secondary">Выйти</button></form>` : ''}</header>
<div class="wrap"><nav>${MODULES.map(([href, label]) => `<a href="${href}" class="${href === path || (href !== '/' && path.startsWith(href)) ? 'on' : ''}">${e(label)}</a>`).join('')}</nav>
<main><h1>${e(title)}</h1>${body}</main></div></body></html>`;
}

export function table(headers, rows, empty = 'Нет данных.') {
  return `<table><tr>${headers.map((h) => `<th>${e(h)}</th>`).join('')}</tr>${rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${headers.length}" class="note">${e(empty)}</td></tr>`}</table>`;
}

export const time = (iso) => (iso ? e(String(iso).replace('T', ' ').slice(0, 19)) : '—');
