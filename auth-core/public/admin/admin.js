'use strict';

// Operator console served by Auth Core. Plain DOM, no build step.

const state = {
  session: null, // { username, role, clientId }
};

// --- Fetch helper ---

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    credentials: 'same-origin',
  });
  if (response.status === 401 && path !== '/admin/api/login') {
    showLogin();
    throw new Error('Session expired');
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `Request failed (HTTP ${response.status})`);
  }
  return body;
}

// --- Screen switching ---

function showLogin() {
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('app-header').style.display = 'none';
  document.getElementById('app-main').classList.remove('visible');
}

function showApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app-header').style.display = 'flex';
  document.getElementById('app-main').classList.add('visible');
  document.getElementById('who').textContent = `${state.session.username} · ${state.session.role} · ${state.session.clientId ? `bank ${state.session.clientId}` : 'all banks'}`;
}

// --- Formatting helpers ---

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** Escapes text for element content and for quoted attribute values. */
function escapeHtml(value) {
  return (value === null || value === undefined ? '' : String(value)).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

function badge(status) {
  const text = escapeHtml(status);
  const kind = /^[A-Z_]+$/.test(String(status)) ? String(status) : 'UNKNOWN';
  return `<span class="badge ${kind}">${text}</span>`;
}

function formatTimestamp(iso) {
  if (!iso) return '<span class="muted">—</span>';
  const date = new Date(iso);
  return date.toLocaleString();
}

function renderTable(container, columns, rows, emptyMessage) {
  if (rows.length === 0) {
    container.innerHTML = `<div class="empty-state">${escapeHtml(emptyMessage)}</div>`;
    return;
  }
  const head = columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join('');
  const body = rows
    .map((row) => `<tr>${columns.map((c) => `<td>${c.render(row)}</td>`).join('')}</tr>`)
    .join('');
  container.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

// --- Login ---

document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const errorEl = document.getElementById('login-error');
  errorEl.textContent = '';
  try {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const totp = document.getElementById('totp').value.trim();
    await api('/admin/api/login', { method: 'POST', body: JSON.stringify({ username, password, ...(totp ? { totp } : {}) }) });
    document.getElementById('password').value = '';
    document.getElementById('totp').value = '';
    state.session = await api('/admin/api/me');
    showApp();
    await loadEverything();
  } catch (error) {
    errorEl.textContent = error.message;
  }
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  await api('/admin/api/logout', { method: 'POST' }).catch(() => {});
  state.session = null;
  showLogin();
});

// --- Stats ---

function renderStats(stats) {
  const cards = [
    { label: 'Identities by status', rows: stats.identitiesByStatus },
    { label: 'Authorizations (24h)', rows: stats.authorizationsLast24hByStatus },
    { label: 'Webhook deliveries (24h)', rows: stats.webhookDeliveriesLast24hByStatus },
  ];
  document.getElementById('stats').innerHTML = cards
    .map(
      (card) => `
        <div class="stat-card">
          <div class="label">${escapeHtml(card.label)}</div>
          <div class="rows">
            ${
              Object.keys(card.rows).length === 0
                ? '<div class="muted">No data</div>'
                : Object.entries(card.rows)
                    .map(([key, value]) => `<div><span>${escapeHtml(key)}</span><span>${escapeHtml(value)}</span></div>`)
                    .join('')
            }
          </div>
        </div>`,
    )
    .join('');
}

// --- Clients ---

async function loadClients() {
  const clients = await api('/admin/api/clients');
  renderTable(
    document.getElementById('clients-table'),
    [
      { label: 'Client ID', render: (r) => `<span class="mono">${escapeHtml(r.clientId)}</span>` },
      { label: 'Status', render: (r) => badge(r.status) },
      { label: 'Webhook configured', render: (r) => (r.hasWebhook ? 'Yes' : '—') },
      { label: 'Push', render: (r) => (r.pushMode === 'NEXUS' ? 'NEXUS-SIGN secure push' : 'Bank push system') },
      { label: 'Client certificates', render: (r) => escapeHtml(r.certificateCount) },
      { label: 'Created', render: (r) => formatTimestamp(r.createdAt) },
    ],
    clients,
    'No bank clients registered yet.',
  );
}

// --- Audit log ---

async function loadAuditLogs() {
  const nexusId = document.getElementById('audit-nexus-filter').value.trim();
  const eventType = document.getElementById('audit-event-filter').value.trim();
  const params = new URLSearchParams();
  if (nexusId) params.set('nexusId', nexusId);
  if (eventType) params.set('eventType', eventType);
  const logs = await api(`/admin/api/audit-logs?${params.toString()}`);
  renderTable(
    document.getElementById('audit-table'),
    [
      { label: 'Time', render: (r) => formatTimestamp(r.timestamp) },
      { label: 'Event', render: (r) => escapeHtml(r.eventType) },
      { label: 'nexus_id', render: (r) => `<span class="mono">${escapeHtml(r.nexusId || '—')}</span>` },
      { label: 'Bank', render: (r) => `<span class="mono">${escapeHtml(r.clientId || '—')}</span>` },
      { label: 'Actor', render: (r) => `<span class="mono">${escapeHtml(r.actor || '—')}</span>` },
      { label: 'Details', render: (r) => `<span class="mono">${escapeHtml(JSON.stringify(r.details))}</span>` },
    ],
    logs,
    'No matching audit events.',
  );
}

document.getElementById('audit-filter-btn').addEventListener('click', () => loadAuditLogs().catch(reportError));

// --- Webhook deliveries ---

async function loadWebhookDeliveries() {
  const status = document.getElementById('webhook-status-filter').value;
  const params = new URLSearchParams();
  if (status) params.set('status', status);
  const deliveries = await api(`/admin/api/webhook-deliveries?${params.toString()}`);
  renderTable(
    document.getElementById('webhook-table'),
    [
      { label: 'Created', render: (r) => formatTimestamp(r.createdAt) },
      { label: 'Client', render: (r) => `<span class="mono">${escapeHtml(r.clientId)}</span>` },
      { label: 'Event', render: (r) => escapeHtml(r.eventType) },
      { label: 'Status', render: (r) => badge(r.status) },
      { label: 'Retries', render: (r) => escapeHtml(r.retryCount) },
      { label: 'Last error', render: (r) => `<span class="muted">${escapeHtml(r.lastError || '—')}</span>` },
    ],
    deliveries,
    'No webhook deliveries recorded.',
  );
}

document.getElementById('webhook-filter-btn').addEventListener('click', () => loadWebhookDeliveries().catch(reportError));

// --- Identity lookup ---

async function lookupIdentity() {
  const nexusId = document.getElementById('identity-search-input').value.trim();
  const resultEl = document.getElementById('identity-result');
  if (!/^\d{9}$/.test(nexusId)) {
    resultEl.classList.add('visible');
    resultEl.innerHTML = '<div class="muted">Enter a 9-digit nexus_id.</div>';
    return;
  }

  try {
    const identity = await api(`/admin/api/identities/${nexusId}`);
    const canAct = state.session.role === 'operator' || state.session.role === 'administrator';

    resultEl.classList.add('visible');
    resultEl.innerHTML = `
      <table>
        <tbody>
          <tr><td class="muted">nexus_id</td><td class="mono">${escapeHtml(identity.nexusId)}</td></tr>
          <tr><td class="muted">bank_customer_ref</td><td class="mono">${escapeHtml(identity.bankCustomerRef)}</td></tr>
          <tr><td class="muted">Status</td><td>${badge(identity.status)}</td></tr>
          <tr><td class="muted">Created</td><td>${formatTimestamp(identity.createdAt)}</td></tr>
          <tr><td class="muted">Last used</td><td>${formatTimestamp(identity.lastUsedAt)}</td></tr>
        </tbody>
      </table>
      ${
        canAct
          ? `<div class="identity-actions">
              ${identity.status === 'ACTIVE' ? '<button class="ghost" data-action="suspend">Suspend</button>' : ''}
              ${identity.status === 'SUSPENDED' ? '<button class="ghost" data-action="reactivate">Reactivate</button>' : ''}
              ${identity.status !== 'REVOKED' ? '<button class="danger" data-action="revoke">Revoke (permanent)</button>' : ''}
            </div>`
          : ''
      }
    `;

    if (canAct) {
      resultEl.querySelectorAll('[data-action]').forEach((button) => {
        button.addEventListener('click', () => handleIdentityAction(nexusId, button.dataset.action));
      });
    }
  } catch (error) {
    resultEl.classList.add('visible');
    resultEl.innerHTML = `<div class="muted">${escapeHtml(error.message)}</div>`;
  }
}

async function handleIdentityAction(nexusId, action) {
  const reason = window.prompt(`Reason for "${action}" on ${nexusId}:`);
  if (!reason) return;
  if (action === 'revoke' && !window.confirm('This requests permanent revocation of the identity and its credentials. A second admin must approve it. Continue?')) return;

  try {
    const result = await api(`/admin/api/identities/${nexusId}/${action}`, { method: 'POST', body: JSON.stringify({ reason }) });
    if (result.status === 'PENDING') window.alert('Request recorded. It takes effect when a second admin approves it.');
    await lookupIdentity();
    await Promise.all([loadStats(), loadApprovals()]);
  } catch (error) {
    window.alert(error.message);
  }
}

document.getElementById('identity-search-btn').addEventListener('click', () => lookupIdentity().catch(reportError));

// --- Four-eyes approvals ---

async function loadApprovals() {
  const approvals = await api('/admin/api/approvals');
  const canAct = state.session.role === 'operator' || state.session.role === 'administrator';
  const container = document.getElementById('approvals-table');
  renderTable(
    container,
    [
      { label: 'Requested', render: (r) => formatTimestamp(r.requestedAt) },
      { label: 'Action', render: (r) => badge(r.action) },
      { label: 'nexus_id', render: (r) => `<span class="mono">${escapeHtml(r.nexusId)}</span>` },
      { label: 'Bank', render: (r) => `<span class="mono">${escapeHtml(r.clientId)}</span>` },
      { label: 'Requested by', render: (r) => escapeHtml(r.requestedBy) },
      { label: 'Reason', render: (r) => escapeHtml(r.reason) },
      { label: 'Expires', render: (r) => formatTimestamp(r.expiresAt) },
      {
        label: '',
        render: (r) => (!canAct ? '' : r.requestedBy === state.session.username
          ? `<button class="ghost" data-approval="${escapeHtml(r.approvalId)}" data-decision="reject">Withdraw</button>`
          : `<button class="danger" data-approval="${escapeHtml(r.approvalId)}" data-decision="approve">Approve</button>
             <button class="ghost" data-approval="${escapeHtml(r.approvalId)}" data-decision="reject">Reject</button>`),
      },
    ],
    approvals,
    'No requests waiting for approval.',
  );
  container.querySelectorAll('[data-approval]').forEach((button) => {
    button.addEventListener('click', () => decideApproval(button.dataset.approval, button.dataset.decision));
  });
}

async function decideApproval(approvalId, decision) {
  if (decision === 'approve' && !window.confirm('Approving executes the action now. Continue?')) return;
  try {
    await api(`/admin/api/approvals/${encodeURIComponent(approvalId)}/${decision}`, { method: 'POST' });
    await Promise.all([loadApprovals(), loadStats(), loadAuditLogs()]);
  } catch (error) {
    window.alert(error.message);
  }
}

document.getElementById('approvals-refresh-btn').addEventListener('click', () => loadApprovals().catch(reportError));

// --- Startup ---

async function loadStats() {
  renderStats(await api('/admin/api/stats'));
}

async function loadEverything() {
  await Promise.all([loadStats(), loadApprovals(), loadClients(), loadAuditLogs(), loadWebhookDeliveries()]);
}

function reportError(error) {
  // eslint-disable-next-line no-console
  console.error(error);
}

(async function init() {
  try {
    state.session = await api('/admin/api/me');
    showApp();
    await loadEverything();
  } catch {
    showLogin();
  }
})();
