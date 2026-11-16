'use strict';

// One customer's mandates and devices, shown under the identity lookup.
// Auditors and platform operators read; the bank's own operators hold,
// release or withdraw a mandate, revoke a device and stop an open device
// request. Releasing a hold needs a second member of staff (the server
// refuses the one who placed it). Every value is escaped before display.
//
// Uses api(), escapeHtml(), badge(), formatTimestamp(), renderTable() and state from admin.js.

const customerPanel = { nexusId: null };

const canChange = () => state.session && ['operator', 'administrator'].includes(state.session.role) && state.session.clientId;
const money = (minor, currency) => `${(Number(minor) / 100).toFixed(2)} ${escapeHtml(currency)}`;

async function loadCustomerPanels(nexusId) {
  customerPanel.nexusId = nexusId;
  document.getElementById('customer-section').style.display = '';
  document.getElementById('customer-title').textContent = `Customer ${nexusId}`;
  document.getElementById('mandate-detail').innerHTML = '';
  await Promise.all([loadMandates(nexusId), loadDevices(nexusId)]);
}

async function loadMandates(nexusId) {
  const { mandates } = await api(`/admin/api/identities/${nexusId}/mandates`);
  const el = document.getElementById('mandates-table');
  renderTable(el, [
    { label: 'Reference', render: (m) => `<span class="mono">${escapeHtml(m.mandateReference)}</span>` },
    { label: 'Payee', render: (m) => escapeHtml(m.payee.name || '') },
    { label: 'Per payment', render: (m) => money(m.perPaymentLimitMinor, m.currency) },
    { label: 'Frequency', render: (m) => escapeHtml(m.frequency) },
    { label: 'Valid until', render: (m) => formatTimestamp(m.validUntil) },
    { label: 'State', render: (m) => badge(m.state) },
    { label: '', render: (m) => `<button class="ghost" data-mandate="${escapeHtml(m.mandateId)}">Details</button>` },
  ], mandates, 'No mandates for this customer.');
  for (const button of el.querySelectorAll('button[data-mandate]')) {
    button.addEventListener('click', () => showMandate(button.dataset.mandate).catch(reportError));
  }
}

async function showMandate(mandateId) {
  const { mandate: m, debits, evidence, events } = await api(`/admin/api/mandates/${mandateId}`);
  const el = document.getElementById('mandate-detail');
  const held = m.state === 'SUSPENDED' && (m.stateReason || '').startsWith('SUSPENDED_BY_BANK:');
  const actions = canChange() ? [
    m.state === 'ACTIVE' ? '<button class="ghost" data-mandate-action="hold">Hold</button>' : '',
    held ? '<button class="ghost" data-mandate-action="release">Release hold</button>' : '',
    ['PENDING_SIGNATURE', 'ACTIVE', 'SUSPENDED'].includes(m.state) ? '<button class="danger" data-mandate-action="withdraw">Withdraw (permanent)</button>' : '',
  ].join('') : '';
  el.innerHTML = `
    <h3 style="margin:12px 0 6px">Mandate <span class="mono">${escapeHtml(m.mandateReference)}</span> ${badge(m.state)}</h3>
    <table><tbody>
      <tr><td class="muted">Payee</td><td>${escapeHtml(m.payee.name || '')} · <span class="mono">${escapeHtml(m.payee.iban || '')}</span></td></tr>
      <tr><td class="muted">Limits</td><td>${money(m.perPaymentLimitMinor, m.currency)} per payment${m.totalLimitMinor ? `, ${money(m.totalLimitMinor, m.currency)} in total` : ''}; used ${money(m.usedTotalMinor, m.currency)}</td></tr>
      <tr><td class="muted">Validity</td><td>${formatTimestamp(m.validFrom)} – ${formatTimestamp(m.validUntil)}</td></tr>
      <tr><td class="muted">Signed</td><td>${formatTimestamp(m.signedAt)} by device <span class="mono">${escapeHtml(m.credentialId)}</span></td></tr>
      <tr><td class="muted">Terms hash</td><td class="mono">${escapeHtml(m.termsHash)}</td></tr>
      <tr><td class="muted">Reason</td><td>${escapeHtml(m.stateReason || '')}</td></tr>
    </tbody></table>
    <div class="identity-actions">${actions}</div>
    <h4>Debits</h4><div id="mandate-debits"></div>
    <h4>Event log</h4><div id="mandate-events"></div>
    <h4>Sealed evidence</h4><div id="mandate-evidence"></div>`;
  renderTable(document.getElementById('mandate-debits'), [
    { label: 'When', render: (d) => formatTimestamp(d.createdAt) },
    { label: 'Reference', render: (d) => `<span class="mono">${escapeHtml(d.debitReference)}</span>` },
    { label: 'Amount', render: (d) => money(d.amountMinor, d.currency) },
    { label: 'Period', render: (d) => escapeHtml(d.periodStart) },
    { label: 'Decision', render: (d) => `${badge(d.decision)} ${escapeHtml(d.reason || '')}` },
  ], debits, 'The bank has not asked for a debit.');
  renderTable(document.getElementById('mandate-events'), [
    { label: 'When', render: (e) => formatTimestamp(e.at) },
    { label: 'Event', render: (e) => escapeHtml(e.event) },
    { label: 'State', render: (e) => `${escapeHtml(e.from || '')} → ${escapeHtml(e.to || '')}` },
    { label: 'Reason', render: (e) => escapeHtml(e.reason || '') },
    { label: 'By', render: (e) => escapeHtml(e.actor || '') },
  ], events, 'No events.');
  renderTable(document.getElementById('mandate-evidence'), [
    { label: 'Chain #', render: (r) => escapeHtml(String(r.chainSequence)) },
    { label: 'Event', render: (r) => escapeHtml(r.sealedPayload.event || '') },
    { label: 'Evidence hash', render: (r) => `<span class="mono">${escapeHtml(String(r.evidenceHash || '').slice(0, 24))}…</span>` },
    { label: 'Sealed', render: (r) => formatTimestamp(r.createdAt) },
  ], evidence, 'No sealed records.');
  for (const button of el.querySelectorAll('[data-mandate-action]')) {
    button.addEventListener('click', () => mandateAction(mandateId, button.dataset.mandateAction).catch((e) => window.alert(e.message)));
  }
}

async function mandateAction(mandateId, action) {
  let body = {};
  if (action !== 'release') {
    const reason = window.prompt(`Reason to ${action} this mandate (written to the evidence):`);
    if (!reason) return;
    if (action === 'withdraw' && !window.confirm('Withdrawing ends the mandate for good. Continue?')) return;
    body = { reason };
  }
  await api(`/admin/api/mandates/${mandateId}/${action}`, { method: 'POST', body: JSON.stringify(body) });
  await loadMandates(customerPanel.nexusId);
  await showMandate(mandateId);
}

async function loadDevices(nexusId) {
  const view = await api(`/admin/api/identities/${nexusId}/devices`);
  document.getElementById('devices-limit').textContent = `Bank limit: ${view.maxDevicesPerIdentity} active device(s) per customer`;
  const devicesEl = document.getElementById('devices-table');
  renderTable(devicesEl, [
    { label: 'Device', render: (d) => `<span class="mono">${escapeHtml(d.credentialId.slice(0, 8))}…</span>` },
    { label: 'Platform', render: (d) => `${escapeHtml(d.platform)} · ${escapeHtml(d.securityLevel)}` },
    { label: 'Trust', render: (d) => badge(d.attestationStatus) },
    { label: 'Added', render: (d) => `${formatTimestamp(d.enrolledAt)} ${escapeHtml(d.enrolmentReason || '')}` },
    { label: 'Last used', render: (d) => formatTimestamp(d.lastUsedAt) },
    { label: 'State', render: (d) => badge(d.state) },
    { label: '', render: (d) => (canChange() && d.state === 'ACTIVE' ? `<button class="danger" data-revoke="${escapeHtml(d.credentialId)}">Revoke</button>` : '') },
  ], view.devices, 'No devices.');
  for (const button of devicesEl.querySelectorAll('button[data-revoke]')) {
    button.addEventListener('click', () => revokeDevice(nexusId, button.dataset.revoke).catch((e) => window.alert(e.message)));
  }
  const requestsEl = document.getElementById('device-requests-table');
  renderTable(requestsEl, [
    { label: 'Kind', render: (r) => escapeHtml(r.kind) },
    { label: 'Method', render: (r) => `${escapeHtml(r.method)} · ${escapeHtml(r.reference)}` },
    { label: 'Requested', render: (r) => formatTimestamp(r.requestedAt) },
    { label: 'Hold until', render: (r) => formatTimestamp(r.notBefore) },
    { label: 'State', render: (r) => badge(r.state) },
    { label: '', render: (r) => (canChange() && ['PENDING', 'APPROVED'].includes(r.state) ? `<button class="ghost" data-cancel="${escapeHtml(r.requestId)}">Stop</button>` : '') },
  ], view.requests, 'No device additions or replacements.');
  for (const button of requestsEl.querySelectorAll('button[data-cancel]')) {
    button.addEventListener('click', () => cancelRequest(nexusId, button.dataset.cancel).catch((e) => window.alert(e.message)));
  }
  renderTable(document.getElementById('device-events-table'), [
    { label: 'When', render: (e) => formatTimestamp(e.at) },
    { label: 'Event', render: (e) => escapeHtml(e.eventType) },
    { label: 'By', render: (e) => escapeHtml(e.actor || '') },
  ], view.securityEvents, 'No security events.');
}

async function revokeDevice(nexusId, credentialId) {
  const reason = window.prompt('Reason to revoke this device (written to the evidence):');
  if (!reason || !window.confirm('The device can no longer confirm payments; open payments addressed to it are cancelled. Continue?')) return;
  await api(`/admin/api/identities/${nexusId}/devices/${credentialId}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) });
  await loadDevices(nexusId);
}

async function cancelRequest(nexusId, requestId) {
  if (!window.confirm('Stop this device request? The customer must ask again.')) return;
  await api(`/admin/api/identities/${nexusId}/device-requests/${requestId}/cancel`, { method: 'POST', body: '{}' });
  await loadDevices(nexusId);
}
