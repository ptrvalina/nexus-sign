'use strict';

// The browser plays the customer's phone. It follows the same rules as the
// mobile SDKs: verify the canonical bytes, display only what is in them, sign
// exactly those bytes with a key that never leaves the device.

const $ = (s) => document.querySelector(s);

const PROTOCOL = {
  version: '1',
  domain: 'NEXUS-SIGN/TRANSACTION-AUTH',
  fields: ['amount_minor', 'authorization_id', 'beneficiary', 'credential_id', 'currency', 'domain', 'expires_at',
    'issued_at', 'nexus_id', 'nonce', 'operation_type', 'policy_reference', 'policy_version', 'protocol_version',
    'transaction_reference'],
  envelope: {
    authorizationId: 'authorization_id', nexusId: 'nexus_id', credentialId: 'credential_id',
    transactionReference: 'transaction_reference', operationType: 'operation_type', amountMinor: 'amount_minor',
    currency: 'currency', beneficiary: 'beneficiary', policyReference: 'policy_reference',
    policyVersion: 'policy_version', issuedAt: 'issued_at', expiresAt: 'expires_at',
  },
};
const STEP_TEXT = {
  PUSH: 'Bank-branded push to the enrolled device',
  AUDIO: 'Voice verification (simulated provider, signed callback)',
  VIDEO: 'Video verification (simulated provider, signed callback)',
  SIGNATURE: 'Device signs the exact canonical payload',
  VERIFY: 'ECDSA P-256 verification against the enrolled key',
  COMMIT: 'Bank commit (simulated core banking)',
};
const ZERO_DECIMALS = new Set(['BIF', 'CLP', 'DJF', 'GNF', 'ISK', 'JPY', 'KMF', 'KRW', 'PYG', 'RWF', 'UGX', 'UYI', 'VND', 'VUV', 'XAF', 'XOF', 'XPF']);
const THREE_DECIMALS = new Set(['BHD', 'IQD', 'JOD', 'KWD', 'LYD', 'OMR', 'TND']);
const FOUR_DECIMALS = new Set(['CLF', 'UYW']);
// Same rule as Auth Core and the SDKs.
const DISPLAY_UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const fractionDigits = (c) => (ZERO_DECIMALS.has(c) ? 0 : THREE_DECIMALS.has(c) ? 3 : FOUR_DECIMALS.has(c) ? 4 : 2);

const device = { keyPair: null, credentialId: null, nexusId: null };
let auth = null; // latest server view of the current authorization
let signed = null; // fields parsed from the verified canonical bytes
let lastValidSignature = null; // for the replay demonstration
let busy = false;

// --- Encoding helpers ---

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]));
  }
  return value;
}
const canonicalBytes = (obj) => new TextEncoder().encode(JSON.stringify(sortKeys(obj)));
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const bytesToB64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

function formatMinor(amountMinor, digits) {
  if (!/^(0|[1-9][0-9]{0,29})$/.test(amountMinor)) throw new Error('invalid amount');
  if (digits <= 0) return amountMinor;
  const padded = amountMinor.padStart(digits + 1, '0');
  return `${padded.slice(0, -digits)}.${padded.slice(-digits)}`;
}

function toMinor(input, currency) {
  const digits = fractionDigits(currency);
  const text = input.trim().replace(/[ _]/g, '').replace(',', '.');
  const m = /^(\d{1,28})(?:\.(\d+))?$/.exec(text);
  if (!m || (m[2] || '').length > digits) throw new Error(`Amount must be a number with at most ${digits} decimals for ${currency}`);
  const minor = (m[1] + (m[2] || '').padEnd(digits, '0')).replace(/^0+(?=\d)/, '');
  if (minor === '0') throw new Error('Amount must be greater than zero');
  return minor;
}

// --- What you see is what you sign ---

class Rejected extends Error {
  constructor(reason, detail) { super(`${reason}: ${detail}`); this.reason = reason; }
}

function parseSignedPayload(bytes) {
  let obj;
  try {
    obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (e) {
    throw new Rejected('invalid_json', e.message);
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Rejected('invalid_json', 'top level is not an object');
  // Duplicate keys, whitespace, escapes and key order all change the re-encoding.
  if (!sameBytes(canonicalBytes(obj), bytes)) throw new Rejected('not_canonical', 'bytes are not in canonical form');
  const keys = Object.keys(obj);
  const missing = PROTOCOL.fields.filter((f) => !keys.includes(f));
  if (missing.length) throw new Rejected('missing_field', missing.join(', '));
  const extra = keys.filter((k) => !PROTOCOL.fields.includes(k));
  if (extra.length) throw new Rejected('unexpected_field', extra.join(', '));
  for (const f of PROTOCOL.fields) {
    if (f === 'beneficiary') continue;
    if (typeof obj[f] !== 'string') throw new Rejected('invalid_value', `${f} must be a string`);
  }
  const b = obj.beneficiary;
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw new Rejected('invalid_value', 'beneficiary');
  for (const [k, v] of Object.entries(b)) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(k) || typeof v !== 'string') throw new Rejected('invalid_value', 'beneficiary');
    if (DISPLAY_UNSAFE.test(v)) throw new Rejected('invalid_value', `beneficiary.${k} contains a control, format or separator character`);
  }
  for (const f of PROTOCOL.fields) {
    if (f !== 'beneficiary' && DISPLAY_UNSAFE.test(obj[f])) throw new Rejected('invalid_value', `${f} contains a control, format or separator character`);
  }
  if (obj.protocol_version !== PROTOCOL.version || obj.domain !== PROTOCOL.domain) throw new Rejected('wrong_protocol', 'protocol/domain');
  if (!/^(0|[1-9][0-9]{0,29})$/.test(obj.amount_minor)) throw new Rejected('invalid_value', 'amount_minor');
  if (!/^[A-Z]{3}$/.test(obj.currency)) throw new Rejected('invalid_value', 'currency');
  const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
  if (!timestamp.test(obj.issued_at) || !timestamp.test(obj.expires_at)) throw new Rejected('invalid_value', 'issued_at/expires_at');
  if (!(Date.parse(obj.expires_at) > Date.parse(obj.issued_at))) throw new Rejected('invalid_value', 'expires_at is not after issued_at');
  return obj;
}

async function verifyEnvelope(envelope) {
  const bytes = b64ToBytes(envelope.canonicalPayloadBase64);
  const fields = parseSignedPayload(bytes);
  const digest = hex(await crypto.subtle.digest('SHA-256', bytes));
  if (digest !== String(envelope.canonicalPayloadHash).toLowerCase()) throw new Rejected('response_mismatch', 'canonicalPayloadHash');
  for (const [field, key] of Object.entries(PROTOCOL.envelope)) {
    const shown = field === 'beneficiary' ? JSON.stringify(sortKeys(envelope[field])) : envelope[field];
    const actual = field === 'beneficiary' ? JSON.stringify(sortKeys(fields[key])) : fields[key];
    if (shown !== actual) throw new Rejected('response_mismatch', field);
  }
  return { fields, bytes, digest };
}

// --- Server calls ---

async function api(path, { method = 'GET', body, headers = {} } = {}) {
  const response = await fetch(path, {
    method, headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  if (response.status === 401 && !path.startsWith('/api/v1/session')) {
    showLogin('Your session has ended. Sign in again.');
  }
  if (!response.ok) {
    const err = new Error(json.detail ? `${json.error}: ${json.detail}` : json.error || `HTTP ${response.status}`);
    err.status = response.status;
    err.code = json.error;
    throw err;
  }
  return json;
}

async function enrol() {
  device.keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  // Key-agreement key for offline confirmation (the SDKs keep it in hardware).
  device.offlineKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const spki = await crypto.subtle.exportKey('spki', device.keyPair.publicKey);
  const offlineSpki = await crypto.subtle.exportKey('spki', device.offlineKeyPair.publicKey);
  const result = await api('/api/v1/devices', {
    method: 'POST',
    body: { publicKeySpkiBase64: bytesToB64(spki), offlinePublicKeySpkiBase64: bytesToB64(offlineSpki), label: 'Browser device (WebCrypto)' },
  });
  device.credentialId = result.credentialId;
  device.nexusId = result.nexusId;
  device.offlineServerKey = await crypto.subtle.importKey('spki', b64ToBytes(result.offlineServerPublicKeySpkiBase64),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  $('#deviceInfo').textContent = `NEXUS ID ${result.nexusId} · P-256 key, non-extractable · credential ${result.credentialId.slice(0, 8)}…`;
  $('#create').disabled = false;
}

async function signBytes(bytes) {
  return bytesToB64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, device.keyPair.privateKey, bytes));
}

// --- Offline confirmation (device protocols v1, same as the SDKs) ---

const utf8 = (text) => new TextEncoder().encode(text);

function qrBytes(qrPayload) {
  if (!qrPayload.startsWith('NXS1.')) throw new Rejected('invalid_qr', 'unknown QR format');
  const b64 = qrPayload.slice(5).replace(/-/g, '+').replace(/_/g, '/');
  return b64ToBytes(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
}

/** ECDH -> HKDF-SHA256 -> HMAC-SHA256 over the payload hash -> 8 digits. */
async function offlineCode(bytes) {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: device.offlineServerKey }, device.offlineKeyPair.privateKey, 256);
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const key = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8('NEXUS-SIGN/OFFLINE/v1'), info: utf8(device.credentialId) }, ikm, 256);
  const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const domain = utf8('NEXUS-SIGN/OFFLINE-CODE/v1');
  const message = new Uint8Array(domain.length + 1 + digest.length);
  message.set(domain, 0);
  message.set(digest, domain.length + 1);
  const tag = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, message));
  const offset = tag[31] & 0x0f;
  const binary = ((tag[offset] & 0x7f) * 2 ** 24) + (tag[offset + 1] << 16) + (tag[offset + 2] << 8) + tag[offset + 3];
  return String(binary % 100000000).padStart(8, '0');
}

async function submitOfflineCode(code, label) {
  const result = await api(`/api/v1/authorizations/${auth.authorizationId}/offline-confirmation`, { method: 'POST', body: { code } });
  await loadAuthorization(result.authorization);
  if (result.status === 'VERIFIED') {
    notice(`${label}: code ${code} accepted by the server.`, 'good');
  } else {
    notice(`${label}: code ${code} rejected (${result.reason}), attempt ${result.attempts}/${result.authorization.maxSignatureAttempts}.`, 'bad');
  }
  return result;
}

async function confirmOffline() {
  // Bank screen: show the QR code for this authorization.
  const challenge = await api(`/api/v1/authorizations/${auth.authorizationId}/offline-challenge`);
  // Whole pixels per module keep the code sharp enough for a phone camera.
  const modules = Number(/viewBox="0 0 (\d+)/.exec(challenge.qrSvg)?.[1] ?? 0);
  const px = modules ? modules * Math.max(3, Math.floor(360 / modules)) : 320;
  const img = $('#qrImage');
  img.style.width = img.style.height = `${px}px`;
  img.src = `data:image/svg+xml;base64,${btoa(challenge.qrSvg)}`;
  $('#codeInput').value = '';
  $('#bankScreen').hidden = false;

  // Device, without network: read the QR, apply the same strict checks as
  // online, show the transaction and the code. (A phone reads the payload
  // with its camera; here the browser is the phone and reads it directly.)
  const bytes = qrBytes(challenge.qrPayload);
  const fields = parseSignedPayload(bytes);
  if (fields.credential_id !== device.credentialId) throw new Rejected('wrong_device', 'the QR code is for another device');
  signed = { fields, bytes, digest: hex(await crypto.subtle.digest('SHA-256', bytes)) };
  $('#wysiwys').textContent = 'QR VERIFIED OFFLINE';
  renderDevice();
  const code = await offlineCode(bytes);
  $('#offlineCode').textContent = code.replace(/(\d{4})(\d{4})/, '$1 $2');
  notice('The device read the QR code without network and shows an 8-digit code. Enter it on the bank screen.');
  $('#codeInput').focus();
}

async function submitBankScreenCode() {
  const code = $('#codeInput').value.replace(/\s/g, '');
  if (!/^\d{8}$/.test(code)) throw new Error('Enter the 8 digits shown on the device.');
  const result = await submitOfflineCode(code, 'Code entered on the bank screen');
  if (result.status === 'VERIFIED' || result.reason === 'signature_attempt_limit') $('#bankScreen').hidden = true;
}

// --- Rendering ---

function notice(text, kind = '') {
  const el = $('#notice');
  el.textContent = text;
  el.className = `notice ${kind}`;
}

function pendingStep() {
  return auth?.verificationPlan.steps.find((s) => s.status === 'PENDING') || null;
}

function renderFlow() {
  const flow = $('#flow');
  flow.replaceChildren();
  const steps = auth?.verificationPlan.steps || [];
  const current = pendingStep();
  steps.forEach((s, i) => {
    const row = document.createElement('div');
    const done = s.status === 'COMPLETED';
    const active = s === current && auth.state === 'PENDING';
    row.className = `flowrow ${done ? 'done' : active ? 'active' : ''} ${s.status === 'FAILED' || s.status === 'TIMED_OUT' ? 'failed' : ''}`;
    const num = document.createElement('b');
    num.textContent = String(i + 1).padStart(2, '0');
    const text = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = s.factor;
    const small = document.createElement('small');
    small.textContent = STEP_TEXT[s.factor] || '';
    text.append(title, small);
    const status = document.createElement('em');
    status.textContent = done ? 'COMPLETE' : s.status === 'PENDING' ? (active ? 'CURRENT' : 'PENDING') : s.status.replace('_', ' ');
    row.append(num, text, status);
    flow.append(row);
  });
  $('#state').textContent = auth ? `${auth.state}${auth.terminalReason && auth.terminalReason !== auth.state ? ` · ${auth.terminalReason}` : ''}` : 'IDLE';
  const open = auth && ['PENDING', 'VERIFIED'].includes(auth.state);
  const advance = $('#advance');
  advance.disabled = !open || busy;
  advance.textContent = !open ? 'Advance control point'
    : auth.state === 'VERIFIED' ? 'Commit at bank'
    : current?.factor === 'SIGNATURE' ? 'Approve on device (sign)' : `Run ${current?.factor}`;
  $('#clock').disabled = !auth || busy;
  $('#offline').disabled = !(auth?.state === 'PENDING' && current?.factor === 'SIGNATURE') || busy;
  document.querySelectorAll('.faultbar button').forEach((b) => { b.disabled = !open || busy; });
}

// Same order as the SDKs: well-known keys first, the rest sorted.
const PREFERRED_BENEFICIARY_KEYS = ['name', 'iban', 'account', 'account_number', 'bic'];
function beneficiaryDisplay(b) {
  const keys = [...PREFERRED_BENEFICIARY_KEYS.filter((k) => k in b), ...Object.keys(b).filter((k) => !PREFERRED_BENEFICIARY_KEYS.includes(k)).sort()];
  return keys.map((k) => b[k]).filter((v) => v.trim()).join(' · ');
}

function renderDevice() {
  const set = (id, v) => { $(id).textContent = v; };
  if (!signed) {
    ['#money', '#op', '#ref', '#nexus', '#auth', '#policyRef', '#expires', '#hash'].forEach((id) => set(id, '—'));
    set('#beneficiaryView', auth ? 'Payload rejected — nothing will be signed' : 'No authorization yet');
    set('#offlineCode', '—');
    return;
  }
  const f = signed.fields;
  set('#money', `${formatMinor(f.amount_minor, fractionDigits(f.currency))} ${f.currency}`);
  set('#beneficiaryView', beneficiaryDisplay(f.beneficiary));
  set('#op', f.operation_type);
  set('#ref', f.transaction_reference);
  set('#nexus', f.nexus_id.replace(/(\d{3})(?=\d)/g, '$1 '));
  set('#auth', `${f.authorization_id.slice(0, 8)}…`);
  set('#policyRef', `${f.policy_reference} / ${f.policy_version}`);
  set('#expires', f.expires_at.slice(11, 19) + ' UTC');
  set('#hash', `${signed.digest.slice(0, 16)}…`);
}

async function loadAuthorization(view) {
  if (view.authorizationId !== auth?.authorizationId) {
    $('#offlineCode').textContent = '—';
    $('#bankScreen').hidden = true;
  }
  auth = view;
  try {
    signed = await verifyEnvelope(view);
    $('#wysiwys').textContent = 'PAYLOAD VERIFIED';
  } catch (e) {
    signed = null;
    $('#wysiwys').textContent = 'REFUSED';
    notice(`Device refused to display or sign: ${e.message}`, 'bad');
  }
  renderDevice();
  renderFlow();
}

function renderEvents(events) {
  const list = $('#events');
  list.replaceChildren(...events.map((e) => {
    const row = document.createElement('div');
    row.className = 'event';
    const time = document.createElement('time');
    time.textContent = e.timestamp.slice(11, 19);
    const msg = document.createElement('span');
    msg.className = /^[A-Z]+$/.test(e.kind) ? e.kind : '';
    msg.textContent = e.message;
    row.append(time, msg);
    return row;
  }));
  $('#count').textContent = `${events.length} events`;
}

async function refresh() {
  const state = await api('/api/v1/state');
  renderEvents(state.events);
  const records = state.evidence.filter((r) => !auth || r.authorizationId === auth.authorizationId);
  if (records.length) $('#evidence').textContent = JSON.stringify(records[records.length - 1], null, 2);
  if (auth) {
    const latest = await api(`/api/v1/authorizations/${auth.authorizationId}`);
    if (latest.state !== auth.state || JSON.stringify(latest.verificationPlan) !== JSON.stringify(auth.verificationPlan)) {
      auth = latest;
      renderFlow();
    }
  }
}

// --- Actions ---

async function run(action) {
  if (busy) return;
  busy = true;
  renderFlow();
  try {
    await action();
  } catch (e) {
    notice(e.message, 'bad');
  } finally {
    busy = false;
    renderFlow();
    refresh().catch(() => {});
  }
}

async function create() {
  const currency = $('#currency').value;
  const beneficiary = { name: $('#beneficiary').value.trim() };
  const iban = $('#iban').value.replace(/\s+/g, '').toUpperCase();
  if (iban) beneficiary.iban = iban;
  const view = await api('/api/v1/authorizations', {
    method: 'POST',
    headers: { 'Idempotency-Key': `ui-${crypto.randomUUID()}` },
    body: {
      credentialId: device.credentialId,
      amountMinor: toMinor($('#amount').value, currency),
      currency,
      beneficiary,
      scenario: $('#scenario').value,
      riskDecision: $('#risk').value,
    },
  });
  notice(view.state === 'REJECTED' ? 'Risk decision BLOCK: authorization rejected, nothing to sign.' : 'Authorization created. The device has verified the payload.', view.state === 'REJECTED' ? 'bad' : '');
  $('#evidence').textContent = 'Waiting for evidence…';
  await loadAuthorization(view);
}

async function submitSignature(signature, label) {
  const result = await api(`/api/v1/authorizations/${auth.authorizationId}/signature`, {
    method: 'POST', body: { signature, signatureFormat: 'raw' },
  });
  await loadAuthorization(result.authorization);
  if (result.status === 'VERIFIED') {
    notice(`${label}: signature verified by the server.`, 'good');
  } else {
    notice(`${label}: server rejected the signature (${result.reason}), attempt ${result.attempts}/${result.authorization.maxSignatureAttempts}.`, 'bad');
  }
  return result;
}

async function approve() {
  // Re-fetch and re-verify immediately before signing, as the SDK does.
  await loadAuthorization(await api(`/api/v1/authorizations/${auth.authorizationId}`));
  if (!signed) throw new Error('Signing refused: the payload failed verification on the device.');
  const signature = await signBytes(signed.bytes);
  const result = await submitSignature(signature, 'Customer approved');
  if (result.status === 'VERIFIED') lastValidSignature = { signature, authorizationId: auth.authorizationId };
}

async function advance() {
  if (auth.state === 'PENDING' && pendingStep()?.factor === 'SIGNATURE') return approve();
  const view = await api(`/api/v1/authorizations/${auth.authorizationId}/advance`, { method: 'POST' });
  await loadAuthorization(view);
  notice(view.state === 'COMMITTED' ? `Committed at bank: ${view.bankTransaction.reference}` : '', view.state === 'COMMITTED' ? 'good' : '');
}

async function attack(kind) {
  if (pendingStep()?.factor !== 'SIGNATURE' && kind !== 'forged-display') {
    throw new Error('Advance to the SIGNATURE step first.');
  }
  if (kind === 'tamper') {
    const altered = { ...signed.fields, amount_minor: '1' };
    return submitSignature(await signBytes(canonicalBytes(altered)), 'Tampered payload (amount changed to 1 minor unit)');
  }
  if (kind === 'wrong-code') {
    const right = await offlineCode(b64ToBytes(auth.canonicalPayloadBase64));
    return submitOfflineCode(String((Number(right) + 1) % 100000000).padStart(8, '0'), 'Guessed offline code typed on the bank screen');
  }
  if (kind === 'replay') {
    if (!lastValidSignature) throw new Error('Complete one authorization first; its signature is then replayed here.');
    return submitSignature(lastValidSignature.signature, `Replay of signature from ${lastValidSignature.authorizationId.slice(0, 8)}…`);
  }
  // Forged display: a compromised backend or proxy shows a smaller amount
  // than the one in the signed bytes. The device check must refuse.
  const forged = { ...auth, amountMinor: '100' };
  try {
    await verifyEnvelope(forged);
    notice('UNEXPECTED: forged response accepted', 'bad');
  } catch (e) {
    notice(`Forged display detected on the device (${e.message}). Nothing was signed.`, 'good');
  }
}

async function injectFault(type) {
  const view = await api(`/api/v1/authorizations/${auth.authorizationId}/fault`, { method: 'POST', body: { type } });
  await loadAuthorization(view);
}

async function reset() {
  await api('/api/v1/reset', { method: 'POST' });
  auth = null;
  signed = null;
  lastValidSignature = null;
  $('#evidence').textContent = 'Waiting for authorization…';
  $('#wysiwys').textContent = '—';
  notice('Environment reset. New device key enrolled.');
  renderDevice();
  await enrol();
}

async function loadPolicy() {
  const p = await api('/api/v1/policy');
  const el = $('#policy');
  const lines = [
    `${p.policy_reference} (version ${p.policy_version})`,
    `High-value threshold · ${p.high_value_threshold_minor} minor units`,
    `Authorization lifetime · ${p.authorization_ttl_seconds / 60} min`,
    `Signature attempts · ${p.max_signature_attempts}`,
  ];
  el.replaceChildren(Object.assign(document.createElement('b'), { textContent: 'Policy profile' }),
    ...lines.map((t) => Object.assign(document.createElement('span'), { textContent: t })));
}

$('#create').addEventListener('click', () => run(create));
$('#advance').addEventListener('click', () => run(advance));
$('#offline').addEventListener('click', () => run(confirmOffline));
$('#codeForm').addEventListener('submit', (e) => { e.preventDefault(); run(submitBankScreenCode); });
$('#closeBankScreen').addEventListener('click', () => { $('#bankScreen').hidden = true; });
$('#reset').addEventListener('click', () => run(reset));
$('#clock').addEventListener('click', () => run(async () => {
  await api('/api/v1/clock', { method: 'POST', body: { advanceSeconds: 300 } });
  if (auth) await loadAuthorization(await api(`/api/v1/authorizations/${auth.authorizationId}`));
  notice('Sandbox clock moved forward 5 minutes.');
}));
$('#verifyChain').addEventListener('click', () => run(async () => {
  const r = await api('/api/v1/evidence/verify');
  const how = [r.deviceSignatures ? `customer signature re-verified from the sealed bytes and device key for ${r.deviceSignatures} records` : '',
    r.offlineCodes ? `${r.offlineCodes} records confirmed offline by code (bound to the bytes, not third-party verifiable)` : ''].filter(Boolean).join('; ');
  notice(r.valid ? `Evidence chain valid: ${r.records} records, every seal verified${how ? `; ${how}` : ''}.` : `Evidence chain INVALID at record ${r.failedAt}: ${r.reason}`, r.valid ? 'good' : 'bad');
}));
document.querySelectorAll('[data-fault]').forEach((b) => b.addEventListener('click', () => run(() => injectFault(b.dataset.fault))));
document.querySelectorAll('[data-attack]').forEach((b) => b.addEventListener('click', () => run(() => attack(b.dataset.attack))));
$('#scenario').addEventListener('change', () => {
  if ($('#scenario').value === 'high-value' && $('#risk').value === 'ALLOW') $('#amount').value = '75000.00';
});

let refreshTimer = null;

function showLogin(message = '') {
  clearInterval(refreshTimer);
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#logout').hidden = true;
  $('#loginNotice').textContent = message;
  $('#accessCode').focus();
}

$('#loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await api('/api/v1/session', { method: 'POST', body: { accessCode: $('#accessCode').value.trim() } });
    $('#accessCode').value = '';
    $('#login').hidden = true;
    start();
  } catch (e) {
    $('#loginNotice').textContent = e.code === 'TOO_MANY_ATTEMPTS' ? 'Too many attempts. Try again in 15 minutes.' : 'Access code not recognized.';
  }
});

$('#logout').addEventListener('click', async () => {
  await api('/api/v1/session/logout', { method: 'POST' }).catch(() => {});
  auth = null;
  signed = null;
  showLogin('Signed out.');
});

async function start() {
  renderFlow();
  try {
    let session;
    try {
      session = await api('/api/v1/session');
    } catch (e) {
      if (e.status === 401) return showLogin();
      throw e;
    }
    $('#app').hidden = false;
    $('#logout').hidden = !session.hosted;
    $('#workspaceName').textContent = session.hosted ? `Workspace · ${session.workspace}` : '';
    const health = await api('/api/v1/health');
    $('#health').replaceChildren(document.createElement('i'), ` CONTROL PLANE ONLINE · PROTOCOL v${health.protocolVersion}`);
    if (!window.isSecureContext || !crypto.subtle) throw new Error('WebCrypto needs a secure context: open http://127.0.0.1 or http://localhost');
    await loadPolicy();
    await enrol();
    await refresh();
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => refresh().catch(() => {}), 2000);
  } catch (e) {
    $('#health').textContent = 'CONTROL PLANE OFFLINE';
    notice(e.message, 'bad');
  }
}

start();
