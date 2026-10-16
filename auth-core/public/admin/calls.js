'use strict';

// Verification calls (ADR 0017): an operator of the bank answers the
// customer's in-app audio or video call, checks the transaction with the
// customer and records the result. Media goes directly between the browser
// and the phone (or through the bank's TURN server), encrypted by WebRTC
// (DTLS-SRTP); Auth Core only relays the signalling and records nothing of
// the media. Nothing is recorded here either.
//
// Uses api(), escapeHtml(), renderTable() and state from admin.js.

const call = {
  current: null, // { sessionId, channel, pc, local, after, polling }
};

const callsEl = () => document.getElementById('calls-table');
const activeEl = () => document.getElementById('call-active');

function formatAmount(amountMinor, currency) {
  let digits = 2;
  try { digits = new Intl.NumberFormat('en', { style: 'currency', currency }).resolvedOptions().maximumFractionDigits; } catch { /* unknown code: 2 */ }
  const text = String(amountMinor).padStart(digits + 1, '0');
  const whole = digits ? text.slice(0, -digits) : text;
  return `${whole}${digits ? `.${text.slice(-digits)}` : ''} ${currency}`;
}

function beneficiaryLines(beneficiary) {
  return Object.entries(beneficiary || {}).map(([k, v]) => `<div><span class="muted">${escapeHtml(k)}</span> ${escapeHtml(v)}</div>`).join('');
}

async function loadCalls() {
  if (!state.session || !['operator', 'administrator'].includes(state.session.role)) {
    document.getElementById('calls-section').style.display = 'none';
    return;
  }
  const calls = await api('/admin/api/verification-calls');
  renderTable(callsEl(), [
    { label: 'Channel', render: (c) => escapeHtml(c.channel) },
    { label: 'Amount', render: (c) => `<b>${escapeHtml(formatAmount(c.transaction.amountMinor, c.transaction.currency))}</b>` },
    { label: 'Beneficiary', render: (c) => beneficiaryLines(c.transaction.beneficiary) },
    { label: 'Reference', render: (c) => `<span class="mono">${escapeHtml(c.transaction.transactionReference)}</span>` },
    { label: 'Expires', render: (c) => formatTimestamp(c.expiresAt) },
    { label: '', render: (c) => `<button class="primary" data-answer="${escapeHtml(c.sessionId)}" ${call.current ? 'disabled' : ''}>${c.claimedByMe ? 'Rejoin' : 'Answer'}</button>` },
  ], calls, 'No calls waiting.');
  for (const button of callsEl().querySelectorAll('button[data-answer]')) {
    button.addEventListener('click', () => answer(button.dataset.answer).catch((e) => { endCall(); window.alert(e.message); }));
  }
}

async function postSignal(sessionId, type, payload) {
  await api(`/admin/api/verification-calls/${sessionId}/signals`, { method: 'POST', body: JSON.stringify({ type, payload }) });
}

async function answer(sessionId) {
  const claim = await api(`/admin/api/verification-calls/${sessionId}/claim`, { method: 'POST', body: '{}' });
  const video = claim.channel === 'VIDEO';
  const local = await navigator.mediaDevices.getUserMedia({ audio: true, video });
  const pc = new RTCPeerConnection({ iceServers: claim.iceServers });
  // Candidates can be gathered before the answer is posted and can arrive
  // before the offer is applied: outgoing ones wait for the answer, incoming
  // ones for the remote description.
  call.current = { sessionId, channel: claim.channel, pc, local, after: 0, polling: true, answered: false, outgoing: [], incoming: [] };
  for (const track of local.getTracks()) pc.addTrack(track, local);
  pc.ontrack = (event) => {
    document.getElementById('call-remote').srcObject = event.streams[0];
    document.getElementById('call-remote-audio').srcObject = video ? null : event.streams[0];
  };
  pc.onicecandidate = (event) => {
    if (!event.candidate || !call.current) return;
    if (call.current.answered) postSignal(sessionId, 'candidate', event.candidate.toJSON()).catch(reportError);
    else call.current.outgoing.push(event.candidate.toJSON());
  };
  pc.onconnectionstatechange = () => { document.getElementById('call-state').textContent = pc.connectionState; };

  const t = claim.transaction;
  activeEl().style.display = 'block';
  document.getElementById('call-local').srcObject = video ? local : null;
  document.getElementById('call-local').style.display = video ? 'block' : 'none';
  document.getElementById('call-remote').style.display = video ? 'block' : 'none';
  document.getElementById('call-indicators').textContent = video ? 'Camera and microphone on' : 'Microphone on';
  document.getElementById('call-terms').innerHTML = `
    <div><span class="muted">${escapeHtml(t.operationType)}</span> <b style="font-size:18px">${escapeHtml(formatAmount(t.amountMinor, t.currency))}</b></div>
    ${beneficiaryLines(t.beneficiary)}
    <div class="mono muted">${escapeHtml(t.transactionReference)}</div>`;
  document.getElementById('call-state').textContent = 'waiting for the customer';
  await loadCalls();
  pollSignals().catch((error) => { reportError(error); endCall(); });
}

/** The phone sends the offer; this side answers and exchanges candidates. */
async function pollSignals() {
  while (call.current && call.current.polling) {
    const { sessionId, pc } = call.current;
    const { signals, next } = await api(`/admin/api/verification-calls/${sessionId}/signals?after=${call.current.after}&waitMs=15000`);
    if (!call.current || call.current.sessionId !== sessionId) return;
    call.current.after = next;
    for (const signal of signals) {
      if (signal.type === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: signal.payload.sdp });
        for (const candidate of call.current.incoming.splice(0)) await pc.addIceCandidate(candidate).catch(reportError);
        const answerDescription = await pc.createAnswer();
        await pc.setLocalDescription(answerDescription);
        await postSignal(sessionId, 'answer', { sdp: pc.localDescription.sdp });
        call.current.answered = true;
        for (const candidate of call.current.outgoing.splice(0)) await postSignal(sessionId, 'candidate', candidate);
      } else if (signal.type === 'candidate') {
        if (pc.remoteDescription) await pc.addIceCandidate(signal.payload).catch(reportError);
        else call.current.incoming.push(signal.payload);
      } else if (signal.type === 'bye') {
        document.getElementById('call-state').textContent = `the customer left (${signal.payload?.reason ?? 'bye'})`;
        endCall(false);
        return;
      }
    }
  }
}

async function decide(result) {
  if (!call.current) return;
  const { sessionId } = call.current;
  if (!window.confirm(result === 'VERIFIED'
    ? 'Record that the customer was verified and confirmed this transaction?'
    : 'Record that the verification failed?')) return;
  try {
    const plan = await api(`/admin/api/verification-calls/${sessionId}/decision`, { method: 'POST', body: JSON.stringify({ result }) });
    document.getElementById('call-state').textContent = `recorded ${result}; plan ${plan.status}`;
  } finally {
    endCall(false);
  }
}

function endCall(hideImmediately = true) {
  if (call.current) {
    call.current.polling = false;
    call.current.pc.close();
    for (const track of call.current.local.getTracks()) track.stop();
  }
  call.current = null;
  document.getElementById('call-indicators').textContent = 'Camera and microphone off';
  document.getElementById('call-local').srcObject = null;
  document.getElementById('call-remote').srcObject = null;
  document.getElementById('call-remote-audio').srcObject = null;
  if (hideImmediately) activeEl().style.display = 'none';
  loadCalls().catch(reportError);
}

document.getElementById('call-verified-btn').addEventListener('click', () => decide('VERIFIED'));
document.getElementById('call-failed-btn').addEventListener('click', () => decide('FAILED'));
document.getElementById('call-hangup-btn').addEventListener('click', () => endCall());
document.getElementById('calls-refresh-btn').addEventListener('click', () => loadCalls().catch(reportError));
setInterval(() => { if (state.session && !call.current) loadCalls().catch(reportError); }, 5000);
