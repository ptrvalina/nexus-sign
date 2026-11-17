'use strict';

// Calls the customer starts from the bank's app ("talk to the bank"): an
// operator of the bank takes one from the queue and talks with the customer.
// No transaction is attached and no result is recorded; the call itself is
// recorded (who, when, how it ended), never its media. Media goes directly
// between the browser and the phone (or through the bank's TURN server),
// encrypted by WebRTC (DTLS-SRTP); Auth Core relays the signalling only.
//
// Uses api(), escapeHtml(), formatTimestamp(), renderTable(), reportError() and state from admin.js.

const ccall = { current: null }; // { callId, pc, local, after, polling, answered, outgoing, incoming }
const ccBase = (callId) => `/admin/api/customer-calls/${callId}`;

async function loadCustomerCalls() {
  if (!state.session || !['operator', 'administrator'].includes(state.session.role) || !state.session.clientId) {
    document.getElementById('customer-calls-section').style.display = 'none';
    return;
  }
  const { calls } = await api('/admin/api/customer-calls');
  const el = document.getElementById('customer-calls-table');
  renderTable(el, [
    { label: 'Channel', render: (c) => escapeHtml(c.channel) },
    { label: 'Topic', render: (c) => escapeHtml(c.topic) },
    { label: 'NEXUS ID', render: (c) => `<span class="mono">${escapeHtml(c.nexusId)}</span>` },
    { label: 'Waiting since', render: (c) => formatTimestamp(c.createdAt) },
    { label: '', render: (c) => `<button class="primary" data-ccall="${escapeHtml(c.callId)}" ${ccall.current ? 'disabled' : ''}>${c.state === 'CONNECTED' ? 'Rejoin' : 'Answer'}</button>` },
  ], calls, 'No customer is calling.');
  for (const button of el.querySelectorAll('button[data-ccall]')) {
    button.addEventListener('click', () => answerCustomerCall(button.dataset.ccall).catch((e) => { stopCustomerCall(); window.alert(e.message); }));
  }
}

async function postCustomerSignal(callId, type, payload, messageId = crypto.randomUUID()) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await api(`${ccBase(callId)}/signals`, { method: 'POST', body: JSON.stringify({ type, payload, messageId }) });
      return;
    } catch (error) {
      if (attempt >= 2 || (error.status && error.status < 500)) throw error;
      await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
    }
  }
}

async function answerCustomerCall(callId) {
  const { call: answered, iceServers } = await api(`${ccBase(callId)}/answer`, { method: 'POST', body: '{}' });
  const video = answered.channel === 'VIDEO';
  const local = await navigator.mediaDevices.getUserMedia({ audio: true, video });
  const pc = new RTCPeerConnection({ iceServers });
  ccall.current = { callId, pc, local, after: 0, polling: true, answered: false, outgoing: [], incoming: [] };
  for (const track of local.getTracks()) pc.addTrack(track, local);
  pc.ontrack = (event) => {
    document.getElementById('ccall-remote').srcObject = event.streams[0];
    document.getElementById('ccall-remote-audio').srcObject = video ? null : event.streams[0];
  };
  pc.onicecandidate = (event) => {
    if (!event.candidate || !ccall.current) return;
    if (ccall.current.answered) postCustomerSignal(callId, 'candidate', event.candidate.toJSON()).catch(reportError);
    else ccall.current.outgoing.push(event.candidate.toJSON());
  };
  pc.onconnectionstatechange = () => {
    document.getElementById('ccall-state').textContent = pc.connectionState === 'disconnected' ? 'reconnecting' : pc.connectionState;
  };
  document.getElementById('ccall-active').style.display = 'block';
  document.getElementById('ccall-local').srcObject = video ? local : null;
  document.getElementById('ccall-local').style.display = video ? 'block' : 'none';
  document.getElementById('ccall-remote').style.display = video ? 'block' : 'none';
  document.getElementById('ccall-title').textContent = `${answered.topic} · NEXUS ID ${answered.nexusId}`;
  document.getElementById('ccall-indicators').textContent = video ? 'Camera and microphone on' : 'Microphone on';
  document.getElementById('ccall-state').textContent = 'connecting';
  await loadCustomerCalls();
  pollCustomerSignals().catch((error) => { reportError(error); stopCustomerCall(false); });
}

/** The phone sends the offer (it may have sent it while waiting); this side answers. */
async function pollCustomerSignals() {
  while (ccall.current && ccall.current.polling) {
    const { callId, pc } = ccall.current;
    const { signals, next } = await api(`${ccBase(callId)}/signals?after=${ccall.current.after}&waitMs=15000`);
    if (!ccall.current || ccall.current.callId !== callId) return;
    ccall.current.after = next;
    for (const signal of signals) {
      if (signal.type === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: signal.payload.sdp });
        for (const candidate of ccall.current.incoming.splice(0)) await pc.addIceCandidate(candidate).catch(reportError);
        await pc.setLocalDescription(await pc.createAnswer());
        await postCustomerSignal(callId, 'answer', { sdp: pc.localDescription.sdp });
        ccall.current.answered = true;
        // The code the customer's app shows too (finding A2-11, call-code.js).
        callCode(signal.payload.sdp, pc.localDescription.sdp).then((code) => {
          document.getElementById('ccall-code').textContent = code ? `${code.slice(0, 3)} ${code.slice(3)}` : 'unavailable (no DTLS fingerprint): end the call';
        }).catch(reportError);
        for (const candidate of ccall.current.outgoing.splice(0)) await postCustomerSignal(callId, 'candidate', candidate);
      } else if (signal.type === 'candidate') {
        if (pc.remoteDescription) await pc.addIceCandidate(signal.payload).catch(reportError);
        else ccall.current.incoming.push(signal.payload);
      } else if (signal.type === 'bye') {
        const reason = signal.payload?.reason ?? 'bye';
        document.getElementById('ccall-state').textContent = signal.from === 'server' ? `call closed (${reason})` : `the customer hung up (${reason})`;
        stopCustomerCall(false);
        return;
      }
    }
  }
}

function stopCustomerCall(hide = true) {
  if (ccall.current) {
    ccall.current.polling = false;
    ccall.current.pc.close();
    for (const track of ccall.current.local.getTracks()) track.stop();
  }
  ccall.current = null;
  document.getElementById('ccall-code').textContent = '—';
  document.getElementById('ccall-indicators').textContent = 'Camera and microphone off';
  for (const id of ['ccall-local', 'ccall-remote', 'ccall-remote-audio']) document.getElementById(id).srcObject = null;
  if (hide) document.getElementById('ccall-active').style.display = 'none';
  loadCustomerCalls().catch(reportError);
}

async function hangUpCustomerCall() {
  const callId = ccall.current?.callId;
  stopCustomerCall();
  if (callId) await api(`${ccBase(callId)}/end`, { method: 'POST', body: '{}' }).catch(reportError);
}

document.getElementById('ccall-hangup-btn').addEventListener('click', () => hangUpCustomerCall());
document.getElementById('customer-calls-refresh-btn').addEventListener('click', () => loadCustomerCalls().catch(reportError));
setInterval(() => { if (state.session && !ccall.current) loadCustomerCalls().catch(reportError); }, 5000);
