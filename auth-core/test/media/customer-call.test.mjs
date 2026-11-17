// A call the customer starts ("talk to the bank"), with real WebRTC media
// between two browsers through Auth Core: the customer's side is a page
// standing in for the SDK, signing with the enrolled device key; the
// operator uses the actual admin console. The phone sends its offer while
// the call waits, the operator answers from the queue, media flows over
// DTLS-SRTP, the customer hangs up and the console is told. Needs what
// webrtc-call.test.mjs needs (PostgreSQL, Redis, Playwright with Chromium).
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { skipWithoutServices, startAuthCore } from '../integration/support/harness.mjs';
import { bankSession, deviceHeaders, totp } from '../integration/support/actors.mjs';

const require = createRequire(import.meta.url);
let playwright = null;
try { playwright = require(process.env.PLAYWRIGHT_MODULE ?? 'playwright'); } catch { playwright = null; }
const skip = skipWithoutServices || (playwright ? false : 'Playwright is not installed (set PLAYWRIGHT_MODULE)');
const CHROMIUM_ARGS = ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', '--disable-features=WebRtcHideLocalIpsWithMdns', '--autoplay-policy=no-user-gesture-required'];

/** The phone: asks for the call, offers at once, then waits for the operator's answer and media. */
async function phoneSide({ baseUrl, channel }) {
  const signedFetch = async (method, path, body) => {
    const raw = body === undefined ? '' : JSON.stringify(body);
    const headers = await window.signDevice(method, path, raw);
    const response = await fetch(baseUrl + path, { method, headers: { ...headers, ...(raw ? { 'Content-Type': 'application/json' } : {}) }, body: raw || undefined });
    return { status: response.status, json: await response.json().catch(() => ({})) };
  };
  const asked = await signedFetch('POST', '/v1/mobile/customer-calls', { channel, topic: 'Question about my card' });
  if (asked.status !== 201) return { asked };
  const { call, iceServers } = asked.json;
  window.callId = call.callId;
  const base = `/v1/mobile/customer-calls/${call.callId}`;
  const local = await navigator.mediaDevices.getUserMedia({ audio: true, video: channel === 'VIDEO' });
  const pc = new RTCPeerConnection({ iceServers });
  window.phonePc = pc;
  for (const track of local.getTracks()) pc.addTrack(track, local);
  const outgoing = []; const incoming = []; let offered = false;
  pc.onicecandidate = (e) => {
    if (!e.candidate) return;
    if (offered) signedFetch('POST', `${base}/signals`, { type: 'candidate', payload: e.candidate.toJSON(), messageId: crypto.randomUUID() });
    else outgoing.push(e.candidate.toJSON());
  };
  await pc.setLocalDescription(await pc.createOffer());
  await signedFetch('POST', `${base}/signals`, { type: 'offer', payload: { sdp: pc.localDescription.sdp } });
  offered = true;
  for (const candidate of outgoing.splice(0)) await signedFetch('POST', `${base}/signals`, { type: 'candidate', payload: candidate });
  let after = 0;
  const deadline = Date.now() + 45_000;
  while (pc.connectionState !== 'connected' && Date.now() < deadline) {
    const { json } = await signedFetch('GET', `${base}/signals?after=${after}&waitMs=2000`);
    after = json.next ?? after;
    for (const s of json.signals ?? []) {
      if (s.type === 'answer') {
        await pc.setRemoteDescription({ type: 'answer', sdp: s.payload.sdp });
        for (const candidate of incoming.splice(0)) await pc.addIceCandidate(candidate);
      } else if (s.type === 'candidate') {
        if (pc.remoteDescription) await pc.addIceCandidate(s.payload); else incoming.push(s.payload);
      }
    }
  }
  await new Promise((r) => setTimeout(r, 2500));
  const stats = [...(await pc.getStats()).values()];
  const transport = stats.find((s) => s.type === 'transport');
  const state = (await signedFetch('GET', base)).json.call.state;
  const ended = (await signedFetch('POST', `${base}/end`, {})).json;
  return {
    callId: call.callId, state: pc.connectionState, callState: state, ended,
    received: Object.fromEntries(stats.filter((s) => s.type === 'inbound-rtp').map((s) => [s.kind, s.bytesReceived])),
    dtlsState: transport?.dtlsState, srtpCipher: transport?.srtpCipher,
    offerSdp: pc.localDescription.sdp, answerSdp: pc.remoteDescription.sdp,
  };
}

/** The call code as the SDKs compute it (finding A2-11), independently of the console's call-code.js. */
function expectedCallCode(offerSdp, answerSdp) {
  const print = (sdp) => {
    const m = /^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/im.exec(sdp);
    return m ? `${m[1].toLowerCase()} ${m[2].toUpperCase()}` : null;
  };
  const digest = createHash('sha256').update(Buffer.concat([Buffer.from('NEXUS-SIGN/CALL-CODE/v1'), Buffer.from([0]),
    Buffer.from(print(offerSdp)), Buffer.from([0]), Buffer.from(print(answerSdp))])).digest();
  return String(digest.readUInt32BE(0) % 1_000_000).padStart(6, '0');
}

describe('real WebRTC call started by the customer: phone ↔ operator console', { skip }, () => {
  let server; let bank; let device; let browser;
  const PASSWORD = 'Correct-Horse-Battery-9';

  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-ccall'));
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    browser = await playwright.chromium.launch({ args: CHROMIUM_ARGS });
  });
  after(async () => { await browser?.close(); await server?.stop(); });

  test('the bank enables the channel; the call waits, an operator answers, media flows, the customer hangs up', async (t) => {
    await server.verificationSetup('customer-calls', 'bank-ccall', 'VIDEO');
    const admin = await server.createAdmin('ccall-operator', 'operator', { clientId: 'bank-ccall', password: PASSWORD });
    const operatorContext = await browser.newContext({ permissions: ['camera', 'microphone'] });
    const console_ = await operatorContext.newPage();
    console_.on('dialog', (d) => d.accept());
    await console_.goto(`${server.baseUrl}/admin/`);
    await console_.fill('#username', admin.username);
    await console_.fill('#password', PASSWORD);
    if (admin.totpSecret) await console_.fill('#totp', totp(admin.totpSecret));
    await console_.click('#login-form button[type=submit]');

    const deviceContext = await browser.newContext({ permissions: ['camera', 'microphone'], bypassCSP: true });
    const phone = await deviceContext.newPage();
    await phone.exposeFunction('signDevice', (method, path, raw) => deviceHeaders(device, method, path, raw));
    await phone.goto(`${server.baseUrl}/healthz`);
    const running = phone.evaluate(phoneSide, { baseUrl: server.baseUrl, channel: 'VIDEO' });
    await console_.click('#customer-calls-refresh-btn');
    await console_.waitForSelector('button[data-ccall]', { timeout: 15_000 });
    await console_.click('button[data-ccall]');
    // Read while the call is up: the console shows the call code (finding A2-11).
    await console_.waitForFunction(() => /^\d{3} \d{3}$/.test(document.getElementById('ccall-code').textContent), null, { timeout: 30_000 });
    const shownCode = (await console_.textContent('#ccall-code')).replace(' ', '');
    const result = await running;
    assert.equal(shownCode, expectedCallCode(result.offerSdp, result.answerSdp), 'console and phone show the same call code');
    t.diagnostic(JSON.stringify(result));
    assert.equal(result.state, 'connected', JSON.stringify(result));
    assert.equal(result.callState, 'CONNECTED');
    assert.equal(result.dtlsState, 'connected'); assert.ok(result.srtpCipher);
    assert.ok(result.received.audio > 0 && result.received.video > 0, JSON.stringify(result.received));
    assert.deepEqual([result.ended.state, result.ended.endReason], ['ENDED', 'hung_up']);
    await console_.waitForFunction(() => /hung up/.test(document.getElementById('ccall-state').textContent), null, { timeout: 20_000 });
    assert.equal((await bank.call('GET', `/v1/customer-calls/${result.callId}`)).json.operator, admin.username);
    await operatorContext.close();
    await deviceContext.close();
  });

  test('a channel the bank did not enable is refused', async () => {
    await server.verificationSetup('customer-calls', 'bank-ccall', 'none');
    const context = await browser.newContext({ bypassCSP: true });
    const phone = await context.newPage();
    await phone.exposeFunction('signDevice', (method, path, raw) => deviceHeaders(device, method, path, raw));
    await phone.goto(`${server.baseUrl}/healthz`);
    const { asked } = await phone.evaluate(phoneSide, { baseUrl: server.baseUrl, channel: 'AUDIO' });
    assert.equal(asked.status, 409); assert.equal(asked.json.code, 'CALL_CHANNEL_NOT_ENABLED');
    await context.close();
  });
});
