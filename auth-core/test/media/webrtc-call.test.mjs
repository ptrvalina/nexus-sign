// Real WebRTC media between two browsers through Auth Core's call signalling
// (ADR 0017). The operator uses the actual admin console (public/admin); the
// customer's side is a browser page standing in for the native SDK, signing
// its requests with the enrolled device key. Media is Chromium's synthetic
// camera and microphone; it travels peer to peer over loopback, DTLS-SRTP.
//
// Needs PostgreSQL and Redis (as the integration suites) and Playwright with
// Chromium: PLAYWRIGHT_MODULE=<path to the playwright package> or `playwright`
// resolvable from here. Without Playwright the suite is skipped and says so.
//
//   node --test test/media/webrtc-call.test.mjs
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { skipWithoutServices, startAuthCore } from '../integration/support/harness.mjs';
import { bankSession, deviceHeaders, deviceSignature, submitSignature, totp } from '../integration/support/actors.mjs';

const require = createRequire(import.meta.url);
let playwright = null;
try { playwright = require(process.env.PLAYWRIGHT_MODULE ?? 'playwright'); } catch { playwright = null; }
const skip = skipWithoutServices || (playwright ? false : 'Playwright is not installed (set PLAYWRIGHT_MODULE)');

const CHROMIUM_ARGS = [
  '--use-fake-ui-for-media-stream',
  '--use-fake-device-for-media-stream',
  // Host candidates as plain addresses, so two browsers on one machine connect
  // without an mDNS responder.
  '--disable-features=WebRtcHideLocalIpsWithMdns',
  '--autoplay-policy=no-user-gesture-required',
];

/** The device side, run in the browser: offer, ICE, wait for media. */
async function deviceSide({ baseUrl, sessionId, video }) {
  const signedFetch = async (method, path, body) => {
    const raw = body === undefined ? '' : JSON.stringify(body);
    const headers = await window.signDevice(method, path, raw);
    const response = await fetch(baseUrl + path, { method, headers: { ...headers, ...(raw ? { 'Content-Type': 'application/json' } : {}) }, body: raw || undefined });
    return response.json().catch(() => ({}));
  };
  const base = `/v1/mobile/verification-sessions/${sessionId}`;
  const joined = await signedFetch('GET', `${base}/call`);
  const local = await navigator.mediaDevices.getUserMedia({ audio: true, video });
  const pc = new RTCPeerConnection({ iceServers: joined.iceServers });
  window.devicePc = pc;
  for (const track of local.getTracks()) pc.addTrack(track, local);
  // As the SDKs do: own candidates wait until the offer is sent, the
  // operator's wait until the answer is applied.
  const outgoing = []; const incoming = []; let offered = false;
  pc.onicecandidate = (e) => {
    if (!e.candidate) return;
    if (offered) signedFetch('POST', `${base}/signals`, { type: 'candidate', payload: e.candidate.toJSON() });
    else outgoing.push(e.candidate.toJSON());
  };
  await pc.setLocalDescription(await pc.createOffer());
  await signedFetch('POST', `${base}/signals`, { type: 'offer', payload: { sdp: pc.localDescription.sdp } });
  offered = true;
  for (const candidate of outgoing.splice(0)) await signedFetch('POST', `${base}/signals`, { type: 'candidate', payload: candidate });
  let after = 0;
  const deadline = Date.now() + 45_000;
  while (pc.connectionState !== 'connected' && Date.now() < deadline) {
    const { signals, next } = await signedFetch('GET', `${base}/signals?after=${after}&waitMs=2000`);
    after = next ?? after;
    for (const s of signals ?? []) {
      if (s.type === 'answer') {
        await pc.setRemoteDescription({ type: 'answer', sdp: s.payload.sdp });
        for (const candidate of incoming.splice(0)) await pc.addIceCandidate(candidate);
      } else if (s.type === 'candidate') {
        if (pc.remoteDescription) await pc.addIceCandidate(s.payload);
        else incoming.push(s.payload);
      }
    }
  }
  if (pc.connectionState !== 'connected') return { state: pc.connectionState };
  await new Promise((r) => setTimeout(r, 2500));
  const stats = [...(await pc.getStats()).values()];
  const inbound = stats.filter((s) => s.type === 'inbound-rtp');
  const pair = stats.find((s) => s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded');
  const transport = stats.find((s) => s.type === 'transport');
  return {
    state: pc.connectionState,
    received: Object.fromEntries(inbound.map((s) => [s.kind, s.bytesReceived])),
    localCandidateType: stats.find((s) => s.id === pair?.localCandidateId)?.candidateType,
    dtlsState: transport?.dtlsState,
    srtpCipher: transport?.srtpCipher,
    tlsVersion: transport?.tlsVersion,
    after,
  };
}

describe('real WebRTC call: phone ↔ operator console', { skip }, () => {
  let server; let bank; let device; let browser; let admin;
  const ADMIN_PASSWORD = 'Correct-Horse-Battery-9';

  before(async () => {
    server = await startAuthCore();
    bank = await bankSession(server, await server.registerBank('bank-media'));
    await server.verificationSetup('operator', 'bank-media', 'AUDIO,VIDEO');
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    browser = await playwright.chromium.launch({ args: CHROMIUM_ARGS });
  });
  after(async () => { await browser?.close(); await server?.stop(); });

  for (const channel of ['VIDEO', 'AUDIO']) {
    test(`${channel}: media flows both ways over DTLS-SRTP, the operator verifies, the device still signs`, async (t) => {
      const policy = channel === 'VIDEO' ? { requireVideo: true, audioAvailable: false } : { requireAudio: true, videoAvailable: false };
      const auth = await bank.createAuthorization(device, { verificationPolicy: policy });
      const opened = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/verification-sessions`, { body: { channel } });
      assert.equal(opened.status, 201, opened.text);
      const { sessionId } = opened.json;
      // One operator account per test: a TOTP code is accepted only once.
      admin = await server.createAdmin(`media-operator-${channel.toLowerCase()}`, 'operator', { clientId: 'bank-media', password: ADMIN_PASSWORD });

      // Operator: the real admin console.
      const operatorContext = await browser.newContext({ permissions: ['camera', 'microphone'] });
      const console_ = await operatorContext.newPage();
      console_.on('dialog', (d) => d.accept());
      await console_.goto(`${server.baseUrl}/admin/`);
      await console_.fill('#username', admin.username);
      await console_.fill('#password', ADMIN_PASSWORD);
      if (admin.totpSecret) await console_.fill('#totp', totp(admin.totpSecret));
      await console_.click('#login-form button[type=submit]');
      await console_.waitForSelector(`button[data-answer="${sessionId}"]`, { timeout: 15_000 });
      await console_.click(`button[data-answer="${sessionId}"]`);
      await console_.waitForFunction(() => document.getElementById('call-state').textContent === 'waiting for the customer' || document.getElementById('call-state').textContent === 'connected');
      assert.match(await console_.textContent('#call-terms'), /1250\.00 PLN/, 'the operator sees the amount from the signed terms');
      assert.match(await console_.textContent('#call-terms'), /PL61109010140000071219812874/);

      // Device: a page standing in for the SDK, signing with the device key.
      const deviceContext = await browser.newContext({ permissions: ['camera', 'microphone'], bypassCSP: true });
      const phone = await deviceContext.newPage();
      await phone.exposeFunction('signDevice', (method, path, raw) => deviceHeaders(device, method, path, raw));
      await phone.goto(`${server.baseUrl}/healthz`);
      const result = await phone.evaluate(deviceSide, { baseUrl: server.baseUrl, sessionId, video: channel === 'VIDEO' });

      t.diagnostic(`${channel} media: ${JSON.stringify(result)}`);
      assert.equal(result.state, 'connected', JSON.stringify(result));
      assert.equal(result.dtlsState, 'connected');
      assert.ok(result.srtpCipher, `SRTP cipher negotiated: ${result.srtpCipher}`);
      assert.ok(result.received.audio > 0, `audio received by the phone: ${JSON.stringify(result.received)}`);
      if (channel === 'VIDEO') assert.ok(result.received.video > 0, 'video received by the phone');
      assert.equal(result.localCandidateType, 'host', 'peer to peer on loopback, not relayed through Auth Core');
      await console_.waitForFunction(() => document.getElementById('call-state').textContent === 'connected');
      if (channel === 'VIDEO') {
        await console_.waitForFunction(() => document.getElementById('call-remote').videoWidth > 0, null, { timeout: 15_000 });
      }
      assert.equal(await console_.textContent('#call-indicators'), channel === 'VIDEO' ? 'Camera and microphone on' : 'Microphone on');

      await console_.click('#call-verified-btn');
      await console_.waitForFunction(() => /recorded VERIFIED/.test(document.getElementById('call-state').textContent));
      assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/verification-plan`)).json.status, 'VERIFIED');
      assert.equal(await console_.textContent('#call-indicators'), 'Camera and microphone off', 'tracks stopped after the decision');

      const { signature } = await deviceSignature(server, device, auth.authorizationId);
      assert.equal((await submitSignature(server, device, auth.authorizationId, signature)).json.status, 'VERIFIED');
      const evidence = await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/evidence`);
      const factor = evidence.json.sealedPayload.verificationFactors.find((f) => f.status === 'VERIFIED');
      assert.deepEqual([factor.channel, factor.method, factor.issuer], [channel, 'OPERATOR', admin.username]);
      await operatorContext.close();
      await deviceContext.close();
    });
  }
});
