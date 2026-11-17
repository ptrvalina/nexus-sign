// Drives android-sdk CallConformanceTest: the SDK's call state machine and
// wire format against this Auth Core, with this script as the operator
// (admin API). Media is scripted on the SDK side; this is a signalling
// protocol test, not a media test.
//
// Runs when NEXUS_CALL_CONFORMANCE_CMD is a command that runs the JVM test
// (it receives NEXUS_CALL_CONFORMANCE=<session file>); skipped otherwise.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { skipWithoutServices, startAuthCore } from '../integration/support/harness.mjs';
import { adminSession, bankSession } from '../integration/support/actors.mjs';

const command = process.env.NEXUS_CALL_CONFORMANCE_CMD;
const skip = skipWithoutServices || (command ? false : 'NEXUS_CALL_CONFORMANCE_CMD is not set');

describe('SDK call state machine against Auth Core', { skip }, () => {
  let server; let bank; let device; let operator;

  before(async () => {
    server = await startAuthCore({ env: { WEBRTC_STUN_URLS: 'stun:turn.bank.example:3478' } });
    bank = await bankSession(server, await server.registerBank('bank-conformance'));
    await server.verificationSetup('operator', 'bank-conformance', 'AUDIO,VIDEO');
    device = await bank.enrolDevice((await bank.createIdentity()).nexusId);
    operator = await adminSession(server, await server.createAdmin('conformance-op', 'operator', { clientId: 'bank-conformance' }));
  });
  after(async () => { await server?.stop(); });

  test('offer, candidates both ways, answer, decision; the device sees Connected then Decided(VERIFIED)', async () => {
    const auth = await bank.createAuthorization(device, { verificationPolicy: { requireVideo: true, audioAvailable: false } });
    const opened = await bank.call('POST', `/v1/authorizations/${auth.authorizationId}/verification-sessions`, { body: { channel: 'VIDEO' } });
    assert.equal(opened.status, 201, opened.text);
    const { sessionId } = opened.json;
    const dir = mkdtempSync(join(tmpdir(), 'nexus-call-'));
    const file = join(dir, 'session.json');
    writeFileSync(file, JSON.stringify({
      baseUrl: server.baseUrl, sessionId, credentialId: device.credentialId,
      authKeyPkcs8: device.authKey.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    }));
    const child = spawn('bash', ['-c', command], { env: { ...process.env, NEXUS_CALL_CONFORMANCE: file }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });
    const exited = new Promise((resolve) => child.on('exit', resolve));

    const op = (method, path, body) => operator.call(method, `/admin/api/verification-calls/${sessionId}${path}`, body === undefined ? {} : { body });
    assert.equal((await op('POST', '/claim', {})).status, 200);
    let cursor = 0; const received = [];
    // The command starts Gradle, which needs a while even with compiled tests;
    // the session itself lasts five minutes.
    const deadline = Date.now() + 180_000;
    while (!received.some((s) => s.type === 'candidate') && Date.now() < deadline) {
      const r = await op('GET', `/signals?after=${cursor}&waitMs=2000`);
      cursor = r.json.next; received.push(...r.json.signals);
    }
    assert.deepEqual(received.map((s) => s.type).slice(0, 2), ['offer', 'candidate'], `device sent offer then candidate: ${output}`);
    assert.match(received[0].payload.sdp, /^v=0/);
    assert.equal(received[1].payload.sdpMid, '0');
    assert.equal((await op('POST', '/signals', { type: 'answer', payload: { sdp: `v=0 conformance answer\r\na=fingerprint:sha-256 ${Array(32).fill('AB').join(':')}` } })).status, 201);
    assert.equal((await op('POST', '/signals', { type: 'candidate', payload: { candidate: 'candidate:7 1 udp 2122260223 192.0.2.20 50001 typ host', sdpMid: '0', sdpMLineIndex: 0 } })).status, 201);
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal((await op('POST', '/decision', { result: 'VERIFIED' })).status, 200);

    const code = await exited;
    assert.equal(code, 0, output);
    // Written by the JVM test only when it ran (not skipped) and passed.
    assert.ok(existsSync(`${file}.done`), `the JVM test ran: ${output.slice(-2000)}`);
    const states = readFileSync(`${file}.done`, 'utf8');
    assert.match(states, /WaitingForOperator.*Connecting|WaitingForOperator.*Connected/, states);
    assert.equal((await bank.call('GET', `/v1/authorizations/${auth.authorizationId}/verification-plan`)).json.status, 'VERIFIED');
  });
});
