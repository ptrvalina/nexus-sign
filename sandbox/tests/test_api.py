"""End-to-end tests against a running sandbox, one per row of README.md#control-test-matrix."""

import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
sys.path.insert(0, str(ROOT / 'tools'))
import protocol  # noqa: E402
from device_simulator import Device  # noqa: E402

WEBHOOK_SECRET = b'test-provider-secret'
server = None
BASE = None


def setUpModule():
    global server, BASE
    env = dict(os.environ, PORT='0', PYTHONDONTWRITEBYTECODE='1',
               SANDBOX_PROVIDER_WEBHOOK_SECRET=WEBHOOK_SECRET.decode())
    server = subprocess.Popen([sys.executable, str(ROOT / 'server' / 'main.py')], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = server.stdout.readline()
    if 'http://' not in line:
        server.kill()
        raise RuntimeError('sandbox did not start: ' + line + server.stdout.read())
    BASE = line.strip().split(' ')[-1]


def tearDownModule():
    server.terminate()
    server.wait(timeout=5)


def call(method, path, body=None, headers=None, raw=None):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    request = urllib.request.Request(BASE + path, data=data, method=method,
                                     headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        payload = err.read()
        try:
            return err.code, json.loads(payload)
        except ValueError:
            return err.code, payload


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(call('POST', '/api/v1/reset')[0], 200)
        self.device = Device(BASE)
        self.device.enrol('unit test phone')

    def create(self, key=None, **overrides):
        body = {'credentialId': self.device.credential_id, 'amountMinor': '125000', 'currency': 'PLN',
                'beneficiary': {'name': 'Jan Kowalski', 'iban': 'PL61109010140000071219812874'}}
        body.update(overrides)
        return call('POST', '/api/v1/authorizations', body, {'Idempotency-Key': key or 'k-' + uuid.uuid4().hex})

    def advance_to_signature(self, authorization_id):
        for _ in range(10):
            status, auth = call('GET', f'/api/v1/authorizations/{authorization_id}')
            steps = [s for s in auth['verificationPlan']['steps'] if s['status'] == 'PENDING']
            if steps[0]['factor'] == 'SIGNATURE':
                return auth
            self.assertEqual(call('POST', f'/api/v1/authorizations/{authorization_id}/advance')[0], 200)
        self.fail('never reached SIGNATURE')

    def factors(self, auth):
        return [s['factor'] for s in auth['verificationPlan']['steps']]


class Protocol(SandboxTest):
    def test_authorization_is_accepted_by_the_sdk_validator(self):
        status, auth = self.create()
        self.assertEqual(status, 201)
        signed = protocol.verify_envelope(auth)  # the SDK's WYSIWYS check, incl. policy_version
        self.assertEqual(set(signed), protocol.FIELDS)
        self.assertEqual(signed['amount_minor'], '125000')
        self.assertEqual(signed['beneficiary'], {'name': 'Jan Kowalski', 'iban': 'PL61109010140000071219812874'})
        self.assertRegex(signed['issued_at'], r'\.\d{3}Z$')
        self.assertRegex(signed['nonce'], r'^[0-9a-f]{64}$')
        uuid.UUID(signed['authorization_id'])
        self.assertEqual(auth['canonicalPayloadHash'],
                         hashlib.sha256(base64.b64decode(auth['canonicalPayloadBase64'])).hexdigest())


class HappyPath(SandboxTest):
    def test_standard_flow_der_signature(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.assertEqual(self.factors(auth), ['PUSH', 'SIGNATURE', 'VERIFY', 'COMMIT'])
        self.advance_to_signature(aid)
        status, result = self.device.approve(aid, 'der')
        self.assertEqual((status, result['status']), (200, 'VERIFIED'))
        status, committed = call('POST', f'/api/v1/authorizations/{aid}/commit')
        self.assertEqual((status, committed['state']), (200, 'COMMITTED'))
        self.assertTrue(committed['bankTransaction']['reference'].startswith('BANK-SBX-'))
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/commit')[0], 409)

    def test_raw_signature_format_as_produced_by_webcrypto(self):
        _, auth = self.create()
        self.advance_to_signature(auth['authorizationId'])
        self.assertEqual(self.device.approve(auth['authorizationId'], 'raw')[1]['status'], 'VERIFIED')


class Idempotency(SandboxTest):
    def test_same_key_same_body_returns_same_authorization(self):
        s1, a1 = self.create(key='idem-key-0001', transactionReference='REF-1')
        s2, a2 = self.create(key='idem-key-0001', transactionReference='REF-1')
        self.assertEqual((s1, s2), (201, 200))
        self.assertEqual(a1['authorizationId'], a2['authorizationId'])
        self.assertEqual(a1['canonicalPayloadBase64'], a2['canonicalPayloadBase64'])

    def test_same_key_different_body_conflicts(self):
        self.create(key='idem-key-0002')
        status, body = self.create(key='idem-key-0002', amountMinor='999')
        self.assertEqual((status, body['error']), (409, 'IDEMPOTENCY_KEY_REUSED'))

    def test_transaction_reference_reuse_conflicts(self):
        self.create(transactionReference='REF-DUP')
        status, body = self.create(transactionReference='REF-DUP')
        self.assertEqual((status, body['error']), (409, 'TRANSACTION_REFERENCE_REUSED'))

    def test_missing_key(self):
        status, body = call('POST', '/api/v1/authorizations', {'credentialId': self.device.credential_id})
        self.assertEqual((status, body['error']), (400, 'IDEMPOTENCY_KEY_REQUIRED'))


class TransactionBinding(SandboxTest):
    def test_signature_over_altered_payload_is_rejected(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        altered = json.loads(base64.b64decode(auth['canonicalPayloadBase64']))
        altered['amount_minor'] = '1'
        signature = self.device.sign_bytes(protocol.canonical_bytes(altered))
        _, result = call('POST', f'/api/v1/authorizations/{aid}/signature', {'signature': signature, 'signatureFormat': 'der'})
        self.assertEqual((result['status'], result['reason']), ('FAILED', 'signature_verification_failed'))

    def test_signature_from_another_authorization_is_rejected(self):
        _, first = self.create()
        self.advance_to_signature(first['authorizationId'])
        self.device.approve(first['authorizationId'])
        replayed = call('GET', f"/api/v1/authorizations/{first['authorizationId']}")[1]['signature']
        _, second = self.create()
        self.advance_to_signature(second['authorizationId'])
        _, result = call('POST', f"/api/v1/authorizations/{second['authorizationId']}/signature",
                         {'signature': replayed, 'signatureFormat': 'der'})
        self.assertEqual(result['status'], 'FAILED')

    def test_resubmitting_a_used_signature_is_refused(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        self.device.approve(aid)
        signature = call('GET', f'/api/v1/authorizations/{aid}')[1]['signature']
        status, body = call('POST', f'/api/v1/authorizations/{aid}/signature', {'signature': signature, 'signatureFormat': 'der'})
        self.assertEqual((status, body['error']), (409, 'AUTHORIZATION_NOT_PENDING'))

    def test_key_of_another_device_is_rejected(self):
        _, auth = self.create()
        self.advance_to_signature(auth['authorizationId'])
        intruder = Device(BASE)
        intruder.enrol('other phone')
        self.assertEqual(intruder.approve(auth['authorizationId'])[1]['status'], 'FAILED')

    def test_control_plane_cannot_complete_the_signature(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        status, body = call('POST', f'/api/v1/authorizations/{aid}/advance')
        self.assertEqual((status, body['error']), (409, 'DEVICE_SIGNATURE_REQUIRED'))
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/commit')[0], 409)

    def test_signature_before_verification_steps_is_refused(self):
        _, auth = self.create()
        status, body = self.device.approve(auth['authorizationId'])
        self.assertEqual((status, body['error']), (409, 'VERIFICATION_STEPS_INCOMPLETE'))


class AdaptiveVerification(SandboxTest):
    def test_push_timeout_escalates_to_audio(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        _, after = call('POST', f'/api/v1/authorizations/{aid}/fault', {'type': 'push_timeout'})
        self.assertEqual(self.factors(after), ['PUSH', 'AUDIO', 'SIGNATURE', 'VERIFY', 'COMMIT'])
        self.assertIn('PUSH_TIMEOUT', after['verificationPlan']['reasons'])

    def test_push_timeout_scenario(self):
        _, auth = self.create(scenario='push-timeout')
        _, after = call('POST', f"/api/v1/authorizations/{auth['authorizationId']}/advance")
        self.assertIn('AUDIO', self.factors(after))

    def test_high_value_requires_audio_and_video(self):
        _, auth = self.create(amountMinor='6000000')
        self.assertEqual(self.factors(auth), ['PUSH', 'AUDIO', 'VIDEO', 'SIGNATURE', 'VERIFY', 'COMMIT'])
        _, step_up = self.create(riskDecision='STEP_UP')
        self.assertEqual(self.factors(step_up)[:3], ['PUSH', 'AUDIO', 'VIDEO'])

    def test_high_value_full_flow(self):
        _, auth = self.create(amountMinor='6000000')
        aid = auth['authorizationId']
        ready = self.advance_to_signature(aid)
        self.assertEqual([a['factor'] for a in ready['verificationPlan']['steps'] if a['status'] == 'COMPLETED'],
                         ['PUSH', 'AUDIO', 'VIDEO'])
        self.assertEqual(len(ready['bankTransaction'] or []), 0)
        self.device.approve(aid)
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/commit')[1]['state'], 'COMMITTED')

    def test_audio_failure_escalates_to_video_never_downgrades(self):
        _, auth = self.create(scenario='failure')
        aid = auth['authorizationId']
        call('POST', f'/api/v1/authorizations/{aid}/advance')  # PUSH
        _, after = call('POST', f'/api/v1/authorizations/{aid}/advance')  # AUDIO fails
        statuses = {s['factor']: s['status'] for s in after['verificationPlan']['steps']}
        self.assertEqual(statuses['AUDIO'], 'FAILED')
        self.assertEqual(statuses['VIDEO'], 'PENDING')
        status, body = self.device.approve(aid)
        self.assertEqual((status, body['error']), (409, 'VERIFICATION_STEPS_INCOMPLETE'))

    def test_video_failure_rejects(self):
        _, auth = self.create(amountMinor='6000000')
        aid = auth['authorizationId']
        call('POST', f'/api/v1/authorizations/{aid}/advance')  # PUSH
        call('POST', f'/api/v1/authorizations/{aid}/advance')  # AUDIO
        _, after = call('POST', f'/api/v1/authorizations/{aid}/fault', {'type': 'provider_failure'})
        self.assertEqual((after['state'], after['terminalReason']), ('REJECTED', 'VERIFICATION_FAILED'))


class Risk(SandboxTest):
    def test_block_is_rejected_and_cannot_be_signed_or_committed(self):
        status, auth = self.create(riskDecision='BLOCK')
        aid = auth['authorizationId']
        self.assertEqual((status, auth['state'], auth['terminalReason']), (201, 'REJECTED', 'RISK_BLOCK'))
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/advance')[0], 409)
        self.assertEqual(self.device.approve(aid)[0], 409)
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/commit')[0], 409)


class SignatureAbuse(SandboxTest):
    def test_attempt_limit_is_terminal(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        bogus = base64.b64encode(b'\x00' * 64).decode()
        for attempt in range(1, 6):
            _, result = call('POST', f'/api/v1/authorizations/{aid}/signature', {'signature': bogus, 'signatureFormat': 'raw'})
            self.assertEqual(result['attempts'], attempt)
        self.assertEqual(result['reason'], 'signature_attempt_limit')
        self.assertEqual(result['authorization']['state'], 'REJECTED')
        self.assertEqual(self.device.approve(aid)[0], 409)

    def test_malformed_signature_counts_as_attempt(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        _, result = call('POST', f'/api/v1/authorizations/{aid}/signature', {'signature': 'not base64!', 'signatureFormat': 'der'})
        self.assertEqual((result['reason'], result['attempts']), ('malformed_signature', 1))


class Expiry(SandboxTest):
    def test_expired_authorization_cannot_be_signed(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        call('POST', '/api/v1/clock', {'advanceSeconds': 301})
        status, body = self.device.approve(aid)
        self.assertEqual((status, body['error']), (410, 'AUTHORIZATION_EXPIRED'))
        self.assertEqual(call('GET', f'/api/v1/authorizations/{aid}')[1]['state'], 'EXPIRED')

    def test_stale_verification_cannot_be_committed(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        self.device.approve(aid)
        call('POST', '/api/v1/clock', {'advanceSeconds': 301})
        status, body = call('POST', f'/api/v1/authorizations/{aid}/commit')
        self.assertEqual((status, body['error']), (409, 'VERIFICATION_TOO_OLD'))


class ProviderWebhook(SandboxTest):
    def signed(self, body, event_id=None, ts=None, secret=WEBHOOK_SECRET):
        raw = json.dumps(body).encode()
        ts = ts or str(int(time.time()))
        sig = 'v1=' + hmac.new(secret, ts.encode() + b'.' + raw, hashlib.sha256).hexdigest()
        return raw, {'X-NEXUS-Timestamp': ts, 'X-NEXUS-Event-Id': event_id or uuid.uuid4().hex, 'X-NEXUS-Signature': sig}

    def test_invalid_hmac_rejected(self):
        raw, headers = self.signed({'sessionId': 'x'}, secret=b'wrong')
        status, body = call('POST', '/api/v1/webhooks/provider', raw=raw, headers=headers)
        self.assertEqual((status, body['error']), (401, 'WEBHOOK_SIGNATURE_INVALID'))

    def test_non_ascii_signature_is_a_client_error(self):
        raw, headers = self.signed({'sessionId': 'x'})
        headers['X-NEXUS-Signature'] = 'v1=\u00e9' * 8
        status, body = call('POST', '/api/v1/webhooks/provider', raw=raw, headers=headers)
        self.assertEqual((status, body['error']), (401, 'WEBHOOK_SIGNATURE_INVALID'))

    def test_stale_timestamp_rejected(self):
        raw, headers = self.signed({'sessionId': 'x'}, ts=str(int(time.time()) - 3600))
        self.assertEqual(call('POST', '/api/v1/webhooks/provider', raw=raw, headers=headers)[1]['error'],
                         'WEBHOOK_TIMESTAMP_OUT_OF_WINDOW')

    def test_same_event_twice_rejected(self):
        raw, headers = self.signed({'sessionId': 'unknown'}, event_id='evt-dup')
        self.assertEqual(call('POST', '/api/v1/webhooks/provider', raw=raw, headers=headers)[0], 404)
        self.assertEqual(call('POST', '/api/v1/webhooks/provider', raw=raw, headers=headers)[1]['error'], 'WEBHOOK_REPLAY')

    def test_hmac_covers_exact_bytes(self):
        raw, headers = self.signed({'sessionId': 'a', 'result': 'PASSED'})
        altered = raw.replace(b'PASSED', b'FAILED')
        self.assertEqual(call('POST', '/api/v1/webhooks/provider', raw=altered, headers=headers)[0], 401)


class Evidence(SandboxTest):
    def test_chain_links_and_seals_verify(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        self.device.approve(aid)
        call('POST', f'/api/v1/authorizations/{aid}/commit')
        _, evidence = call('GET', '/api/v1/evidence')
        results = [r['result'] for r in evidence['records']]
        self.assertEqual(results, ['CREATED', 'VERIFIED', 'COMMITTED'])
        self.assertEqual(evidence['records'][1]['previousEvidenceHash'], evidence['records'][0]['evidenceHash'])
        self.assertTrue(all(r['canonicalPayloadHash'] == auth['canonicalPayloadHash'] for r in evidence['records']))
        self.assertEqual(call('GET', '/api/v1/evidence/verify')[1],
                         {'valid': True, 'records': 3, 'deviceSignatures': 2, 'offlineCodes': 0, 'head': evidence['records'][-1]['evidenceHash']})
        signed = evidence['records'][1]
        self.assertEqual(signed['signedPayloadBase64'], auth['canonicalPayloadBase64'])
        self.assertIn('BEGIN PUBLIC KEY', signed['credentialPublicKeyPem'])

    def test_resealed_record_with_altered_terms_is_detected(self):
        """Whoever holds the sealing key can re-seal a record, but cannot make
        the customer's key sign different terms."""
        import main
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        self.device.approve(aid)
        _, evidence = call('GET', '/api/v1/evidence')
        record = {k: v for k, v in evidence['records'][1].items() if k not in ('evidenceHash', 'seal')}
        fields = json.loads(base64.b64decode(record['signedPayloadBase64']))
        fields['amount_minor'] = '9900000'
        altered = main.protocol.canonical_bytes(fields)
        record['signedPayloadBase64'] = base64.b64encode(altered).decode()
        record['canonicalPayloadHash'] = main.protocol.sha256_hex(altered)
        record['previousEvidenceHash'] = 'GENESIS'
        key = main.p256.generate_private_key()
        record['evidenceHash'] = main.protocol.sha256_hex(main.protocol.canonical_bytes(record))
        r, s = main.p256.sign(key, record['evidenceHash'].encode('ascii'))
        record['seal'] = {'signature': base64.b64encode(main.p256.rs_to_raw(r, s)).decode()}
        result = main.verify_evidence_chain([record], main.p256.public_key(key))
        self.assertEqual((result['valid'], result['reason']), (False, 'device_signature_invalid'))

    def test_tampering_is_detected(self):
        import main
        _, auth = self.create()
        _, evidence = call('GET', '/api/v1/evidence')
        records = evidence['records']
        public_key = main.p256.public_key_from_spki(base64.b64decode(
            ''.join(evidence['publicKeyPem'].strip().splitlines()[1:-1])))
        self.assertTrue(main.verify_evidence_chain(records, public_key)['valid'])
        records[0]['result'] = 'COMMITTED'
        self.assertEqual(main.verify_evidence_chain(records, public_key)['reason'], 'hash_mismatch')


class OfflineConfirmation(SandboxTest):
    def challenge(self, aid):
        status, body = call('GET', f'/api/v1/authorizations/{aid}/offline-challenge')
        self.assertEqual(status, 200, body)
        return body['qrPayload']

    def test_code_from_the_phone_confirms_and_is_sealed(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        qr = self.challenge(aid)
        self.assertTrue(qr.startswith('NXS1.'))
        svg = call('GET', f'/api/v1/authorizations/{aid}/offline-challenge')[1]['qrSvg']
        self.assertTrue(svg.startswith('<svg') and 'viewBox' in svg)
        canonical, signed = self.device.read_offline_challenge(qr)
        self.assertEqual(canonical, base64.b64decode(auth['canonicalPayloadBase64']))
        self.assertEqual(signed['amount_minor'], '125000')
        status, result = call('POST', f'/api/v1/authorizations/{aid}/offline-confirmation', {'code': self.device.offline_code(qr)})
        self.assertEqual((status, result['status']), (200, 'VERIFIED'))
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/commit')[1]['state'], 'COMMITTED')
        _, evidence = call('GET', '/api/v1/evidence')
        self.assertEqual(evidence['records'][1]['confirmationMethod'], 'OFFLINE_CODE')
        verified = call('GET', '/api/v1/evidence/verify')[1]
        self.assertEqual((verified['valid'], verified['offlineCodes'], verified['deviceSignatures']), (True, 2, 0))

    def test_wrong_codes_count_towards_the_attempt_limit(self):
        _, auth = self.create()
        aid = auth['authorizationId']
        self.advance_to_signature(aid)
        right = self.device.offline_code(self.challenge(aid))
        wrong = str((int(right) + 1) % 100_000_000).zfill(8)
        for attempt in range(1, 5):
            result = call('POST', f'/api/v1/authorizations/{aid}/offline-confirmation', {'code': wrong})[1]
            self.assertEqual((result['status'], result['attempts']), ('FAILED', attempt))
        last = call('POST', f'/api/v1/authorizations/{aid}/offline-confirmation', {'code': wrong})[1]
        self.assertEqual(last['reason'], 'signature_attempt_limit')
        self.assertEqual(call('POST', f'/api/v1/authorizations/{aid}/offline-confirmation', {'code': right})[0], 409,
                         'the right code no longer helps once the authorization is rejected')

    def test_a_code_is_bound_to_its_authorization_and_device(self):
        _, first = self.create()
        _, second = self.create()
        for aid in (first['authorizationId'], second['authorizationId']):
            self.advance_to_signature(aid)
        code_for_first = self.device.offline_code(self.challenge(first['authorizationId']))
        result = call('POST', f'/api/v1/authorizations/{second["authorizationId"]}/offline-confirmation', {'code': code_for_first})[1]
        self.assertEqual(result['status'], 'FAILED')
        other = Device(BASE)
        other.enrol('another phone')
        with self.assertRaises(protocol.Rejected):
            other.read_offline_challenge(self.challenge(first['authorizationId']))

    def test_not_offered_before_the_signature_step(self):
        _, auth = self.create(scenario='high-value')
        status, body = call('GET', f'/api/v1/authorizations/{auth["authorizationId"]}/offline-challenge')
        self.assertEqual((status, body['error']), (409, 'VERIFICATION_STEPS_INCOMPLETE'))
        status, body = call('POST', f'/api/v1/authorizations/{auth["authorizationId"]}/offline-confirmation', {'code': '1234'})
        self.assertEqual(status, 409)


class InputHandling(SandboxTest):
    def test_invalid_inputs_return_400(self):
        cases = {
            'letters in amount': {'amountMinor': 'abc'},
            'negative amount': {'amountMinor': '-100'},
            'numeric amount': {'amountMinor': 125000},
            'leading zero': {'amountMinor': '0100'},
            'zero amount': {'amountMinor': '0'},
            'lowercase currency': {'currency': 'pln'},
            'beneficiary as string': {'beneficiary': 'Jan'},
            'integer-like beneficiary key': {'beneficiary': {'name': 'x', '0': 'y'}},
            'nested beneficiary': {'beneficiary': {'name': {'first': 'Jan'}}},
            'missing beneficiary name': {'beneficiary': {'iban': 'PL61'}},
            'line break in beneficiary name': {'beneficiary': {'name': 'ACME\nPL00 0000'}},
            'bidi override in beneficiary name': {'beneficiary': {'name': 'Jan \u202eikswoloK'}},
            'unknown scenario': {'scenario': 'nope'},
            'unknown risk decision': {'riskDecision': 'MAYBE'},
            'bad transaction reference': {'transactionReference': '<script>'},
        }
        for name, override in cases.items():
            with self.subTest(name):
                status, body = self.create(**override)
                self.assertEqual(status, 400, body)

    def test_unknown_credential(self):
        status, body = self.create(credentialId=str(uuid.uuid4()))
        self.assertEqual((status, body['error']), (404, 'CREDENTIAL_NOT_FOUND'))

    def test_malformed_json_and_oversized_body(self):
        self.assertEqual(call('POST', '/api/v1/authorizations', raw=b'{nope', headers={'Idempotency-Key': 'k-12345678'})[0], 400)
        self.assertEqual(call('POST', '/api/v1/authorizations', raw=b'[]', headers={'Idempotency-Key': 'k-12345678'})[0], 400)
        self.assertEqual(call('POST', '/api/v1/devices', raw=b' ' * 70000)[0], 413)

    def test_invalid_public_key(self):
        status, body = call('POST', '/api/v1/devices', {'publicKeySpkiBase64': base64.b64encode(b'\x30' * 91).decode()})
        self.assertEqual((status, body['error']), (400, 'INVALID_PUBLIC_KEY'))

    def test_html_in_beneficiary_is_data_not_markup(self):
        status, auth = self.create(beneficiary={'name': '<img src=x onerror=alert(1)>'})
        self.assertEqual(status, 201)
        self.assertEqual(protocol.verify_envelope(auth)['beneficiary']['name'], '<img src=x onerror=alert(1)>')


class StaticFiles(SandboxTest):
    def raw_get(self, path):
        with socket.create_connection((BASE.split('//')[1].split(':')[0], int(BASE.rsplit(':', 1)[1]))) as sock:
            sock.sendall(f'GET {path} HTTP/1.0\r\n\r\n'.encode())
            data = b''
            while chunk := sock.recv(65536):
                data += chunk
        return int(data.split(b' ', 2)[1]), data

    def test_path_traversal_is_not_served(self):
        for path in ('/web/../../../../etc/hostname', '/web/../server/main.py', '/web/%2e%2e/config/policy.json',
                     '/config/policy.json', '/server/main.py'):
            with self.subTest(path):
                status, data = self.raw_get(path)
                self.assertEqual(status, 404)

    def test_ui_served_with_security_headers(self):
        status, data = self.raw_get('/')
        self.assertEqual(status, 200)
        self.assertIn(b"Content-Security-Policy: default-src 'self'", data)
        self.assertIn(b'X-Content-Type-Options: nosniff', data)


if __name__ == '__main__':
    unittest.main()
