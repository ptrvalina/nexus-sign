"""Hosted mode: access codes, isolated workspaces, session cookies, limits."""

import http.client
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import access  # noqa: E402

BANK_A = 'bank-a:AcmeTestCode4f7Qz9LmX2pR'
BANK_B = 'bank-b:PartnerCode8kW3nV6tY1sD'


class HostedServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = dict(os.environ, PORT='0', PYTHONDONTWRITEBYTECODE='1', SANDBOX_INSECURE_COOKIES='1',
                   SANDBOX_ACCESS_CODES=f'{BANK_A},{BANK_B}', SANDBOX_SESSION_SECRET='test-secret')
        cls.server = subprocess.Popen([sys.executable, str(ROOT / 'server' / 'main.py')], env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = cls.server.stdout.readline()
        if 'http://' not in line:
            cls.server.kill()
            raise RuntimeError(line + cls.server.stdout.read())
        cls.port = int(line.strip().rsplit(':', 1)[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)

    def call(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        conn.request(method, path, body=None if body is None else json.dumps(body),
                     headers={'Content-Type': 'application/json', **(headers or {})})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        is_json = (response.getheader('Content-Type') or '').startswith('application/json')
        return response.status, (json.loads(data) if data and is_json else {}), response.getheader('Set-Cookie')

    def bearer(self, entry):
        return {'Authorization': 'Bearer ' + entry.split(':', 1)[1]}

    def test_api_requires_authentication(self):
        for path in ('/api/v1/state', '/api/v1/policy', '/api/v1/evidence'):
            self.assertEqual(self.call('GET', path)[0], 401)
        self.assertEqual(self.call('POST', '/api/v1/reset')[0], 401)
        self.assertEqual(self.call('GET', '/api/v1/health')[0], 200)
        self.assertEqual(self.call('GET', '/')[0], 200)

    def test_login_sets_hardened_cookie_and_cookie_works(self):
        status, body, cookie = self.call('POST', '/api/v1/session', {'accessCode': BANK_A.split(':', 1)[1]})
        self.assertEqual((status, body['workspace']), (200, 'bank-a'))
        for flag in ('HttpOnly', 'SameSite=Strict', 'Path=/'):
            self.assertIn(flag, cookie)
        session = cookie.split(';', 1)[0]
        status, body, _ = self.call('GET', '/api/v1/session', headers={'Cookie': session})
        self.assertEqual((status, body['workspace']), (200, 'bank-a'))
        tampered = session.replace('bank-a', 'bank-b', 1)
        self.assertEqual(self.call('GET', '/api/v1/state', headers={'Cookie': tampered})[0], 401)

    def test_wrong_code_rejected(self):
        status, body, cookie = self.call('POST', '/api/v1/session', {'accessCode': 'x' * 24},
                                         {'X-Forwarded-For': '203.0.113.9'})
        self.assertEqual((status, body['error'], cookie), (401, 'INVALID_ACCESS_CODE', None))

    def test_workspaces_are_isolated(self):
        a, b = self.bearer(BANK_A), self.bearer(BANK_B)
        spki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=='
        status, device, _ = self.call('POST', '/api/v1/devices', {'publicKeySpkiBase64': spki}, a)
        self.assertEqual(status, 201)
        _, state_b, _ = self.call('GET', '/api/v1/state', headers=b)
        self.assertNotIn(device['credentialId'], [d['credentialId'] for d in state_b['devices']])
        self.call('POST', '/api/v1/reset', headers=b)
        _, state_a, _ = self.call('GET', '/api/v1/state', headers=a)
        self.assertIn(device['credentialId'], [d['credentialId'] for d in state_a['devices']])


    def test_logout_revokes_cookie_on_the_server(self):
        _, _, cookie = self.call('POST', '/api/v1/session', {'accessCode': BANK_A.split(':', 1)[1]})
        session = cookie.split(';', 1)[0]
        self.assertEqual(self.call('GET', '/api/v1/state', headers={'Cookie': session})[0], 200)
        self.assertEqual(self.call('POST', '/api/v1/session/logout', headers={'Cookie': session})[0], 200)
        self.assertEqual(self.call('GET', '/api/v1/state', headers={'Cookie': session})[0], 401)

    def test_malformed_credentials_are_client_errors(self):
        for body in ({'accessCode': 12345}, {'accessCode': None}, {'accessCode': ['x']}):
            with self.subTest(body=body):
                status, response, _ = self.call('POST', '/api/v1/session', body, {'X-Forwarded-For': '203.0.113.50'})
                self.assertEqual((status, response['error']), (401, 'INVALID_ACCESS_CODE'))
        status, _, _ = self.call('GET', '/api/v1/state', headers={'Cookie': 'nxs_session=bank-a.9999999999.ab.\u00e9\u00e9'})
        self.assertEqual(status, 401)

class AccessConfiguration(unittest.TestCase):
    def test_rejects_weak_or_malformed_codes(self):
        for raw in ('bank:short', 'Bank:' + 'x' * 20, 'nocolon', f'{BANK_A},{BANK_A}', 'a:' + 'x' * 20):
            with self.subTest(raw=raw[:12]):
                with self.assertRaises(access.ConfigurationError):
                    access.parse_access_codes(raw)

    def test_login_rate_limit(self):
        control = access.AccessControl(raw_codes=BANK_A, session_secret='s')
        for _ in range(access.LOGIN_FAILURES_PER_WINDOW):
            self.assertTrue(control.login_allowed('198.51.100.1'))
            control.record_failure('198.51.100.1')
        self.assertFalse(control.login_allowed('198.51.100.1'))
        self.assertTrue(control.login_allowed('198.51.100.2'))

    def test_expired_cookie_rejected(self):
        control = access.AccessControl(raw_codes=BANK_A, session_secret='s')
        cookie = control.issue_cookie('bank-a').split(';', 1)[0]
        self.assertEqual(control.workspace_from_cookie(cookie), 'bank-a')
        name, value = cookie.split('=', 1)
        workspace, expires, session_id, mac = value.split('.')
        self.assertIsNone(control.workspace_from_cookie(f'{name}={workspace}.1.{session_id}.{mac}'))

    def test_short_or_repetitive_codes_are_refused(self):
        for raw in ('bank-a:ShortCode123', 'bank-a:' + 'ab' * 12):
            with self.assertRaises(access.ConfigurationError):
                access.AccessControl(raw_codes=raw, session_secret='s')

    def test_rotated_code_invalidates_cookies(self):
        before = access.AccessControl(raw_codes=BANK_A, session_secret='s')
        cookie = before.issue_cookie('bank-a').split(';', 1)[0]
        rotated = access.AccessControl(raw_codes='bank-a:RotatedCode5hJ2gF9cK7qN', session_secret='s')
        self.assertEqual(before.workspace_from_cookie(cookie), 'bank-a')
        self.assertIsNone(rotated.workspace_from_cookie(cookie))

    def test_bearer_codes_are_rate_limited(self):
        headers = {'Authorization': 'Bearer ' + 'y' * 24, 'X-Forwarded-For': '203.0.113.77'}
        control = access.AccessControl(raw_codes=BANK_A, session_secret='s')
        for _ in range(access.LOGIN_FAILURES_PER_WINDOW):
            self.assertIsNone(control.resolve(headers, '203.0.113.77'))
        with self.assertRaises(access.TooManyAttempts):
            control.resolve({'Authorization': 'Bearer ' + BANK_A.split(':', 1)[1]}, '203.0.113.77')
        self.assertEqual(control.resolve({'Authorization': 'Bearer ' + BANK_A.split(':', 1)[1]}, '203.0.113.78'), 'bank-a')

    def test_failure_tracker_stays_bounded_under_many_addresses(self):
        control = access.AccessControl(raw_codes=BANK_A, session_secret='s')
        limit = access.MAX_TRACKED_CLIENTS
        for i in range(limit + 500):
            control.record_failure(f'10.{i // 65536}.{(i // 256) % 256}.{i % 256}')
        self.assertLessEqual(len(control._failures), limit)
        for _ in range(3 * access.LOGIN_FAILURES_PER_WINDOW):
            control.record_failure('198.51.100.9')
        self.assertEqual(len(control._failures['198.51.100.9']), access.LOGIN_FAILURES_PER_WINDOW)
        self.assertFalse(control.login_allowed('198.51.100.9'))

    def test_sign_out_survives_a_restart_with_a_revocation_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'revoked')
            previous = os.environ.get('SANDBOX_REVOKED_SESSIONS_FILE')
            os.environ['SANDBOX_REVOKED_SESSIONS_FILE'] = path
            try:
                first = access.AccessControl(raw_codes=BANK_A, session_secret='s')
                cookie = first.issue_cookie('bank-a').split(';', 1)[0]
                first.revoke_cookie(cookie)
                restarted = access.AccessControl(raw_codes=BANK_A, session_secret='s')
                self.assertIsNone(restarted.workspace_from_cookie(cookie))
                self.assertEqual(restarted.workspace_from_cookie(restarted.issue_cookie('bank-a').split(';', 1)[0]), 'bank-a')
            finally:
                if previous is None:
                    os.environ.pop('SANDBOX_REVOKED_SESSIONS_FILE', None)
                else:
                    os.environ['SANDBOX_REVOKED_SESSIONS_FILE'] = previous

    def test_local_mode_refuses_public_interface(self):
        env = dict(os.environ, PORT='0', HOST='0.0.0.0', PYTHONDONTWRITEBYTECODE='1')
        env.pop('SANDBOX_ACCESS_CODES', None)
        result = subprocess.run([sys.executable, str(ROOT / 'server' / 'main.py')], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('without SANDBOX_ACCESS_CODES', result.stderr + result.stdout)


if __name__ == '__main__':
    unittest.main()
