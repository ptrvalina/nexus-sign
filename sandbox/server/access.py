"""Access control for a hosted sandbox.

Local mode (default): no access codes configured, one shared workspace, no
login. Suitable for 127.0.0.1 only.

Hosted mode: SANDBOX_ACCESS_CODES lists one access code per guest, e.g.

    SANDBOX_ACCESS_CODES="acme-bank:9fQ2kd7LwZ...,partner-x:Tn4e..."

Every code opens its own isolated workspace (devices, authorizations,
evidence, clock), so one bank never sees or resets another's session. The
browser exchanges the code for a signed, HttpOnly session cookie; scripts send
it as `Authorization: Bearer <code>`.
"""

import hashlib
import hmac
import os
import re
import secrets
import threading
import time

WORKSPACE_NAME = re.compile(r'^[a-z0-9][a-z0-9-]{1,31}$')
MIN_CODE_LENGTH = 22
MIN_DISTINCT_CHARACTERS = 10
SESSION_TTL_SECONDS = int(os.environ.get('SANDBOX_SESSION_TTL_SECONDS', str(12 * 3600)))
COOKIE_NAME = 'nxs_session'
LOGIN_FAILURES_PER_WINDOW = 10
LOGIN_WINDOW_SECONDS = 900
MAX_TRACKED_CLIENTS = 10_000


class ConfigurationError(ValueError):
    pass


def parse_access_codes(raw):
    """'name:code,name:code' -> {code: name}. Refuses weak or duplicate entries."""
    codes = {}
    names = set()
    for entry in filter(None, (e.strip() for e in (raw or '').split(','))):
        name, sep, code = entry.partition(':')
        if not sep or not WORKSPACE_NAME.match(name):
            raise ConfigurationError(f'invalid entry {entry[:20]!r}: expected name:code, name like "acme-bank"')
        if len(code) < MIN_CODE_LENGTH:
            raise ConfigurationError(f'access code for {name!r} is shorter than {MIN_CODE_LENGTH} characters')
        if len(set(code)) < MIN_DISTINCT_CHARACTERS:
            raise ConfigurationError(f'access code for {name!r} is too repetitive; generate one with tools/new_access_code.py')
        if name in names or code in codes:
            raise ConfigurationError(f'duplicate workspace or code for {name!r}')
        names.add(name)
        codes[code] = name
    return codes


class AccessControl:
    def __init__(self, raw_codes=None, session_secret=None, secure_cookies=True):
        self.codes = parse_access_codes(raw_codes if raw_codes is not None else os.environ.get('SANDBOX_ACCESS_CODES'))
        secret = session_secret if session_secret is not None else os.environ.get('SANDBOX_SESSION_SECRET', '')
        # Without a configured secret, sessions end when the process restarts.
        self.secret = secret.encode() if secret else secrets.token_bytes(32)
        self.secure_cookies = secure_cookies
        self._failures = {}
        self._revoked = {}  # session id -> expiry, for signed-out cookies
        self._lock = threading.Lock()
        # With SANDBOX_SESSION_SECRET set, cookies outlive a restart, so a
        # sign-out must too: revoked session IDs are kept in this file.
        self._revocation_file = os.environ.get('SANDBOX_REVOKED_SESSIONS_FILE') or None
        self._load_revocations()

    def _load_revocations(self):
        if not self._revocation_file or not os.path.exists(self._revocation_file):
            return
        now = time.time()
        with open(self._revocation_file, encoding='ascii') as f:
            for line in f:
                session_id, _, expires = line.strip().partition(' ')
                if re.fullmatch(r'[0-9a-f]{32}', session_id) and expires.isdigit() and int(expires) > now:
                    self._revoked[session_id] = int(expires)

    @property
    def hosted(self):
        return bool(self.codes)

    def workspace_names(self):
        return sorted(self.codes.values()) if self.hosted else ['local']

    # --- Access codes ---

    def check_code(self, code):
        """Returns the workspace name for a valid code, else None. Compares
        against every configured code so timing does not reveal which exist."""
        if not isinstance(code, str):
            return None
        match = None
        candidate = code.encode('utf-8', 'surrogateescape')
        for known, name in self.codes.items():
            if hmac.compare_digest(known.encode(), candidate):
                match = name
        return match

    def login_allowed(self, client):
        now = time.time()
        with self._lock:
            recent = [t for t in self._failures.get(client, []) if now - t < LOGIN_WINDOW_SECONDS]
            if recent:
                self._failures[client] = recent
            else:
                self._failures.pop(client, None)
            return len(recent) < LOGIN_FAILURES_PER_WINDOW

    def record_failure(self, client):
        now = time.time()
        with self._lock:
            if client not in self._failures and len(self._failures) >= MAX_TRACKED_CLIENTS:
                # Drop clients whose failures have all aged out, then, if the
                # table is still full, the clients whose last failure is oldest:
                # memory stays bounded under a flood of source addresses.
                for key in [k for k, v in self._failures.items() if now - v[-1] >= LOGIN_WINDOW_SECONDS]:
                    del self._failures[key]
                if len(self._failures) >= MAX_TRACKED_CLIENTS:
                    oldest = sorted(self._failures, key=lambda k: self._failures[k][-1])
                    for key in oldest[:len(self._failures) - MAX_TRACKED_CLIENTS + 1]:
                        del self._failures[key]
            # Only the failures inside the window matter, and at most the limit.
            recent = [t for t in self._failures.get(client, []) if now - t < LOGIN_WINDOW_SECONDS]
            self._failures[client] = (recent + [now])[-LOGIN_FAILURES_PER_WINDOW:]

    # --- Session cookies ---

    def _mac(self, workspace, payload):
        # Keyed by the workspace's current access code: a rotated code
        # invalidates every cookie issued for the old one.
        code = next((c for c, name in self.codes.items() if name == workspace), None)
        if code is None:
            return None
        key = hmac.new(self.secret, code.encode(), hashlib.sha256).digest()
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    def issue_cookie(self, workspace):
        expires = int(time.time()) + SESSION_TTL_SECONDS
        payload = f'{workspace}.{expires}.{secrets.token_hex(16)}'
        value = f'{payload}.{self._mac(workspace, payload)}'
        flags = f'Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict'
        return f'{COOKIE_NAME}={value}; {flags}' + ('; Secure' if self.secure_cookies else '')

    def clear_cookie(self):
        return f'{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict' + ('; Secure' if self.secure_cookies else '')

    def _session_from_cookie(self, header):
        """(workspace, session id, expiry) for a valid, unrevoked cookie, else None."""
        for part in (header or '').split(';'):
            key, _, value = part.strip().partition('=')
            if key != COOKIE_NAME:
                continue
            fields = value.split('.')
            if len(fields) != 4:
                continue
            workspace, expires, session_id, mac = fields
            expected = self._mac(workspace, f'{workspace}.{expires}.{session_id}')
            if (expected is None or not expires.isdigit() or int(expires) <= time.time()
                    or not hmac.compare_digest(expected.encode(), mac.encode('utf-8', 'surrogateescape'))):
                continue
            with self._lock:
                if session_id in self._revoked:
                    continue
            return workspace, session_id, int(expires)
        return None

    def workspace_from_cookie(self, header):
        session = self._session_from_cookie(header)
        return session[0] if session else None

    def revoke_cookie(self, header):
        """Signs a browser session out on the server, not only in the browser."""
        session = self._session_from_cookie(header)
        if not session:
            return
        now = time.time()
        with self._lock:
            for key in [k for k, exp in self._revoked.items() if exp <= now]:
                del self._revoked[key]
            self._revoked[session[1]] = session[2]
            if self._revocation_file:
                tmp = f'{self._revocation_file}.tmp'
                with open(tmp, 'w', encoding='ascii') as f:
                    f.writelines(f'{k} {v}\n' for k, v in self._revoked.items())
                os.replace(tmp, self._revocation_file)

    def resolve(self, headers, client=None):
        """Workspace for a request, or None when it is not authenticated.
        Bearer codes count towards the same failure limit as the sign-in form."""
        if not self.hosted:
            return 'local'
        auth = headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            if client is not None and not self.login_allowed(client):
                raise TooManyAttempts()
            workspace = self.check_code(auth[7:].strip())
            if workspace is None and client is not None:
                self.record_failure(client)
            return workspace
        return self.workspace_from_cookie(headers.get('Cookie'))


class TooManyAttempts(Exception):
    pass


def generate_code():
    return secrets.token_urlsafe(24)
