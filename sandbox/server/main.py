#!/usr/bin/env python3
"""NEXUS-SIGN sandbox.

A single-process model of the NEXUS-SIGN authorization layer for workshops and
integration rehearsals. It speaks the production v1 signing protocol: the
canonical bytes, their hash and the device signature are exactly what Auth
Core and the mobile SDKs produce and accept. What is simulated is everything
around that core — bank back office, push delivery, audio/video providers,
HSM custody — and all of it is labeled as such.

Standard library only; run with `python3 server/main.py`.
"""

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import access
import p256
import protocol
import qr

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'config' / 'policy.json').read_text(encoding='utf-8'))
HOST = os.environ.get('HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', '8787'))

TRUST_PROXY = os.environ.get('SANDBOX_TRUST_PROXY') == '1'
MAX_AUTHORIZATIONS = int(os.environ.get('SANDBOX_MAX_AUTHORIZATIONS', '300'))
MAX_DEVICES = 100

# Shared secret of the simulated audio/video provider. It exists only in this
# process and the browser never sees it; set it explicitly only to send
# provider webhooks from your own test harness.
_provider_secret = os.environ.get('SANDBOX_PROVIDER_WEBHOOK_SECRET')
PROVIDER_WEBHOOK_SECRET = _provider_secret.encode() if _provider_secret else secrets.token_bytes(32)

STATIC_FILES = {
    '/': ('web/index.html', 'text/html; charset=utf-8'),
    '/index.html': ('web/index.html', 'text/html; charset=utf-8'),
    '/web/app.js': ('web/app.js', 'text/javascript; charset=utf-8'),
    '/web/styles.css': ('web/styles.css', 'text/css; charset=utf-8'),
}

SCENARIOS = ('standard', 'push-timeout', 'high-value', 'user-request', 'failure')
RISK_DECISIONS = ('ALLOW', 'STEP_UP', 'BLOCK')
PENDING_STATES = ('PENDING',)
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
PRINTABLE_REF = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$')
OPERATION_TYPE = re.compile(r'^[a-z][a-z0-9_]{0,31}$')
IDEMPOTENCY_KEY = re.compile(r'^[A-Za-z0-9._:-]{8,128}$')

lock = threading.RLock()


class ApiError(Exception):
    def __init__(self, status, error, detail=None):
        super().__init__(error)
        self.status, self.error, self.detail = status, error, detail


# --- Sandbox clock ---
# Expiry is part of the protocol, so the sandbox lets tests and demos move time
# forward instead of waiting five minutes.

clock_offset_ms = 0


def now_ms():
    return int(time.time() * 1000) + clock_offset_ms


def iso_ms(ms):
    """RFC 3339 UTC with milliseconds — identical to JavaScript toISOString()."""
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ms // 1000)) + '.%03dZ' % (ms % 1000)


def b64(data):
    return base64.b64encode(data).decode('ascii')


# --- State ---

def empty_state():
    key = p256.generate_private_key()
    return {
        'devices': {}, 'authorizations': {}, 'sessions': {}, 'idempotency': {}, 'references': {},
        'evidence': [], 'events': [], 'webhook_events': set(),
        # Evidence records are sealed with an ephemeral P-256 key standing in
        # for the HSM. It is regenerated on every start and reset.
        'evidence_key': key, 'evidence_public_key': p256.public_key(key),
    }


store = empty_state()


class Workspace:
    """Isolated sandbox state for one access code (or the single local user)."""

    def __init__(self, name):
        self.name = name
        self.store = empty_state()
        self.clock_offset_ms = 0
        self.verified_evidence = None


ACCESS = None
WORKSPACES = {}


def configure_access():
    global ACCESS, WORKSPACES
    ACCESS = access.AccessControl(secure_cookies=os.environ.get('SANDBOX_INSECURE_COOKIES') != '1')
    WORKSPACES = {name: Workspace(name) for name in ACCESS.workspace_names()}


def emit(message, kind='INFO', authorization_id=None):
    event = {'eventId': str(uuid.uuid4()), 'timestamp': iso_ms(now_ms()), 'kind': kind,
             'message': message, 'authorizationId': authorization_id}
    store['events'].insert(0, event)
    del store['events'][200:]
    return event


def append_evidence(auth, result):
    previous = store['evidence'][-1]['evidenceHash'] if store['evidence'] else 'GENESIS'
    record = {
        'schemaVersion': '1',
        'environment': 'SANDBOX',
        'evidenceId': str(uuid.uuid4()),
        'sequence': len(store['evidence']) + 1,
        'recordedAt': iso_ms(now_ms()),
        'authorizationId': auth['id'],
        'nexusId': auth['payload']['nexus_id'],
        'credentialId': auth['payload']['credential_id'],
        'transactionReference': auth['payload']['transaction_reference'],
        'canonicalPayloadHash': auth['hash'],
        'signature': auth['signature'],
        'signatureFormat': auth['signature_format'],
        'signatureAlgorithm': 'HMAC-SHA256' if auth['confirmation_method'] == 'OFFLINE_CODE' else 'ES256',
        # With a signature, the record carries what is needed to check it
        # without the sandbox: the exact bytes signed and the device key.
        **({'confirmationMethod': auth['confirmation_method'],
            'signedPayloadBase64': b64(auth['canonical']),
            'credentialPublicKeyPem': p256.public_key_pem(auth['device_public_key'])} if auth['signature'] else {}),
        'policyReference': auth['payload']['policy_reference'],
        'policyVersion': auth['payload']['policy_version'],
        'verificationPath': [s['factor'] for s in auth['steps'] if s['status'] == 'COMPLETED'],
        'providerAssertions': list(auth['assertions']),
        'result': result,
        'correlationId': auth['correlation_id'],
        'previousEvidenceHash': previous,
    }
    digest = protocol.sha256_hex(protocol.canonical_bytes(record))
    record['evidenceHash'] = digest
    r, s = p256.sign(store['evidence_key'], digest.encode('ascii'))
    record['seal'] = {'algorithm': 'ES256', 'format': 'raw', 'keyId': 'sandbox-ephemeral',
                      'signature': b64(p256.rs_to_raw(r, s))}
    store['evidence'].append(record)
    return record


def verify_device_signature(record):
    """The customer's signature over the sealed bytes, checked with the sealed
    device key. Returns a failure reason or None."""
    try:
        signed = base64.b64decode(record['signedPayloadBase64'], validate=True)
        key = p256.public_key_from_spki(base64.b64decode(''.join(record['credentialPublicKeyPem'].splitlines()[1:-1])))
        r, s = p256.decode_signature(base64.b64decode(record['signature'], validate=True), record['signatureFormat'])
    except (KeyError, ValueError, binascii.Error):
        return 'device_signature_malformed'
    if protocol.sha256_hex(signed) != record.get('canonicalPayloadHash'):
        return 'signed_payload_mismatch'
    if not p256.verify(key, signed, r, s):
        return 'device_signature_invalid'
    return None


def verify_evidence_chain(records, public_key):
    previous = 'GENESIS'
    device_signatures = 0
    offline_codes = 0
    for index, record in enumerate(records):
        body = {k: v for k, v in record.items() if k not in ('evidenceHash', 'seal')}
        if body.get('previousEvidenceHash') != previous:
            return {'valid': False, 'failedAt': index, 'reason': 'chain_broken'}
        digest = protocol.sha256_hex(protocol.canonical_bytes(body))
        if digest != record.get('evidenceHash'):
            return {'valid': False, 'failedAt': index, 'reason': 'hash_mismatch'}
        try:
            r, s = p256.raw_to_rs(base64.b64decode(record['seal']['signature'], validate=True))
        except (KeyError, ValueError, binascii.Error):
            return {'valid': False, 'failedAt': index, 'reason': 'seal_malformed'}
        if not p256.verify(public_key, digest.encode('ascii'), r, s):
            return {'valid': False, 'failedAt': index, 'reason': 'seal_invalid'}
        if record.get('confirmationMethod') == 'OFFLINE_CODE':
            # An HMAC with a key the sandbox also holds: bound to the bytes,
            # but not verifiable by a third party.
            if protocol.sha256_hex(base64.b64decode(record.get('signedPayloadBase64', ''))) != record.get('canonicalPayloadHash'):
                return {'valid': False, 'failedAt': index, 'reason': 'signed_payload_mismatch'}
            offline_codes += 1
        elif record.get('signature'):
            problem = verify_device_signature(record)
            if problem:
                return {'valid': False, 'failedAt': index, 'reason': problem}
            device_signatures += 1
        previous = digest
    return {'valid': True, 'records': len(records), 'deviceSignatures': device_signatures,
            'offlineCodes': offline_codes, 'head': previous}


# --- Authorizations ---

def step(factor):
    return {'factor': factor, 'status': 'PENDING'}


def current_step(auth):
    for s in auth['steps']:
        if s['status'] == 'PENDING':
            return s
    return None


def escalate(auth, factor, reason):
    """Adds a stronger factor before SIGNATURE. Steps are never removed, so a
    verification plan can only become stronger (no downgrade)."""
    if any(s['factor'] == factor for s in auth['steps']):
        return False
    signature_index = next(i for i, s in enumerate(auth['steps']) if s['factor'] == 'SIGNATURE')
    auth['steps'].insert(signature_index, step(factor))
    auth['reasons'].append(reason)
    emit(f'Verification escalated to {factor} ({reason})', 'POLICY', auth['id'])
    return True


def terminate(auth, state, result, message, kind='SECURITY'):
    auth['state'] = state
    auth['terminal_reason'] = result
    emit(message, kind, auth['id'])
    append_evidence(auth, result)


def refresh_expiry(auth):
    if auth['state'] in PENDING_STATES and now_ms() > auth['expires_ms']:
        terminate(auth, 'EXPIRED', 'EXPIRED', 'Authorization expired before a valid signature', 'WARN')


def view(auth):
    refresh_expiry(auth)
    p = auth['payload']
    return {
        # Same fields as GET /v1/mobile/authorizations/{id} in Auth Core.
        'authorizationId': auth['id'],
        'nexusId': p['nexus_id'],
        'credentialId': p['credential_id'],
        'transactionReference': p['transaction_reference'],
        'operationType': p['operation_type'],
        'amountMinor': p['amount_minor'],
        'currency': p['currency'],
        'beneficiary': dict(p['beneficiary']),
        'policyReference': p['policy_reference'],
        'policyVersion': p['policy_version'],
        'canonicalPayloadHash': auth['hash'],
        'nonce': p['nonce'],
        'issuedAt': p['issued_at'],
        'expiresAt': p['expires_at'],
        'state': auth['state'],
        'signature': auth['signature'],
        'signatureAlgorithm': 'HMAC-SHA256' if auth['confirmation_method'] == 'OFFLINE_CODE' else 'ES256',
        'signatureFormat': auth['signature_format'],
        'confirmationMethod': auth['confirmation_method'],
        'verifiedAt': auth['verified_at'],
        'consumedAt': auth['consumed_at'],
        'canonicalPayloadBase64': b64(auth['canonical']),
        # Sandbox extensions.
        'protocolVersion': protocol.PROTOCOL_VERSION,
        'domain': protocol.DOMAIN,
        'scenario': auth['scenario'],
        'riskDecision': auth['risk'],
        'terminalReason': auth['terminal_reason'],
        'signatureAttempts': auth['attempts'],
        'maxSignatureAttempts': POLICY['max_signature_attempts'],
        'verificationPlan': {'steps': [dict(s) for s in auth['steps']], 'reasons': list(auth['reasons'])},
        'bankTransaction': dict(auth['bank']) if auth['bank'] else None,
    }


def require_string(body, key, pattern=None, required=True, default=None):
    value = body.get(key, default)
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise ApiError(400, 'VALIDATION_FAILED', f'{key} must be a string')
    if pattern is not None and not pattern.match(value):
        raise ApiError(400, 'VALIDATION_FAILED', f'{key} has an invalid format')
    return value


def create_authorization(body, idempotency_key):
    if not idempotency_key or not IDEMPOTENCY_KEY.match(idempotency_key):
        raise ApiError(400, 'IDEMPOTENCY_KEY_REQUIRED', 'Idempotency-Key header: 8-128 characters [A-Za-z0-9._:-]')
    fingerprint = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    previous = store['idempotency'].get(idempotency_key)
    if previous:
        if previous['fingerprint'] != fingerprint:
            raise ApiError(409, 'IDEMPOTENCY_KEY_REUSED', 'the key was already used with a different request body')
        return 200, view(store['authorizations'][previous['authorization_id']])

    credential_id = require_string(body, 'credentialId', UUID_RE)
    device = store['devices'].get(credential_id)
    if not device:
        raise ApiError(404, 'CREDENTIAL_NOT_FOUND', 'enrol a device key first (POST /api/v1/devices)')
    amount = require_string(body, 'amountMinor', protocol.AMOUNT)
    if amount == '0':
        raise ApiError(400, 'VALIDATION_FAILED', 'amountMinor must be greater than zero')
    currency = require_string(body, 'currency', protocol.CURRENCY)
    beneficiary = body.get('beneficiary')
    problem = protocol.validate_beneficiary(beneficiary)
    if problem:
        raise ApiError(400, 'VALIDATION_FAILED', problem)
    if not str(beneficiary.get('name', '')).strip():
        raise ApiError(400, 'VALIDATION_FAILED', 'beneficiary.name is required')
    operation_type = require_string(body, 'operationType', OPERATION_TYPE, default='transfer')
    reference = require_string(body, 'transactionReference', PRINTABLE_REF, required=False)
    scenario = require_string(body, 'scenario', default='standard')
    if scenario not in SCENARIOS:
        raise ApiError(400, 'VALIDATION_FAILED', f'scenario must be one of {", ".join(SCENARIOS)}')
    risk = require_string(body, 'riskDecision', default='ALLOW')
    if risk not in RISK_DECISIONS:
        raise ApiError(400, 'VALIDATION_FAILED', f'riskDecision must be one of {", ".join(RISK_DECISIONS)}')

    if len(store['authorizations']) >= MAX_AUTHORIZATIONS:
        raise ApiError(429, 'WORKSPACE_LIMIT_REACHED', 'reset the environment to continue')
    authorization_id = str(uuid.uuid4())
    reference = reference or 'SBX-' + authorization_id[:8].upper()
    if reference in store['references']:
        raise ApiError(409, 'TRANSACTION_REFERENCE_REUSED', 'transactionReference already has an authorization')

    issued = now_ms()
    expires = issued + POLICY['authorization_ttl_seconds'] * 1000
    payload = {
        'protocol_version': protocol.PROTOCOL_VERSION,
        'domain': protocol.DOMAIN,
        'authorization_id': authorization_id,
        'nexus_id': device['nexus_id'],
        'credential_id': credential_id,
        'transaction_reference': reference,
        'operation_type': operation_type,
        'amount_minor': amount,
        'currency': currency,
        'beneficiary': dict(beneficiary),
        'policy_reference': POLICY['policy_reference'],
        'policy_version': POLICY['policy_version'],
        'issued_at': iso_ms(issued),
        'expires_at': iso_ms(expires),
        'nonce': secrets.token_hex(32),
    }
    canonical = protocol.canonical_bytes(payload)

    steps, reasons = [step('PUSH')], ['STANDARD']
    high_value = int(amount) >= int(POLICY['high_value_threshold_minor'])
    if high_value or risk == 'STEP_UP' or scenario == 'high-value':
        steps += [step('AUDIO'), step('VIDEO')]
        reasons = ['HIGH_VALUE' if high_value or scenario == 'high-value' else 'RISK_STEP_UP']
    elif scenario == 'user-request':
        steps.append(step('AUDIO'))
        reasons = ['CLIENT_REQUEST']
    elif scenario == 'failure':
        steps.append(step('AUDIO'))
        reasons = ['POLICY_AUDIO']
    steps += [step('SIGNATURE'), step('VERIFY'), step('COMMIT')]

    auth = {
        'id': authorization_id, 'payload': payload, 'canonical': canonical,
        'hash': protocol.sha256_hex(canonical), 'expires_ms': expires, 'state': 'PENDING',
        'scenario': scenario, 'risk': risk, 'steps': steps, 'reasons': reasons,
        # Scripted provider behavior for the scenario; consumed once.
        'pending_faults': {'push-timeout': {'PUSH'}, 'failure': {'AUDIO'}}.get(scenario, set()),
        'attempts': 0, 'signature': None, 'signature_format': None, 'confirmation_method': None, 'verified_at': None,
        'verified_ms': None, 'consumed_at': None, 'assertions': [], 'bank': None,
        'terminal_reason': None, 'correlation_id': str(uuid.uuid4()),
    }
    store['authorizations'][authorization_id] = auth
    store['references'][reference] = authorization_id
    store['idempotency'][idempotency_key] = {'fingerprint': fingerprint, 'authorization_id': authorization_id}
    emit(f'Authorization created; plan {" → ".join(s["factor"] for s in steps)}', 'AUTH', authorization_id)
    emit(f'Canonical payload bound, sha256 {auth["hash"][:16]}…', 'CRYPTO', authorization_id)
    append_evidence(auth, 'CREATED')
    if risk == 'BLOCK':
        terminate(auth, 'REJECTED', 'RISK_BLOCK', 'Risk engine decision BLOCK; authorization rejected, signing not offered')
    return 201, view(auth)


# --- Verification providers (simulated) ---

def provider_signature(timestamp, raw_body):
    return 'v1=' + hmac.new(PROVIDER_WEBHOOK_SECRET, timestamp.encode() + b'.' + raw_body, hashlib.sha256).hexdigest()


def open_session(auth, factor):
    session = {
        'sessionId': str(uuid.uuid4()), 'authorizationId': auth['id'], 'factor': factor,
        'nonce': secrets.token_hex(16), 'expiresMs': now_ms() + POLICY['verification_session_ttl_seconds'] * 1000,
        'status': 'OPEN',
    }
    store['sessions'][session['sessionId']] = session
    emit(f'{factor} verification session opened with simulated provider', 'VERIFY', auth['id'])
    return session


def handle_provider_webhook(headers, raw_body):
    """Provider completion callback. The only way an AUDIO/VIDEO step can
    complete; the built-in simulated provider goes through it too."""
    timestamp = headers.get('X-NEXUS-Timestamp', '')
    event_id = headers.get('X-NEXUS-Event-Id', '')
    signature = headers.get('X-NEXUS-Signature', '')
    if not re.match(r'^\d{1,12}$', timestamp):
        raise ApiError(400, 'INVALID_TIMESTAMP')
    if not event_id or len(event_id) > 128:
        raise ApiError(400, 'INVALID_EVENT_ID')
    if abs(now_ms() // 1000 - int(timestamp)) > POLICY['webhook_clock_skew_seconds']:
        raise ApiError(401, 'WEBHOOK_TIMESTAMP_OUT_OF_WINDOW')
    # HMAC over the exact bytes received, never over a re-serialization.
    if not hmac.compare_digest(provider_signature(timestamp, raw_body).encode(), signature.encode('utf-8', 'surrogateescape')):
        raise ApiError(401, 'WEBHOOK_SIGNATURE_INVALID')
    if event_id in store['webhook_events']:
        raise ApiError(409, 'WEBHOOK_REPLAY')
    try:
        body = json.loads(raw_body)
    except ValueError:
        raise ApiError(400, 'INVALID_JSON') from None
    if not isinstance(body, dict):
        raise ApiError(400, 'INVALID_JSON')
    store['webhook_events'].add(event_id)

    session = store['sessions'].get(body.get('sessionId'))
    if not session:
        raise ApiError(404, 'VERIFICATION_SESSION_NOT_FOUND')
    if session['status'] != 'OPEN':
        raise ApiError(409, 'VERIFICATION_SESSION_ALREADY_USED')
    if not hmac.compare_digest(str(body.get('nonce', '')), session['nonce']):
        raise ApiError(401, 'VERIFICATION_SESSION_NONCE_MISMATCH')
    auth = store['authorizations'][session['authorizationId']]
    refresh_expiry(auth)
    if now_ms() > session['expiresMs']:
        session['status'] = 'EXPIRED'
        raise ApiError(410, 'VERIFICATION_SESSION_EXPIRED')
    current = current_step(auth)
    if auth['state'] not in PENDING_STATES or not current or current['factor'] != session['factor']:
        session['status'] = 'STALE'
        raise ApiError(409, 'VERIFICATION_SESSION_STALE')
    result = body.get('result')
    if result not in ('PASSED', 'FAILED'):
        raise ApiError(400, 'VALIDATION_FAILED', 'result must be PASSED or FAILED')

    session['status'] = result
    assertion = {'factor': session['factor'], 'sessionId': session['sessionId'], 'result': result,
                 'eventId': event_id, 'assertionHash': hashlib.sha256(raw_body).hexdigest(),
                 'completedAt': iso_ms(now_ms())}
    auth['assertions'].append(assertion)
    if result == 'PASSED':
        current['status'] = 'COMPLETED'
        emit(f'{session["factor"]} verification passed (provider assertion verified)', 'VERIFY', auth['id'])
    elif session['factor'] == 'AUDIO':
        emit('AUDIO verification failed; policy escalates, never downgrades', 'SECURITY', auth['id'])
        current['status'] = 'FAILED'
        escalate(auth, 'VIDEO', 'AUDIO_FAILED')
    else:
        terminate(auth, 'REJECTED', 'VERIFICATION_FAILED', f'{session["factor"]} verification failed; no weaker factor is allowed')
    return {'status': 'accepted', 'eventId': event_id, 'authorization': view(auth)}


def simulated_provider_complete(auth, factor, result):
    session = open_session(auth, factor)
    raw = json.dumps({'sessionId': session['sessionId'], 'nonce': session['nonce'], 'result': result},
                     separators=(',', ':')).encode()
    ts = str(now_ms() // 1000)
    headers = {'X-NEXUS-Timestamp': ts, 'X-NEXUS-Event-Id': 'sim-' + str(uuid.uuid4()),
               'X-NEXUS-Signature': provider_signature(ts, raw)}
    return handle_provider_webhook(headers, raw)['authorization']


def advance(auth, fault=None):
    refresh_expiry(auth)
    if auth['state'] == 'VERIFIED':
        return commit(auth)
    if auth['state'] not in PENDING_STATES:
        raise ApiError(409, 'AUTHORIZATION_NOT_PENDING', auth['state'])
    current = current_step(auth)
    factor = current['factor']
    scripted = factor in auth['pending_faults']
    auth['pending_faults'].discard(factor)

    if factor == 'PUSH':
        if fault == 'push_timeout' or scripted:
            current['status'] = 'TIMED_OUT'
            emit(f'Push not acknowledged within {POLICY["push_timeout_seconds"]} s', 'WARN', auth['id'])
            escalate(auth, 'AUDIO', 'PUSH_TIMEOUT')
        else:
            current['status'] = 'COMPLETED'
            emit('Push delivered to the enrolled device (simulated delivery)', 'FLOW', auth['id'])
        return view(auth)
    if factor in ('AUDIO', 'VIDEO'):
        if fault not in (None, 'provider_failure'):
            raise ApiError(409, 'FAULT_NOT_APPLICABLE', f'{fault} cannot be applied at {factor}')
        result = 'FAILED' if fault == 'provider_failure' or scripted else 'PASSED'
        return simulated_provider_complete(auth, factor, result)
    if fault:
        raise ApiError(409, 'FAULT_NOT_APPLICABLE', f'{fault} cannot be applied at {factor}')
    raise ApiError(409, 'DEVICE_SIGNATURE_REQUIRED',
                   'the next step is completed by the device: POST /api/v1/authorizations/{id}/signature')


def submit_signature(auth, body):
    refresh_expiry(auth)
    if auth['state'] == 'EXPIRED':
        raise ApiError(410, 'AUTHORIZATION_EXPIRED')
    if auth['state'] not in PENDING_STATES:
        raise ApiError(409, 'AUTHORIZATION_NOT_PENDING', auth['state'])
    current = current_step(auth)
    if current['factor'] != 'SIGNATURE':
        raise ApiError(409, 'VERIFICATION_STEPS_INCOMPLETE', f'complete {current["factor"]} first')
    fmt = body.get('signatureFormat')
    sig_b64 = body.get('signature')
    if fmt not in ('der', 'raw') or not isinstance(sig_b64, str) or not sig_b64:
        raise ApiError(400, 'VALIDATION_FAILED', 'signature (base64) and signatureFormat (der|raw) are required')

    auth['attempts'] += 1
    reason = None
    try:
        r, s = p256.decode_signature(base64.b64decode(sig_b64, validate=True), fmt)
    except (ValueError, binascii.Error):
        reason = 'malformed_signature'
    else:
        device = store['devices'].get(auth['payload']['credential_id'])
        if device is None:
            reason = 'credential_retired'
        elif not p256.verify(device['public_key'], auth['canonical'], r, s):
            reason = 'signature_verification_failed'

    if reason:
        limit = POLICY['max_signature_attempts']
        if auth['attempts'] >= limit:
            terminate(auth, 'REJECTED', 'SIGNATURE_ATTEMPT_LIMIT', f'Signature rejected ({reason}); attempt limit {limit} reached')
            return {'status': 'FAILED', 'reason': 'signature_attempt_limit', 'attempts': auth['attempts'], 'authorization': view(auth)}
        emit(f'Signature rejected ({reason}); attempt {auth["attempts"]}/{limit}', 'SECURITY', auth['id'])
        return {'status': 'FAILED', 'reason': reason, 'attempts': auth['attempts'], 'authorization': view(auth)}

    auth['signature'], auth['signature_format'] = sig_b64, fmt
    auth['confirmation_method'] = 'DEVICE_SIGNATURE'
    auth['device_public_key'] = device['public_key']
    auth['verified_ms'] = now_ms()
    auth['verified_at'] = auth['consumed_at'] = iso_ms(auth['verified_ms'])
    auth['state'] = 'VERIFIED'
    current['status'] = 'COMPLETED'
    current_step(auth)['status'] = 'COMPLETED'  # VERIFY
    emit('Device ECDSA P-256 signature verified over the exact canonical bytes', 'CRYPTO', auth['id'])
    append_evidence(auth, 'VERIFIED')
    return {'status': 'VERIFIED', 'authorization': view(auth)}


def offline_device(auth):
    """The device of a pending authorization at its SIGNATURE step, if it
    was enrolled for offline confirmation."""
    refresh_expiry(auth)
    if auth['state'] == 'EXPIRED':
        raise ApiError(410, 'AUTHORIZATION_EXPIRED')
    if auth['state'] not in PENDING_STATES:
        raise ApiError(409, 'AUTHORIZATION_NOT_PENDING', auth['state'])
    current = current_step(auth)
    if current['factor'] != 'SIGNATURE':
        raise ApiError(409, 'VERIFICATION_STEPS_INCOMPLETE', f'complete {current["factor"]} first')
    device = store['devices'].get(auth['payload']['credential_id'])
    if device is None or device.get('offline_key') is None:
        raise ApiError(409, 'OFFLINE_CONFIRMATION_UNAVAILABLE', 'the device was enrolled without an offline key')
    return device, current


def offline_challenge(auth):
    offline_device(auth)
    emit('Offline challenge issued for the bank screen (QR code with the canonical bytes)', 'VERIFY', auth['id'])
    payload = protocol.offline_qr_payload(auth['canonical'])
    return {'authorizationId': auth['id'], 'qrPayload': payload, 'codeDigits': 8,
            'expiresAt': auth['payload']['expires_at'],
            # Sandbox convenience; a bank renders the payload with its own QR library.
            'qrSvg': qr.to_svg(qr.encode(payload, 'L'))}


def confirm_offline(auth, body):
    device, current = offline_device(auth)
    code = body.get('code')
    if not isinstance(code, str) or not re.fullmatch(r'\d{8}', code):
        raise ApiError(400, 'VALIDATION_FAILED', 'code must be 8 digits')
    auth['attempts'] += 1
    tag = protocol.offline_tag(device['offline_key'], auth['canonical'])
    if not hmac.compare_digest(protocol.offline_code(tag).encode(), code.encode()):
        limit = POLICY['max_signature_attempts']
        if auth['attempts'] >= limit:
            terminate(auth, 'REJECTED', 'SIGNATURE_ATTEMPT_LIMIT', f'Offline code rejected; attempt limit {limit} reached')
            return {'status': 'FAILED', 'reason': 'signature_attempt_limit', 'attempts': auth['attempts'], 'authorization': view(auth)}
        emit(f'Offline code rejected; attempt {auth["attempts"]}/{limit}', 'SECURITY', auth['id'])
        return {'status': 'FAILED', 'reason': 'offline_code_invalid', 'attempts': auth['attempts'], 'authorization': view(auth)}

    auth['signature'], auth['signature_format'] = b64(tag), 'hmac'
    auth['confirmation_method'] = 'OFFLINE_CODE'
    auth['device_public_key'] = device['public_key']
    auth['verified_ms'] = now_ms()
    auth['verified_at'] = auth['consumed_at'] = iso_ms(auth['verified_ms'])
    auth['state'] = 'VERIFIED'
    current['status'] = 'COMPLETED'
    current_step(auth)['status'] = 'COMPLETED'  # VERIFY
    emit('Offline code verified: the device confirmed exactly these bytes without network', 'CRYPTO', auth['id'])
    append_evidence(auth, 'VERIFIED')
    return {'status': 'VERIFIED', 'authorization': view(auth)}


def commit(auth):
    refresh_expiry(auth)
    if auth['state'] == 'COMMITTED':
        raise ApiError(409, 'ALREADY_COMMITTED', auth['bank']['reference'])
    if auth['state'] != 'VERIFIED':
        raise ApiError(409, 'AUTHORIZATION_NOT_VERIFIED', auth['state'])
    if now_ms() - auth['verified_ms'] > POLICY['verification_max_age_seconds'] * 1000:
        terminate(auth, 'REJECTED', 'VERIFICATION_TOO_OLD', 'Verification older than the policy allows; commit refused')
        raise ApiError(409, 'VERIFICATION_TOO_OLD')
    auth['bank'] = {'state': 'COMMITTED', 'reference': 'BANK-SBX-' + secrets.token_hex(5).upper(),
                    'committedAt': iso_ms(now_ms())}
    auth['state'] = 'COMMITTED'
    current_step(auth)['status'] = 'COMPLETED'
    emit(f'Simulated core banking commit accepted: {auth["bank"]["reference"]}', 'BANK', auth['id'])
    append_evidence(auth, 'COMMITTED')
    return view(auth)


def enrol_device(body):
    spki_b64 = body.get('publicKeySpkiBase64')
    if not isinstance(spki_b64, str):
        raise ApiError(400, 'VALIDATION_FAILED', 'publicKeySpkiBase64 is required')
    try:
        public_key = p256.public_key_from_spki(base64.b64decode(spki_b64, validate=True))
    except (ValueError, binascii.Error) as exc:
        raise ApiError(400, 'INVALID_PUBLIC_KEY', str(exc)) from None
    label = body.get('label', 'Sandbox device')
    if not isinstance(label, str) or len(label) > 64:
        raise ApiError(400, 'VALIDATION_FAILED', 'label must be a string of at most 64 characters')
    if len(store['devices']) >= MAX_DEVICES:
        # Every page load enrols a fresh browser key; retire the oldest one.
        retired = next(iter(store['devices']))
        del store['devices'][retired]
        emit(f'Oldest device key retired (credential {retired[:8]}…)', 'ENROL')
    offline_b64 = body.get('offlinePublicKeySpkiBase64')
    offline_public = None
    if offline_b64 is not None:
        try:
            offline_public = p256.public_key_from_spki(base64.b64decode(offline_b64, validate=True))
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ApiError(400, 'INVALID_PUBLIC_KEY', f'offline key: {exc}') from None
    credential_id = str(uuid.uuid4())
    nexus_id = str(secrets.randbelow(900_000_000) + 100_000_000)
    device = {'credential_id': credential_id, 'nexus_id': nexus_id, 'label': label,
              'public_key': public_key, 'created_at': iso_ms(now_ms()), 'offline_key': None}
    result = {'credentialId': credential_id, 'nexusId': nexus_id, 'label': label,
              'publicKeyPem': p256.public_key_pem(public_key), 'algorithm': 'ES256'}
    if offline_public is not None:
        # One-time server key: agree the offline key, keep only the result.
        server_private = p256.generate_private_key()
        shared = p256.ecdh_shared_secret(server_private, offline_public)
        device['offline_key'] = protocol.derive_offline_key(shared, credential_id)
        result['offlineServerPublicKeySpkiBase64'] = b64(p256.spki_from_public_key(p256.public_key(server_private)))
    store['devices'][credential_id] = device
    emit(f'Device key enrolled ({label}); credential {credential_id[:8]}…'
         + ('; offline confirmation key agreed' if offline_public is not None else ''), 'ENROL')
    return result


def state_snapshot():
    for auth in store['authorizations'].values():
        refresh_expiry(auth)
    return {
        'time': iso_ms(now_ms()),
        'clockOffsetSeconds': clock_offset_ms // 1000,
        'devices': [{'credentialId': d['credential_id'], 'nexusId': d['nexus_id'], 'label': d['label']}
                    for d in store['devices'].values()],
        'authorizations': [{'authorizationId': a['id'], 'state': a['state'],
                            'transactionReference': a['payload']['transaction_reference']}
                           for a in store['authorizations'].values()],
        'evidence': store['evidence'][-30:],
        'events': store['events'][:80],
    }


# --- HTTP ---

SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
}


class Handler(BaseHTTPRequestHandler):
    server_version = 'NEXUS-SIGN-Sandbox/1.3'
    sys_version = ''
    timeout = 15  # seconds a client may take to send its request

    def log_message(self, fmt, *args):
        if os.environ.get('SANDBOX_ACCESS_LOG'):
            super().log_message(fmt, *args)

    def send_bytes(self, status, raw, content_type, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        for key, value in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(raw)

    def send_json(self, status, obj):
        self.send_bytes(status, json.dumps(obj, ensure_ascii=False, indent=2).encode('utf-8'),
                        'application/json; charset=utf-8')

    def read_body(self):
        length = self.headers.get('Content-Length', '0')
        if not re.fullmatch(r'[0-9]{1,9}', length):
            raise ApiError(400, 'INVALID_CONTENT_LENGTH')
        if int(length) > POLICY['max_request_bytes']:
            raise ApiError(413, 'REQUEST_TOO_LARGE')
        return self.rfile.read(int(length))

    def parse_json(self, raw):
        if not raw:
            return {}
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, 'INVALID_JSON') from None
        if not isinstance(body, dict):
            raise ApiError(400, 'INVALID_JSON', 'request body must be a JSON object')
        return body

    def dispatch(self, method):
        try:
            path = urlparse(self.path).path
            if method == 'GET' and path in STATIC_FILES:
                file, content_type = STATIC_FILES[path]
                return self.send_bytes(200, (ROOT / file).read_bytes(), content_type)
            if not path.startswith('/api/v1/'):
                raise ApiError(404, 'NOT_FOUND')
            raw = self.read_body() if method == 'POST' else b''
            parts = path.split('/')[3:]
            if parts == ['health'] and method == 'GET':
                return self.send_json(200, {'status': 'ok', 'environment': 'SANDBOX', 'hosted': ACCESS.hosted,
                                            'protocolVersion': protocol.PROTOCOL_VERSION, 'domain': protocol.DOMAIN})
            if parts[:1] == ['session']:
                return self.session(method, parts, raw)
            workspace = self.workspace()
            if workspace is None:
                raise ApiError(401, 'AUTHENTICATION_REQUIRED', 'sign in with your access code')
            if method == 'GET' and parts == ['evidence', 'verify']:
                return self.send_json(200, verify_workspace_evidence(WORKSPACES[workspace]))
            with lock:
                status, result = self.in_workspace(WORKSPACES[workspace], method, parts, raw)
            self.send_json(status, result)
        except ApiError as exc:
            self.send_json(exc.status, {'error': exc.error, **({'detail': exc.detail} if exc.detail else {})})
        except Exception as exc:  # never drop the connection on a bug
            self.send_json(500, {'error': 'INTERNAL_ERROR', 'detail': type(exc).__name__})

    def client_address_for_limits(self):
        peer = self.client_address[0]
        if TRUST_PROXY and is_internal_address(peer):
            # The reverse proxy appends the address it received the request
            # from; the rightmost entry is the only one the client cannot forge.
            # A request that reaches this port directly from outside is not
            # from the proxy, so its header is ignored.
            forwarded = [a.strip() for a in self.headers.get('X-Forwarded-For', '').split(',') if a.strip()]
            if forwarded:
                return forwarded[-1]
        return peer

    def workspace(self):
        try:
            return ACCESS.resolve(self.headers, self.client_address_for_limits())
        except access.TooManyAttempts:
            raise ApiError(429, 'TOO_MANY_ATTEMPTS', 'try again in 15 minutes') from None

    def session(self, method, parts, raw):
        if parts == ['session'] and method == 'GET':
            workspace = self.workspace()
            if workspace is None:
                raise ApiError(401, 'AUTHENTICATION_REQUIRED')
            return self.send_json(200, {'workspace': workspace, 'hosted': ACCESS.hosted})
        if parts == ['session'] and method == 'POST':
            if not ACCESS.hosted:
                return self.send_json(200, {'workspace': 'local', 'hosted': False})
            client = self.client_address_for_limits()
            if not ACCESS.login_allowed(client):
                raise ApiError(429, 'TOO_MANY_ATTEMPTS', 'try again in 15 minutes')
            workspace = ACCESS.check_code(self.parse_json(raw).get('accessCode'))
            if workspace is None:
                ACCESS.record_failure(client)
                raise ApiError(401, 'INVALID_ACCESS_CODE')
            with lock:
                previous = activate(WORKSPACES[workspace])
                emit('Signed in to the sandbox', 'SYSTEM')
                deactivate(WORKSPACES[workspace], previous)
            return self.send_bytes(200, json.dumps({'workspace': workspace, 'hosted': True}).encode(),
                                   'application/json; charset=utf-8', {'Set-Cookie': ACCESS.issue_cookie(workspace)})
        if parts == ['session', 'logout'] and method == 'POST':
            ACCESS.revoke_cookie(self.headers.get('Cookie'))
            return self.send_bytes(200, b'{"status":"signed-out"}', 'application/json; charset=utf-8',
                                   {'Set-Cookie': ACCESS.clear_cookie()})
        raise ApiError(404, 'NOT_FOUND')

    def in_workspace(self, workspace, method, parts, raw):
        previous = activate(workspace)
        try:
            return self.route(method, parts, raw)
        finally:
            deactivate(workspace, previous)

    def route(self, method, parts, raw):
        global clock_offset_ms, store
        if method == 'GET':
            if parts == ['state']:
                return 200, state_snapshot()
            if parts == ['policy']:
                return 200, POLICY
            if parts == ['evidence']:
                return 200, {'records': store['evidence'],
                             'publicKeyPem': p256.public_key_pem(store['evidence_public_key'])}
            if len(parts) == 2 and parts[0] == 'authorizations':
                return 200, view(self.authorization(parts[1]))
            if len(parts) == 3 and parts[0] == 'authorizations' and parts[2] == 'offline-challenge':
                return 200, offline_challenge(self.authorization(parts[1]))
            raise ApiError(404, 'NOT_FOUND')

        if parts == ['webhooks', 'provider']:
            return 200, handle_provider_webhook(self.headers, raw)
        body = self.parse_json(raw)
        if parts == ['reset']:
            store = empty_state()
            clock_offset_ms = 0
            emit('Sandbox state reset; evidence key regenerated', 'SYSTEM')
            return 200, {'status': 'reset'}
        if parts == ['clock']:
            seconds = body.get('advanceSeconds')
            if not isinstance(seconds, int) or isinstance(seconds, bool) or not 0 < seconds <= 86400:
                raise ApiError(400, 'VALIDATION_FAILED', 'advanceSeconds must be an integer 1..86400')
            clock_offset_ms += seconds * 1000
            emit(f'Sandbox clock advanced by {seconds} s', 'SYSTEM')
            return 200, {'time': iso_ms(now_ms()), 'clockOffsetSeconds': clock_offset_ms // 1000}
        if parts == ['devices']:
            return 201, enrol_device(body)
        if parts == ['authorizations']:
            return create_authorization(body, self.headers.get('Idempotency-Key'))
        if len(parts) == 3 and parts[0] == 'authorizations':
            auth = self.authorization(parts[1])
            action = parts[2]
            if action == 'advance':
                return 200, advance(auth)
            if action == 'fault':
                fault = body.get('type')
                if fault not in ('push_timeout', 'provider_failure'):
                    raise ApiError(400, 'UNKNOWN_FAULT', 'type must be push_timeout or provider_failure')
                return 200, advance(auth, fault)
            if action == 'signature':
                result = submit_signature(auth, body)
                return 200, result
            if action == 'commit':
                return 200, commit(auth)
            if action == 'offline-confirmation':
                return 200, confirm_offline(auth, body)
        raise ApiError(404, 'NOT_FOUND')

    def authorization(self, authorization_id):
        auth = store['authorizations'].get(authorization_id)
        if not auth:
            raise ApiError(404, 'AUTHORIZATION_NOT_FOUND')
        return auth

    def do_GET(self):
        self.dispatch('GET')

    def do_HEAD(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')


def is_internal_address(address):
    """Loopback or private network: where the reverse proxy runs."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def verify_workspace_evidence(workspace):
    """Verifies a workspace's evidence chain outside the request lock.

    Re-verifying a long chain takes seconds in pure Python; holding the lock
    for that would stall every other workspace. Records are append-only, so a
    snapshot taken under the lock is consistent, and the result is cached
    until the chain grows or the workspace is reset.
    """
    with lock:
        records = list(workspace.store['evidence'])
        public_key = workspace.store['evidence_public_key']
    marker = (public_key, len(records))  # the evidence key is regenerated on reset
    cached = getattr(workspace, 'verified_evidence', None)
    if cached and cached[0] == marker:
        return cached[1]
    result = verify_evidence_chain(records, public_key)
    workspace.verified_evidence = (marker, result)
    return result


def activate(workspace):
    """Points the module-level state at one workspace. Callers hold `lock`,
    so exactly one workspace is active at a time."""
    global store, clock_offset_ms
    previous = (store, clock_offset_ms)
    store, clock_offset_ms = workspace.store, workspace.clock_offset_ms
    return previous


def deactivate(workspace, previous):
    global store, clock_offset_ms
    workspace.store, workspace.clock_offset_ms = store, clock_offset_ms  # reset replaces the store
    store, clock_offset_ms = previous


def main():
    try:
        configure_access()
    except access.ConfigurationError as exc:
        raise SystemExit(f'SANDBOX_ACCESS_CODES: {exc}')
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    mode = f'hosted, {len(WORKSPACES)} workspaces' if ACCESS.hosted else 'local, no sign-in'
    print(f'NEXUS-SIGN sandbox ({mode}): http://{HOST}:{server.server_address[1]}', flush=True)
    if ACCESS.hosted and HOST == '127.0.0.1' and not TRUST_PROXY:
        print('Note: listening on 127.0.0.1 only; put it behind the HTTPS reverse proxy (deploy/).', flush=True)
    elif not ACCESS.hosted and HOST not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('Refusing to listen on a network interface without SANDBOX_ACCESS_CODES.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
