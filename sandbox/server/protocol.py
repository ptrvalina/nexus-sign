"""NEXUS-SIGN transaction authorization protocol v1.

This module is the sandbox's copy of the wire contract implemented by Auth
Core (`canonicalAuthorization.ts`) and by both mobile SDKs
(`SignedTransaction.kt`, `SignedTransaction.swift`). The shared vectors in
`auth-core/test-vectors/signed-payload-v1.json` pin all four implementations to the
same bytes.

Canonical form: the 15-field authorization object, keys sorted recursively in
UTF-16 code-unit order (JavaScript's default sort), serialized exactly like
`JSON.stringify` (no whitespace, same string escaping), UTF-8 encoded.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
import unicodedata

PROTOCOL_VERSION = '1'
DOMAIN = 'NEXUS-SIGN/TRANSACTION-AUTH'

FIELDS = frozenset({
    'amount_minor', 'authorization_id', 'beneficiary', 'credential_id', 'currency', 'domain',
    'expires_at', 'issued_at', 'nexus_id', 'nonce', 'operation_type', 'policy_reference',
    'policy_version', 'protocol_version', 'transaction_reference',
})

AMOUNT = re.compile(r'^(0|[1-9][0-9]{0,29})$')
CURRENCY = re.compile(r'^[A-Z]{3}$')
# Protocol v1 formats: lowercase UUIDs, 9-digit NEXUS ID, 32-byte nonce in lowercase hex.
UUID_V1 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
NEXUS_ID = re.compile(r'^[0-9]{9}$')
NONCE = re.compile(r'^[0-9a-f]{64}$')
BENEFICIARY_KEY = re.compile(r'^[a-z][a-z0-9_]{0,63}$')
BENEFICIARY_MAX_FIELDS = 16
# ISO 20022 Max140Text, in UTF-16 code units (FI-003; 512 until 2.0.0-rc.2).
BENEFICIARY_MAX_VALUE_LENGTH = 140
TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$')


class Rejected(ValueError):
    """Same reason codes as the SDKs: invalid_json, duplicate_key, not_canonical,
    missing_field, unexpected_field, invalid_value, wrong_protocol."""

    def __init__(self, reason, detail):
        super().__init__(f'{reason}: {detail}')
        self.reason = reason
        self.detail = detail


# --- Canonical encoding ---

class _Number(str):
    """A JSON number kept as its literal text, so re-encoding is exact."""


_ESCAPES = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _js_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif c < 0x20 or 0xD800 <= c <= 0xDFFF:
            # JSON.stringify escapes control characters and (since ES2019)
            # lone surrogates as lowercase \uXXXX.
            out.append('\\u%04x' % c)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_order(key):
    return key.encode('utf-16-be', 'surrogatepass')


def _write(value, out):
    if isinstance(value, _Number):
        out.append(str(value))
    elif isinstance(value, bool):
        out.append('true' if value else 'false')
    elif value is None:
        out.append('null')
    elif isinstance(value, int) and abs(value) <= 2**53 - 1:
        out.append(str(value))  # safe integers only: identical in JSON.stringify
    elif isinstance(value, str):
        out.append(_js_string(value))
    elif isinstance(value, dict):
        out.append('{')
        for i, key in enumerate(sorted(value, key=_utf16_order)):
            if i:
                out.append(',')
            out.append(_js_string(key))
            out.append(':')
            _write(value[key], out)
        out.append('}')
    elif isinstance(value, list):
        out.append('[')
        for i, item in enumerate(value):
            if i:
                out.append(',')
            _write(item, out)
        out.append(']')
    else:
        raise TypeError(f'unsupported type in canonical payload: {type(value).__name__}')


def canonical_bytes(value):
    out = []
    _write(value, out)
    return ''.join(out).encode('utf-8', 'surrogatepass')


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# --- Validation shared by the create API and the strict parser ---

def validate_beneficiary(beneficiary):
    """Returns an error string, or None when the beneficiary is acceptable."""
    if not isinstance(beneficiary, dict):
        return 'beneficiary must be an object'
    if len(beneficiary) > BENEFICIARY_MAX_FIELDS:
        return f'beneficiary has more than {BENEFICIARY_MAX_FIELDS} fields'
    for key, value in beneficiary.items():
        if not BENEFICIARY_KEY.match(key):
            return f'beneficiary key {key!r} must match {BENEFICIARY_KEY.pattern}'
        if not isinstance(value, str) or isinstance(value, _Number):
            return f'beneficiary.{key} must be a string'
        if len(value.encode('utf-16-le', 'surrogatepass')) // 2 > BENEFICIARY_MAX_VALUE_LENGTH:
            return f'beneficiary.{key} is longer than {BENEFICIARY_MAX_VALUE_LENGTH} characters'
        if value == '' or unicodedata.category(value[0]) == 'Zs' or unicodedata.category(value[-1]) == 'Zs':
            return f'beneficiary.{key} is empty or has leading or trailing space'
        if not is_display_safe(value):
            return f'beneficiary.{key} contains a control, format or separator character'
    return None


_DISPLAY_UNSAFE = {'Cc', 'Cf', 'Zl', 'Zp'}


def is_display_safe(text):
    """Same rule as Auth Core and the SDKs: no control, format (bidi,
    zero-width) or line/paragraph separator characters in displayed text."""
    return not any(unicodedata.category(ch) in _DISPLAY_UNSAFE for ch in text)


# --- Strict parser (what a verifying device does) ---

def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Rejected('duplicate_key', key)
        obj[key] = value
    return obj


def _no_constants(name):
    raise Rejected('invalid_json', f'{name} is not valid JSON')


_DECODER = json.JSONDecoder(object_pairs_hook=_pairs, parse_int=_Number, parse_float=_Number,
                            parse_constant=_no_constants)


def parse_signed_payload(data):
    """Parses canonical authorization bytes the way the mobile SDKs do.

    The bytes are accepted only if re-encoding the parsed object reproduces
    them exactly, which rules out duplicate keys, alternative escapes,
    whitespace, unsorted keys and trailing data.
    """
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise Rejected('invalid_json', 'not valid UTF-8') from None
    if not text or text[0] in ' \t\r\n':
        raise Rejected('not_canonical', 'leading whitespace')
    try:
        obj, end = _DECODER.raw_decode(text)
    except Rejected:
        raise
    except ValueError as exc:
        raise Rejected('invalid_json', str(exc)) from None
    if end != len(text):
        raise Rejected('not_canonical', 'trailing data')
    if not isinstance(obj, dict):
        raise Rejected('invalid_json', 'top level is not an object')
    try:
        reencoded = canonical_bytes(obj)
    except TypeError as exc:
        raise Rejected('invalid_value', str(exc)) from None
    if reencoded != data:
        raise Rejected('not_canonical', 'bytes are not in canonical form')

    missing = FIELDS - obj.keys()
    if missing:
        raise Rejected('missing_field', ', '.join(sorted(missing)))
    unexpected = obj.keys() - FIELDS
    if unexpected:
        raise Rejected('unexpected_field', ', '.join(sorted(unexpected)))

    for key in FIELDS - {'beneficiary'}:
        value = obj[key]
        if not isinstance(value, str) or isinstance(value, _Number):
            raise Rejected('invalid_value', f'{key} must be a string')
    problem = validate_beneficiary(obj['beneficiary'])
    if problem:
        raise Rejected('invalid_value', problem)

    if obj['protocol_version'] != PROTOCOL_VERSION or obj['domain'] != DOMAIN:
        raise Rejected('wrong_protocol', 'unsupported protocol_version/domain')
    if not AMOUNT.match(obj['amount_minor']):
        raise Rejected('invalid_value', 'amount_minor')
    if not CURRENCY.match(obj['currency']):
        raise Rejected('invalid_value', 'currency')
    if not TIMESTAMP.match(obj['issued_at']) or not TIMESTAMP.match(obj['expires_at']):
        raise Rejected('invalid_value', 'timestamps')
    if not UUID_V1.match(obj['authorization_id']) or not UUID_V1.match(obj['credential_id']):
        raise Rejected('invalid_value', 'authorization_id/credential_id')
    if not NEXUS_ID.match(obj['nexus_id']):
        raise Rejected('invalid_value', 'nexus_id')
    if not NONCE.match(obj['nonce']):
        raise Rejected('invalid_value', 'nonce')
    for key in FIELDS - {'beneficiary'}:
        if not is_display_safe(obj[key]):
            raise Rejected('invalid_value', f'{key} contains a control, format or separator character')
    return {k: (dict(v) if isinstance(v, dict) else str(v)) for k, v in obj.items()}


# Response fields a device cross-checks against the signed bytes, as in the
# SDKs' AuthorizationEnvelope. camelCase name -> canonical field.
ENVELOPE_FIELDS = {
    'authorizationId': 'authorization_id', 'nexusId': 'nexus_id', 'credentialId': 'credential_id',
    'transactionReference': 'transaction_reference', 'operationType': 'operation_type',
    'amountMinor': 'amount_minor', 'currency': 'currency', 'beneficiary': 'beneficiary',
    'policyReference': 'policy_reference', 'policyVersion': 'policy_version',
    'issuedAt': 'issued_at', 'expiresAt': 'expires_at',
}


def verify_envelope(envelope):
    """Mirror of SignedPayload.verify() in the SDKs. Returns the signed fields
    or raises Rejected('response_mismatch', field)."""
    try:
        data = base64.b64decode(envelope['canonicalPayloadBase64'], validate=True)
    except (binascii.Error, KeyError, TypeError):
        raise Rejected('invalid_json', 'canonicalPayloadBase64 is not base64') from None
    signed = parse_signed_payload(data)
    if sha256_hex(data) != str(envelope.get('canonicalPayloadHash', '')).lower():
        raise Rejected('response_mismatch', 'canonicalPayloadHash')
    for field, key in ENVELOPE_FIELDS.items():
        if field == 'credentialId' and envelope.get(field) is None:
            continue
        if envelope.get(field) != signed[key]:
            raise Rejected('response_mismatch', field)
    return signed


# --- Display (integer string arithmetic, never floating point) ---

ZERO_DECIMAL_CURRENCIES = {'BIF', 'CLP', 'DJF', 'GNF', 'ISK', 'JPY', 'KMF', 'KRW', 'PYG', 'RWF',
                           'UGX', 'UYI', 'VND', 'VUV', 'XAF', 'XOF', 'XPF'}
THREE_DECIMAL_CURRENCIES = {'BHD', 'IQD', 'JOD', 'KWD', 'LYD', 'OMR', 'TND'}
FOUR_DECIMAL_CURRENCIES = {'CLF', 'UYW'}


def fraction_digits(currency):
    """ISO 4217 minor units, matching the platform data the SDKs use."""
    if currency in ZERO_DECIMAL_CURRENCIES:
        return 0
    if currency in THREE_DECIMAL_CURRENCIES:
        return 3
    if currency in FOUR_DECIMAL_CURRENCIES:
        return 4
    return 2


def format_minor_units(amount_minor, digits):
    if not AMOUNT.match(amount_minor):
        raise ValueError('amount_minor must be a non-negative integer string')
    if digits <= 0:
        return amount_minor
    padded = amount_minor.rjust(digits + 1, '0')
    return padded[:-digits] + '.' + padded[-digits:]


# --- Offline confirmation (device protocols v1) ---
# Same derivation as Auth Core and the SDKs; vectors in
# auth-core/test-vectors/device-protocols-v1.json.

OFFLINE_KDF_SALT = b'NEXUS-SIGN/OFFLINE/v1'
OFFLINE_CODE_DOMAIN = b'NEXUS-SIGN/OFFLINE-CODE/v1'
OFFLINE_QR_PREFIX = 'NXS1.'


def derive_offline_key(shared_secret, credential_id):
    """HKDF-SHA256 (RFC 5869), one 32-byte block."""
    if len(shared_secret) != 32:
        raise ValueError('ECDH shared secret must be 32 bytes')
    prk = hmac.new(OFFLINE_KDF_SALT, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, credential_id.encode('utf-8') + b'\x01', hashlib.sha256).digest()


def offline_tag(offline_key, canonical):
    message = OFFLINE_CODE_DOMAIN + b'\x00' + hashlib.sha256(canonical).digest()
    return hmac.new(offline_key, message, hashlib.sha256).digest()


def offline_code(tag):
    """RFC 4226 dynamic truncation to 8 digits."""
    offset = tag[-1] & 0x0F
    binary = int.from_bytes(tag[offset:offset + 4], 'big') & 0x7FFFFFFF
    return str(binary % 100_000_000).zfill(8)


def offline_qr_payload(canonical):
    return OFFLINE_QR_PREFIX + base64.urlsafe_b64encode(canonical).decode('ascii').rstrip('=')
