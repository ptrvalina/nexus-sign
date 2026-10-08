"""Protocol parity: the sandbox must produce and accept exactly the bytes that
Auth Core and the mobile SDKs do. The shared vectors are read from
auth-core/test-vectors, where Auth Core generates them."""

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_VECTORS = ROOT.parent / 'auth-core' / 'test-vectors'
sys.path.insert(0, str(ROOT / 'server'))
import p256  # noqa: E402
import protocol  # noqa: E402
import qr  # noqa: E402

VECTORS = json.loads((SHARED_VECTORS / 'signed-payload-v1.json').read_text(encoding='utf-8'))


class CanonicalVectors(unittest.TestCase):
    def test_valid_vectors_parse_and_reencode_byte_for_byte(self):
        for vector in VECTORS['valid']:
            with self.subTest(vector['name']):
                data = base64.b64decode(vector['canonical_base64'])
                fields = protocol.parse_signed_payload(data)
                self.assertEqual(fields, vector['fields'])
                self.assertEqual(protocol.canonical_bytes(vector['fields']), data)
                self.assertEqual(protocol.sha256_hex(data), vector['canonical_sha256'])

    def test_invalid_vectors_rejected_with_the_sdk_reason(self):
        for vector in VECTORS['invalid']:
            with self.subTest(vector['name']):
                with self.assertRaises(protocol.Rejected) as caught:
                    protocol.parse_signed_payload(base64.b64decode(vector['canonical_base64']))
                self.assertEqual(caught.exception.reason, vector['reason'])

    def test_response_mismatch_cases(self):
        mismatch = VECTORS['response_mismatch']
        data = base64.b64decode(mismatch['base_canonical_base64'])
        fields = protocol.parse_signed_payload(data)
        envelope = {camel: fields[snake] for camel, snake in protocol.ENVELOPE_FIELDS.items()}
        envelope.update(canonicalPayloadBase64=mismatch['base_canonical_base64'],
                        canonicalPayloadHash=mismatch['base_canonical_sha256'])
        protocol.verify_envelope(envelope)
        for case in mismatch['cases']:
            with self.subTest(case['name']):
                tampered = dict(envelope, **{case['field']: case['value']})
                with self.assertRaises(protocol.Rejected) as caught:
                    protocol.verify_envelope(tampered)
                self.assertEqual(caught.exception.reason, 'response_mismatch')

    def test_amount_formatting(self):
        for case in VECTORS['amount_formatting']:
            self.assertEqual(protocol.format_minor_units(case['amount_minor'], case['fraction_digits']), case['expected'])

    def test_key_order_is_utf16_like_javascript(self):
        # In code-point order U+FF5E comes before U+1F600; in UTF-16 order
        # (what Array.prototype.sort uses) U+1F600 = D83D DE00 comes first.
        # Python's plain sorted() would disagree with the server here.
        self.assertEqual(protocol.canonical_bytes({'\uFF5E': '2', '\U0001F600': '1'}).decode(),
                         '{"\U0001F600":"1","\uFF5E":"2"}')

    def test_string_escaping_matches_json_stringify(self):
        self.assertEqual(protocol.canonical_bytes({'a': 'q"b\\s/\n\t\x01 ż'}).decode(),
                         '{"a":"q\\"b\\\\s/\\n\\t\\u0001 ż"}')


class Ecdsa(unittest.TestCase):
    def test_sign_verify_both_encodings(self):
        key = p256.generate_private_key()
        pub = p256.public_key(key)
        message = b'{"amount_minor":"125000"}'
        r, s = p256.sign(key, message)
        self.assertTrue(p256.verify(pub, message, *p256.der_to_rs(p256.rs_to_der(r, s))))
        self.assertTrue(p256.verify(pub, message, *p256.raw_to_rs(p256.rs_to_raw(r, s))))
        self.assertFalse(p256.verify(pub, message + b' ', r, s))
        self.assertFalse(p256.verify(p256.public_key(p256.generate_private_key()), message, r, s))

    def test_spki_round_trip_and_rejections(self):
        pub = p256.public_key(p256.generate_private_key())
        spki = p256.spki_from_public_key(pub)
        self.assertEqual(p256.public_key_from_spki(spki), pub)
        off_curve = bytearray(spki)
        off_curve[-1] ^= 1
        for bad in (spki[:-1], spki + b'\x00', bytes(off_curve)):
            with self.assertRaises(p256.InvalidKey):
                p256.public_key_from_spki(bad)

    def test_der_is_strict(self):
        key = p256.generate_private_key()
        der = p256.rs_to_der(*p256.sign(key, b'x'))
        for bad in (der + b'\x00', der[:-1], b'\x31' + der[1:]):
            with self.assertRaises(ValueError):
                p256.der_to_rs(bad)

    def test_out_of_range_components_rejected(self):
        pub = p256.public_key(p256.generate_private_key())
        self.assertFalse(p256.verify(pub, b'x', 0, 1))
        self.assertFalse(p256.verify(pub, b'x', 1, p256.N))


class EcdsaInterop(unittest.TestCase):
    """Signatures made by OpenSSL, WebCrypto and the JVM verify here, and
    fail once the message or signature changes."""
    VECTORS = json.loads((ROOT / 'tests' / 'vectors' / 'ecdsa-interop.json').read_text(encoding='utf-8'))

    def test_foreign_signatures_verify(self):
        message = self.VECTORS['message'].encode()
        for vector in self.VECTORS['signatures']:
            with self.subTest(vector['producer']):
                key = p256.public_key_from_spki(base64.b64decode(vector['public_key_spki_base64']))
                r, s = p256.decode_signature(base64.b64decode(vector['signature_base64']), vector['format'])
                self.assertTrue(p256.verify(key, message, r, s))
                self.assertFalse(p256.verify(key, message + b' ', r, s))
                self.assertFalse(p256.verify(key, message, r, (s + 1) % p256.N))


class OfflineVectors(unittest.TestCase):
    """Offline confirmation derivation identical to Auth Core and the SDKs."""
    VECTORS = json.loads((SHARED_VECTORS / 'device-protocols-v1.json').read_text(encoding='utf-8'))['offline']

    def test_ecdh_key_code_and_qr_match(self):
        v = self.VECTORS
        shared = p256.ecdh_shared_secret(int(v['device_private_scalar_hex'], 16),
                                         p256.public_key(int(v['server_private_scalar_hex'], 16)))
        self.assertEqual(shared.hex(), v['shared_secret_hex'])
        key = protocol.derive_offline_key(shared, v['credential_id'])
        self.assertEqual(key.hex(), v['offline_key_hex'])
        for c in v['confirmations']:
            with self.subTest(c['name']):
                canonical = base64.b64decode(c['canonical_base64'])
                tag = protocol.offline_tag(key, canonical)
                self.assertEqual(base64.b64encode(tag).decode(), c['tag_base64'])
                self.assertEqual(protocol.offline_code(tag), c['code'])
                self.assertEqual(protocol.offline_qr_payload(canonical), c['qr_payload'])


class QrCode(unittest.TestCase):
    # Output verified with independent decoders (OpenCV QRCodeDetector and
    # QRCodeDetectorAruco). Re-verify before changing this value.
    KNOWN_TEXT = 'NXS1.eyJhbW91bnRfbWlub3IiOiIxMjUwMDAifQ'
    KNOWN_SVG_SHA256 = '0bca1da73e45b72e74ae33cee0a44dc3b936801352069c82c3d3c0127f0c4d58'

    def test_known_answer(self):
        svg = qr.to_svg(qr.encode(self.KNOWN_TEXT, 'M'))
        self.assertEqual(hashlib.sha256(svg.encode()).hexdigest(), self.KNOWN_SVG_SHA256)

    def test_structure(self):
        modules = qr.encode(self.KNOWN_TEXT, 'M')
        self.assertEqual(len(modules), 29)  # version 3
        finder = [row[:7] for row in modules[:7]]
        self.assertEqual(finder[0], [True] * 7)
        self.assertEqual(finder[3], [True, False, True, True, True, False, True])
        self.assertEqual([modules[6][x] for x in range(8, 21)], [x % 2 == 0 for x in range(8, 21)], 'timing pattern')

    def test_offline_payload_fits_and_large_input_is_refused(self):
        payload = protocol.offline_qr_payload(base64.b64decode(VECTORS['valid'][0]['canonical_base64']))
        self.assertLessEqual(len(qr.encode(payload, 'M')), 4 * 30 + 17)
        with self.assertRaises(qr.DataTooLong):
            qr.encode('x' * 3000, 'M')


class Contracts(unittest.TestCase):
    def test_openapi_parses(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('PyYAML not installed')
        doc = yaml.safe_load((ROOT / 'openapi.yaml').read_text(encoding='utf-8'))
        self.assertEqual(doc['openapi'], '3.0.3')
        self.assertIn('/api/v1/authorizations/{authorizationId}/signature', doc['paths'])


if __name__ == '__main__':
    unittest.main()
