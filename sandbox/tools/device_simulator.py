#!/usr/bin/env python3
"""Command-line stand-in for a phone running the NEXUS-SIGN SDK.

It does what the SDK does: holds a P-256 key, verifies that the authorization
response agrees with the canonical bytes (what you see is what you sign), shows
the transaction from the signed bytes and signs exactly those bytes.

    python3 tools/device_simulator.py enrol
    python3 tools/device_simulator.py sign <authorizationId>
    python3 tools/device_simulator.py offline <qrPayload>     (no network used)

Options: --base=https://sandbox.example.com   (default http://127.0.0.1:8787)
         --token=<access code>                (hosted sandbox)

The key is kept in .device-key.json next to this script. It is a throwaway test
key — the simulator's signing code is not constant time.
"""

import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import p256  # noqa: E402
import protocol  # noqa: E402


class Device:
    def __init__(self, base_url, private_key=None, credential_id=None, token=None, offline_key=None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.private_key = private_key or p256.generate_private_key()
        self.credential_id = credential_id
        self.nexus_id = None
        # Agreed with the sandbox at enrolment (the SDKs keep it in hardware).
        self.offline_key = offline_key

    def call(self, method, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        auth = {'Authorization': f'Bearer {self.token}'} if self.token else {}
        request = urllib.request.Request(self.base_url + path, data=data, method=method,
                                         headers={'Content-Type': 'application/json', **auth, **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b'{}')

    def spki_base64(self):
        return base64.b64encode(p256.spki_from_public_key(p256.public_key(self.private_key))).decode()

    def enrol(self, label='Device simulator'):
        offline_private = p256.generate_private_key()
        offline_spki = base64.b64encode(p256.spki_from_public_key(p256.public_key(offline_private))).decode()
        status, body = self.call('POST', '/api/v1/devices', {
            'publicKeySpkiBase64': self.spki_base64(), 'offlinePublicKeySpkiBase64': offline_spki, 'label': label})
        if status != 201:
            raise RuntimeError(f'enrolment failed: {status} {body}')
        self.credential_id, self.nexus_id = body['credentialId'], body['nexusId']
        server_key = p256.public_key_from_spki(base64.b64decode(body['offlineServerPublicKeySpkiBase64']))
        self.offline_key = protocol.derive_offline_key(p256.ecdh_shared_secret(offline_private, server_key), self.credential_id)
        return body

    def read_offline_challenge(self, qr_payload):
        """What the phone does with a scanned QR code, without network: strict
        parse of the canonical bytes and a check that they are for this device."""
        if not qr_payload.startswith(protocol.OFFLINE_QR_PREFIX):
            raise protocol.Rejected('invalid_qr', 'unknown QR format')
        encoded = qr_payload[len(protocol.OFFLINE_QR_PREFIX):]
        canonical = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        signed = protocol.parse_signed_payload(canonical)
        if signed['credential_id'] != self.credential_id:
            raise protocol.Rejected('wrong_device', 'the QR code is for another device')
        return canonical, signed

    def offline_code(self, qr_payload):
        canonical, _ = self.read_offline_challenge(qr_payload)
        return protocol.offline_code(protocol.offline_tag(self.offline_key, canonical))

    def fetch_verified(self, authorization_id):
        """Returns (response, signed fields). Raises protocol.Rejected when the
        response does not match the bytes that would be signed."""
        status, envelope = self.call('GET', f'/api/v1/authorizations/{authorization_id}')
        if status != 200:
            raise RuntimeError(f'fetch failed: {status} {envelope}')
        return envelope, protocol.verify_envelope(envelope)

    def sign_bytes(self, data, fmt='der'):
        r, s = p256.sign(self.private_key, data)
        raw = p256.rs_to_der(r, s) if fmt == 'der' else p256.rs_to_raw(r, s)
        return base64.b64encode(raw).decode()

    def approve(self, authorization_id, fmt='der'):
        envelope, _ = self.fetch_verified(authorization_id)
        canonical = base64.b64decode(envelope['canonicalPayloadBase64'])
        return self.call('POST', f'/api/v1/authorizations/{authorization_id}/signature',
                         {'signature': self.sign_bytes(canonical, fmt), 'signatureFormat': fmt})


def describe(signed):
    amount = protocol.format_minor_units(signed['amount_minor'], protocol.fraction_digits(signed['currency']))
    who = ' · '.join(v for v in signed['beneficiary'].values() if v.strip())
    return f"{signed['operation_type']}: {amount} {signed['currency']} → {who} • {signed['transaction_reference']}"


def main(argv):
    base = 'http://127.0.0.1:8787'
    key_file = Path(__file__).with_name('.device-key.json')
    args = [a for a in argv if not a.startswith('--')]
    base = next((a.split('=', 1)[1] for a in argv if a.startswith('--base=')), base)
    token = next((a.split('=', 1)[1] for a in argv if a.startswith('--token=')), None)
    if not args or args[0] not in ('enrol', 'sign', 'offline'):
        print(__doc__)
        return 2
    if args[0] == 'enrol':
        device = Device(base, token=token)
        info = device.enrol()
        key_file.write_text(json.dumps({'privateKey': hex(device.private_key), 'credentialId': info['credentialId'],
                                        'offlineKey': device.offline_key.hex()}))
        print(f"enrolled: credentialId={info['credentialId']} nexusId={info['nexusId']}")
        return 0
    saved = json.loads(key_file.read_text())
    device = Device(base, int(saved['privateKey'], 16), saved['credentialId'], token=token,
                    offline_key=bytes.fromhex(saved['offlineKey']) if saved.get('offlineKey') else None)
    if args[0] == 'offline':
        _, signed = device.read_offline_challenge(args[1])
        print('Confirming offline:', describe(signed))
        print('Code:', device.offline_code(args[1]))
        return 0
    _, signed = device.fetch_verified(args[1])
    print('Signing:', describe(signed))
    status, body = device.approve(args[1])
    print(status, body.get('status'), body.get('reason', ''))
    return 0 if body.get('status') == 'VERIFIED' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
