"""ECDSA over NIST P-256 with SHA-256, standard library only.

The sandbox must run with nothing but a Python interpreter, so signature
verification is implemented here instead of pulling in `cryptography`.
Verification uses only public data and is therefore not timing sensitive.
Signing exists for the automated tests and the command-line device simulator;
it uses deterministic nonces (RFC 6979) and is not constant time — it must
never be used with a key that protects anything real.
"""

import base64
import hashlib
import hmac
import secrets

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

# DER prefix of a SubjectPublicKeyInfo for id-ecPublicKey / prime256v1 with an
# uncompressed point. It is what WebCrypto, Android Keystore, iOS
# (SecKeyCopyExternalRepresentation + header) and OpenSSL all export.
SPKI_PREFIX = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')


class InvalidKey(ValueError):
    pass


def _on_curve(pt):
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


# Jacobian coordinates: (X, Y, Z) represents (X/Z^2, Y/Z^3); Z == 0 is infinity.
def _double(p1):
    x1, y1, z1 = p1
    if z1 == 0 or y1 == 0:
        return (0, 1, 0)
    ysq = y1 * y1 % P
    s = 4 * x1 * ysq % P
    zsq = z1 * z1 % P
    m = 3 * (x1 - zsq) * (x1 + zsq) % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * ysq * ysq) % P
    z3 = 2 * y1 * z1 % P
    return (x3, y3, z3)


def _add(p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1sq, z2sq = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2sq % P, x2 * z1sq % P
    s1, s2 = y1 * z2sq * z2 % P, y2 * z1sq * z1 % P
    if u1 == u2:
        return _double(p1) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    x3 = (r * r - h3 - 2 * u1 * h2) % P
    y3 = (r * (u1 * h2 - x3) - s1 * h3) % P
    z3 = h * z1 * z2 % P
    return (x3, y3, z3)


def _mul(k, pt):
    result, addend = (0, 1, 0), (pt[0], pt[1], 1)
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _double(addend)
        k >>= 1
    return result


def _affine(pt):
    x, y, z = pt
    if z == 0:
        return None
    zinv = pow(z, -1, P)
    zinv2 = zinv * zinv % P
    return (x * zinv2 % P, y * zinv2 * zinv % P)


def _digest_int(message):
    return int.from_bytes(hashlib.sha256(message).digest(), 'big')


# --- Public keys ---

def public_key_from_spki(der):
    """Parses a DER SubjectPublicKeyInfo and returns the curve point.

    Only the single fixed encoding for P-256 uncompressed points is accepted;
    anything else (other curves, compressed points, trailing data) is refused.
    """
    if len(der) != len(SPKI_PREFIX) + 65 or not der.startswith(SPKI_PREFIX):
        raise InvalidKey('not a P-256 SubjectPublicKeyInfo with an uncompressed point')
    point = der[len(SPKI_PREFIX):]
    if point[0] != 0x04:
        raise InvalidKey('point is not uncompressed')
    pt = (int.from_bytes(point[1:33], 'big'), int.from_bytes(point[33:65], 'big'))
    if not _on_curve(pt):
        raise InvalidKey('point is not on P-256')
    return pt


def spki_from_public_key(pt):
    return SPKI_PREFIX + b'\x04' + pt[0].to_bytes(32, 'big') + pt[1].to_bytes(32, 'big')


def public_key_pem(pt):
    body = base64.encodebytes(spki_from_public_key(pt)).decode().replace('\n', '')
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(lines) + '\n-----END PUBLIC KEY-----\n'


# --- Signature encodings ---

def raw_to_rs(sig):
    if len(sig) != 64:
        raise ValueError('raw ECDSA signature must be 64 bytes')
    return int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')


def rs_to_raw(r, s):
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, 'big')
    return b'\x02' + bytes([len(b)]) + b


def rs_to_der(r, s):
    body = _der_int(r) + _der_int(s)
    return b'\x30' + bytes([len(body)]) + body


def der_to_rs(sig):
    """Strict DER decoding of ECDSA-Sig-Value (minimal lengths, no trailing data)."""
    def read_int(buf, i):
        if i + 2 > len(buf) or buf[i] != 0x02:
            raise ValueError('expected INTEGER')
        ln = buf[i + 1]
        if ln == 0 or ln > 33 or i + 2 + ln > len(buf):
            raise ValueError('bad INTEGER length')
        v = buf[i + 2:i + 2 + ln]
        if v[0] & 0x80:
            raise ValueError('negative INTEGER')
        if ln > 1 and v[0] == 0 and not v[1] & 0x80:
            raise ValueError('non-minimal INTEGER')
        return int.from_bytes(v, 'big'), i + 2 + ln

    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ValueError('bad SEQUENCE')
    r, i = read_int(sig, 2)
    s, i = read_int(sig, i)
    if i != len(sig):
        raise ValueError('trailing data')
    return r, s


def decode_signature(sig, fmt):
    if fmt == 'raw':
        return raw_to_rs(sig)
    if fmt == 'der':
        return der_to_rs(sig)
    raise ValueError('signatureFormat must be "der" or "raw"')


# --- ECDSA ---

def verify(public_key, message, r, s):
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = _digest_int(message)
    w = pow(s, -1, N)
    u1, u2 = e * w % N, r * w % N
    pt = _affine(_add(_mul(u1, G), _mul(u2, public_key)))
    return pt is not None and pt[0] % N == r


def _rfc6979_k(d, h1):
    x = d.to_bytes(32, 'big')
    h = (int.from_bytes(h1, 'big') % N).to_bytes(32, 'big')
    v, k = b'\x01' * 32, b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, 'big')
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(private_key, message):
    """Returns (r, s) with low-S normalization. Test and simulator use only."""
    h1 = hashlib.sha256(message).digest()
    e = int.from_bytes(h1, 'big')
    k = _rfc6979_k(private_key, h1)
    r = _affine(_mul(k, G))[0] % N
    s = pow(k, -1, N) * (e + r * private_key) % N
    if s > N // 2:
        s = N - s
    return r, s


def generate_private_key():
    return secrets.randbelow(N - 1) + 1


def public_key(private_key):
    return _affine(_mul(private_key, G))


# --- ECDH ---

def ecdh_shared_secret(private_key, public_key):
    """X9.63 ECDH: the x coordinate of private_key * public_key, 32 bytes."""
    if not _on_curve(public_key):
        raise InvalidKey('point is not on P-256')
    shared = _affine(_mul(private_key, public_key))
    if shared is None:
        raise InvalidKey('degenerate shared point')
    return shared[0].to_bytes(32, 'big')
