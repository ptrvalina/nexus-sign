/**
 * Conversion between the two P-256 ECDSA signature encodings:
 *
 * - DER, a SEQUENCE of two INTEGERs: produced by the Secure Enclave, the
 *   Android Keystore and OpenSSL, and sent by both SDKs;
 * - raw r || s, two 32-byte big-endian integers: what PKCS#11
 *   (CKM_ECDSA) takes and returns, so the PKCS#11 adapter converts.
 */

const P256_COORDINATE_LENGTH = 32;

/**
 * Converts a strict DER signature to raw r || s. Only the canonical encoding
 * is accepted (exact lengths, minimal positive INTEGERs, no trailing bytes):
 * the bytes received are sealed into the evidence, and an auditor's OpenSSL
 * check must reach the same verdict as the HSM.
 */
export function derToRaw(der: Buffer): Buffer {
  if (der[0] !== 0x30 || der.length < 2 || (der[1] ?? 0) & 0x80 || der[1] !== der.length - 2) {
    throw new Error('Not a canonical DER SEQUENCE');
  }
  const r = readDerInteger(der, 2);
  const s = readDerInteger(der, r.nextOffset);
  if (s.nextOffset !== der.length) {
    throw new Error('Trailing data after DER signature');
  }
  const raw = Buffer.concat([toFixedWidth(r.value), toFixedWidth(s.value)]);
  if (!rawToDer(raw).equals(der)) {
    throw new Error('DER signature is not minimally encoded');
  }
  return raw;
}

export function rawToDer(raw: Buffer): Buffer {
  if (raw.length !== P256_COORDINATE_LENGTH * 2) {
    throw new Error(`Expected ${P256_COORDINATE_LENGTH * 2}-byte raw P-256 signature, got ${raw.length} bytes`);
  }
  const r = toUnsignedInteger(raw.subarray(0, P256_COORDINATE_LENGTH));
  const s = toUnsignedInteger(raw.subarray(P256_COORDINATE_LENGTH, P256_COORDINATE_LENGTH * 2));

  const sequenceBody = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, sequenceBody.length]), sequenceBody]);
}

// --- DER encoding (raw -> DER) ---

/** DER INTEGER encoding: strip leading zero bytes, then prefix 0x00 if the
 * high bit is set, so the value is not read as negative. */
function toUnsignedInteger(bytes: Buffer): Buffer {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) {
    start += 1;
  }
  let trimmed = bytes.subarray(start);
  if ((trimmed[0] ?? 0) & 0x80) {
    trimmed = Buffer.concat([Buffer.from([0x00]), trimmed]);
  }
  return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed]);
}

// --- DER decoding (DER -> raw) ---

function readDerInteger(buf: Buffer, offset: number): { value: Buffer; nextOffset: number } {
  if (buf[offset] !== 0x02) {
    throw new Error('Expected a DER INTEGER');
  }
  const lengthByte = buf[offset + 1];
  if (lengthByte === undefined) {
    throw new Error('Unexpected end of buffer reading DER INTEGER length');
  }
  if ((lengthByte & 0x80) !== 0) {
    throw new Error('Multi-byte DER INTEGER lengths are not expected for a P-256 signature component');
  }
  const start = offset + 2;
  const end = start + lengthByte;
  if (lengthByte === 0 || end > buf.length) {
    throw new Error('DER INTEGER is empty or truncated');
  }
  if ((buf[start] ?? 0) & 0x80) {
    throw new Error('Negative DER INTEGER in signature');
  }
  return { value: buf.subarray(start, end), nextOffset: end };
}

/** Strips the leading 0x00 that DER adds to keep the value non-negative and
 * left-pads to the fixed 32-byte width of PKCS#11 raw r||s. */
function toFixedWidth(value: Buffer): Buffer {
  let trimmed = value;
  while (trimmed.length > P256_COORDINATE_LENGTH && trimmed[0] === 0x00) {
    trimmed = trimmed.subarray(1);
  }
  if (trimmed.length > P256_COORDINATE_LENGTH) {
    throw new Error(`Signature component is longer than ${P256_COORDINATE_LENGTH} bytes; not a P-256 signature`);
  }
  if (trimmed.length === P256_COORDINATE_LENGTH) {
    return Buffer.from(trimmed);
  }
  return Buffer.concat([Buffer.alloc(P256_COORDINATE_LENGTH - trimmed.length, 0), trimmed]);
}

/** Order n of the P-256 group. */
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

/**
 * Returns the signature with s replaced by n − s when s > n/2 ("low-S"), in
 * the same encoding. (r, s) and (r, n − s) verify alike; the Secure Enclave
 * and Android Keystore produce either, so Auth Core keeps one form: the
 * stored and sealed bytes, and the comparison of a resubmitted deferred
 * signature, do not depend on which one a device or proxy sent (A1-05, B-06).
 * Input that is not a well-formed signature is returned unchanged for the
 * verifier to refuse.
 */
export function normalizeLowS(signatureB64: string, format: 'der' | 'raw'): string {
  let raw: Buffer;
  try {
    raw = format === 'der' ? derToRaw(Buffer.from(signatureB64, 'base64')) : Buffer.from(signatureB64, 'base64');
  } catch {
    return signatureB64;
  }
  if (raw.length !== P256_COORDINATE_LENGTH * 2) return signatureB64;
  const s = BigInt(`0x${raw.subarray(P256_COORDINATE_LENGTH).toString('hex')}`);
  if (s <= P256_ORDER / 2n) return signatureB64;
  const low = Buffer.from((P256_ORDER - s).toString(16).padStart(P256_COORDINATE_LENGTH * 2, '0'), 'hex');
  const normalized = Buffer.concat([raw.subarray(0, P256_COORDINATE_LENGTH), low]);
  return (format === 'der' ? rawToDer(normalized) : normalized).toString('base64');
}
