/**
 * Minimal DER TLV parser. Decodes structure only (tag, length, content,
 * children); callers interpret the content of the tags they need, see
 * appAttestService.ts.
 */
export interface DerElement {
  /** Raw tag byte, including class and constructed bits. Compare against the
   * constants below: a context-specific tag (such as X.509 `[3] extensions`)
   * differs from a universal SEQUENCE only in these bits. */
  rawTag: number;
  constructed: boolean;
  /** Tag number with class and constructed bits masked off: 0x10 for SEQUENCE,
   * 0x04 for OCTET STRING, `N` for a context-specific `[N]`. */
  tagNumber: number;
  content: Buffer;
  /** Set only when `constructed` is true; the content is itself a DER stream. */
  children: DerElement[];
  /** Bytes occupied in the source buffer (header + content), i.e. the offset
   * of the next sibling. */
  totalLength: number;
}

export const UNIVERSAL_TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OBJECT_IDENTIFIER: 0x06,
  SEQUENCE: 0x10,
  SET: 0x11,
} as const;

function parseLength(buf: Buffer, offset: number): { length: number; headerLength: number } {
  const first = buf[offset];
  if (first === undefined) {
    throw new Error('Unexpected end of buffer while reading DER length');
  }
  if ((first & 0x80) === 0) {
    return { length: first, headerLength: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0) {
    throw new Error('Indefinite-length DER encoding is not supported');
  }
  let length = 0;
  for (let i = 0; i < numBytes; i += 1) {
    const byte = buf[offset + 1 + i];
    if (byte === undefined) {
      throw new Error('Unexpected end of buffer while reading DER long-form length');
    }
    length = length * 256 + byte;
  }
  return { length, headerLength: 1 + numBytes };
}

/** Parses one DER element at `offset`. Bytes after `totalLength` are not an
 * error; callers expecting a single element ignore them. */
export function parseDerElement(buf: Buffer, offset = 0): DerElement {
  const tagByte = buf[offset];
  if (tagByte === undefined) {
    throw new Error('Unexpected end of buffer while reading DER tag');
  }
  const constructed = (tagByte & 0x20) !== 0;
  let tagNumber = tagByte & 0x1f;
  let tagLength = 1;
  // High tag numbers (>= 31, used by Android key attestation, e.g. [704])
  // follow in base-128 bytes; the last byte has the top bit clear.
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    for (;;) {
      const next = buf[offset + tagLength];
      if (next === undefined) throw new Error('Unexpected end of buffer while reading a DER tag number');
      if (tagLength > 4) throw new Error('DER tag number is too large');
      tagNumber = tagNumber * 128 + (next & 0x7f);
      tagLength += 1;
      if ((next & 0x80) === 0) break;
    }
    if (tagNumber < 31) throw new Error('Non-minimal DER tag number encoding');
  }

  const { length, headerLength } = parseLength(buf, offset + tagLength);
  const contentStart = offset + tagLength + headerLength;
  const contentEnd = contentStart + length;
  if (contentEnd > buf.length) {
    throw new Error('DER element length extends beyond the buffer');
  }

  const content = buf.subarray(contentStart, contentEnd);
  const children = constructed ? parseDerSequence(content) : [];

  return {
    rawTag: tagByte,
    constructed,
    tagNumber,
    content,
    children,
    totalLength: tagLength + headerLength + length,
  };
}

/** Parses a buffer as a flat sequence of sibling DER elements, i.e. the
 * content of a constructed element. */
function parseDerSequence(buf: Buffer): DerElement[] {
  const elements: DerElement[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const element = parseDerElement(buf, offset);
    elements.push(element);
    offset += element.totalLength;
  }
  return elements;
}

/** Encodes an OBJECT IDENTIFIER's dotted string form into its raw DER
 * content bytes (base-128 arc encoding, first two arcs combined per
 * X.690 §8.19), for comparing against a parsed element's `.content`. */
export function encodeObjectIdentifier(dotted: string): Buffer {
  const arcs = dotted.split('.').map((part) => Number.parseInt(part, 10));
  if (arcs.length < 2 || arcs.some((arc) => Number.isNaN(arc))) {
    throw new Error(`Invalid OID: ${dotted}`);
  }

  const firstArc = arcs[0] as number;
  const secondArc = arcs[1] as number;
  const bytes: number[] = [firstArc * 40 + secondArc];

  for (const arc of arcs.slice(2)) {
    bytes.push(...encodeBase128(arc));
  }

  return Buffer.from(bytes);
}

function encodeBase128(value: number): number[] {
  if (value === 0) {
    return [0];
  }
  const groups: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    groups.unshift(remaining & 0x7f);
    remaining = Math.floor(remaining / 128);
  }
  return groups.map((group, index) => (index < groups.length - 1 ? group | 0x80 : group));
}
