// The bank database's ECDSA P-256 verifier (bank-integration/p256Sql.mjs)
// against Node's OpenSSL on the same inputs: generated keys and messages,
// valid DER and raw signatures, and the corruptions an attacker or a broken
// component produces. The database must accept exactly what OpenSSL accepts,
// except compressed public keys, which it refuses by design.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import pg from 'pg';
import { createDatabase, skipWithoutServices } from './support/harness.mjs';

const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

function rawFromDer(der) {
  let i = 2;
  const read = () => { const len = der[i + 1]; const v = der.subarray(i + 2, i + 2 + len); i += 2 + len; return Buffer.from(v.toString('hex').padStart(64, '0').slice(-64), 'hex'); };
  return Buffer.concat([read(), read()]);
}
function derFromRS(r, s) {
  const enc = (x) => { let h = x.toString(16); if (h.length % 2) h = `0${h}`; let b = Buffer.from(h, 'hex'); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([2, b.length]), b]); };
  const body = Buffer.concat([enc(r), enc(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
function openssl(spki, message, signature, format) {
  try {
    return verify('sha256', message, { key: createPublicKey({ key: spki, format: 'der', type: 'spki' }), dsaEncoding: format === 'der' ? 'der' : 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}

function cases(count) {
  const out = [];
  for (let k = 0; k < count; k += 1) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const message = randomBytes(1 + ((k * 37) % 300));
    const der = sign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const raw = rawFromDer(der);
    const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`); const s = BigInt(`0x${raw.subarray(32).toString('hex')}`);
    const add = (name, signature, format, msg = message, key = spki) => out.push({ name, spki: key, message: msg, signature, format });
    add('valid DER', der, 'der');
    add('valid raw', raw, 'raw');
    const flipped = Buffer.from(der); flipped[flipped.length - 1 - (k % 10)] ^= 1 << (k % 8);
    add('one signature bit flipped', flipped, 'der');
    const otherMessage = Buffer.from(message); otherMessage[0] ^= 1;
    add('another message', der, 'der', otherMessage);
    add('high-S twin of a valid signature', derFromRS(r, N - s), 'der');
    add('raw signature declared as DER', raw, 'der');
    add('DER signature declared as raw', der, 'raw');
    add('trailing byte after DER', Buffer.concat([der, Buffer.from([0])]), 'der');
    add('another key', der, 'der', message, generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'der' }));
    if (k === 0) {
      add('r = 0', derFromRS(0n, s), 'der');
      add('s = n', derFromRS(r, N), 'der');
      add('r + n', derFromRS(r + N, s), 'der');
      const offCurve = Buffer.from(spki); offCurve[90] ^= 1;
      add('public point off the curve', der, 'der', message, offCurve);
      add('P-384 key', der, 'der', message, generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ type: 'spki', format: 'der' }));
      add('empty signature', Buffer.alloc(0), 'der');
      add('empty message, valid signature', sign('sha256', Buffer.alloc(0), { key: privateKey, dsaEncoding: 'der' }), 'der', Buffer.alloc(0));
    }
  }
  return out;
}

describe('bank database ECDSA P-256 verifier (PostgreSQL)', { skip: skipWithoutServices }, () => {
  let db; let client;
  before(async () => {
    db = await createDatabase({ schema: false });
    client = new pg.Client({ connectionString: db.url });
    await client.connect();
    const { P256_SQL } = await import('../../../bank-integration/p256Sql.mjs');
    await client.query(`CREATE SCHEMA bank; ${P256_SQL}`);
  });
  after(async () => { await client?.end(); await db?.drop(); });

  test('accepts exactly what OpenSSL accepts', async () => {
    const all = cases(Number(process.env.P256_CASES ?? 12));
    for (const c of all) {
      const expected = openssl(c.spki, c.message, c.signature, c.format);
      const got = (await client.query('SELECT bank.p256_verify($1, $2, $3, $4) AS ok', [c.spki, c.message, c.signature, c.format])).rows[0].ok;
      assert.equal(got, expected, c.name);
    }
    assert.ok(all.some((c) => c.name === 'valid DER') && all.length > 100);
  });

  test('refuses a compressed public key, which no NEXUS-SIGN component exports', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const message = Buffer.from('payment');
    const der = sign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const compressed = publicKey.export({ type: 'spki', format: 'der' }); // uncompressed; build the compressed form by hand
    const x = compressed.subarray(27, 59); const yOdd = compressed[90] & 1;
    const spki = Buffer.concat([Buffer.from('3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex'), Buffer.from([yOdd ? 3 : 2]), x]);
    assert.equal(openssl(spki, message, der, 'der'), true, 'OpenSSL accepts it');
    assert.equal((await client.query('SELECT bank.p256_verify($1, $2, $3, $4) AS ok', [spki, message, der, 'der'])).rows[0].ok, false);
  });

  test('canonical JSON of a bank statement matches the JavaScript canonicalJson', async () => {
    const { canonicalJson } = await import('../../scripts/lib/evidence.mjs');
    for (const statement of [
      { type: 'NEXUS_CREDENTIAL_REVOCATION', version: 1, nexusId: '123456789', credentialId: '00000000-0000-4000-8000-000000000001', reason: 'lost "phone" \\ / é \n\t\u0001 😀', revokedAt: '2026-11-15T10:00:00.000Z', bankKeyId: 'a'.repeat(64) },
      { type: 'NEXUS_CREDENTIAL_APPROVAL', version: 1, nexusId: '123456789', credentialId: '00000000-0000-4000-8000-000000000002', signingKeySha256: 'b'.repeat(64), reference: 'app', approvedAt: '2026-11-15T10:00:00.000Z', bankKeyId: 'c'.repeat(64) },
    ]) {
      const got = (await client.query('SELECT bank.canonical_flat_json($1::jsonb) AS t', [JSON.stringify(statement)])).rows[0].t;
      assert.equal(got, canonicalJson(statement).toString('utf8'));
    }
    assert.equal((await client.query(`SELECT bank.canonical_flat_json('{"a":{"b":1}}'::jsonb) AS t`)).rows[0].t, null, 'nested objects are refused');
  });
});
