// Recovery protocol 2 on the device side, as the SDKs implement it
// (RecoveryProtocol.swift, RecoveryProtocol.kt). Used by the smoke test and
// the integration suites; specification in docs/protocol/recovery-protocol-v2.md.
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes, sign } from 'node:crypto';

const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
const spki = (key) => key.export({ type: 'spki', format: 'der' });

export function recoverySeed(words, saltB64, iterations) {
  return pbkdf2Sync(Buffer.from(words.map((w) => w.toLowerCase()).join(' '), 'utf8'), Buffer.from(saltB64, 'base64'), iterations, 32, 'sha256');
}

export function recoveryWrapKey(seed, nexusId) {
  return Buffer.from(hkdfSync('sha256', seed, Buffer.from('NEXUS-SIGN/RECOVERY-WRAP/v2'), Buffer.from(nexusId), 32));
}

export function recoveryAad(nexusId, recoverySpki) {
  return Buffer.from(`NEXUS-SIGN/RECOVERY-KEY/v2\n${nexusId}\n${sha256hex(recoverySpki)}`, 'utf8');
}

/** A new recovery key wrapped under the phrase. */
export function createRecoveryKey(words, saltB64, iterations, nexusId) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const scalar = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', recoveryWrapKey(recoverySeed(words, saltB64, iterations), nexusId), iv);
  cipher.setAAD(recoveryAad(nexusId, spki(publicKey)));
  const wrapped = Buffer.concat([iv, cipher.update(scalar), cipher.final(), cipher.getAuthTag()]);
  return { privateKey, publicKey, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), wrapped };
}

/** Opens the wrapped key of a recovery session with the phrase; throws on a wrong phrase. */
export function openRecoveryKey(words, session) {
  const wrapped = Buffer.from(session.wrappedRecoveryKey, 'base64');
  const recoveryPublicKey = createPublicKey(session.recoveryPublicKeyPem);
  const seed = recoverySeed(words, session.parameters.salt, session.parameters.iterations);
  const decipher = createDecipheriv('aes-256-gcm', recoveryWrapKey(seed, session.nexusId), wrapped.subarray(0, 12));
  decipher.setAAD(recoveryAad(session.nexusId, spki(recoveryPublicKey)));
  decipher.setAuthTag(wrapped.subarray(44));
  const scalar = Buffer.concat([decipher.update(wrapped.subarray(12, 44)), decipher.final()]);
  return createPrivateKey({ key: { ...recoveryPublicKey.export({ format: 'jwk' }), d: scalar.toString('base64url') }, format: 'jwk' });
}

export function setupSigningInput({ nexusId, credentialId, saltB64, recoveryPublicKey, wrapped }) {
  return Buffer.from(['NEXUS-SIGN/RECOVERY-SETUP/v2', nexusId, credentialId, saltB64, sha256hex(spki(recoveryPublicKey)), sha256hex(wrapped)].join('\n'), 'utf8');
}

export function proofSigningInput({ sessionId, nonceB64, nexusId, newSigningPublicKey }) {
  return Buffer.from(['NEXUS-SIGN/RECOVERY-PROOF/v2', sessionId, nonceB64, nexusId, sha256hex(spki(newSigningPublicKey))].join('\n'), 'utf8');
}

export const signDerB64 = (privateKey, bytes) => sign('sha256', bytes, { key: privateKey, dsaEncoding: 'der' }).toString('base64');
