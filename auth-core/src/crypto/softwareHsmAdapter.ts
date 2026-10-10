import { createHash, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import type { EvidenceSeal, HsmAdapter } from './hsmAdapter';
import { rawToDer } from './ecdsaSignatureFormat';

export class SoftwareHsmAdapter implements HsmAdapter {
  public readonly name = 'software-dev';
  private readonly privateKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;

  async verifySignature(publicKeyPem: string, payload: Buffer, signature: Buffer, format: 'der' | 'raw'): Promise<boolean> {
    // A malformed key or signature is an invalid signature, not a server
    // error: the caller counts it as a failed attempt.
    try {
      const derSignature = format === 'raw' ? rawToDer(signature) : signature;
      return cryptoVerify('sha256', payload, { key: createPublicKey(publicKeyPem), dsaEncoding: 'der' }, derSignature);
    } catch {
      return false;
    }
  }

  async healthCheck(): Promise<void> {
    const probe = Buffer.from('NEXUS-SIGN-HSM-HEALTH-CHECK', 'utf8');
    const signature = cryptoSign('sha256', probe, { key: this.privateKey, dsaEncoding: 'der' });
    if (!cryptoVerify('sha256', probe, { key: this.privateKey, dsaEncoding: 'der' }, signature)) {
      throw new Error('Software HSM self-test failed');
    }
  }

  async evidencePublicKeyPem(): Promise<string> {
    return createPublicKey(this.privateKey).export({ type: 'spki', format: 'pem' }).toString();
  }

  async evidenceKeyId(): Promise<string> {
    return createHash('sha256').update(createPublicKey(this.privateKey).export({ type: 'spki', format: 'der' })).digest('hex');
  }

  async signEvidence(payload: Buffer): Promise<EvidenceSeal> {
    return { signature: cryptoSign('sha256', payload, { key: this.privateKey, dsaEncoding: 'der' }), keyVersion: 1, keyId: await this.evidenceKeyId() };
  }
}
