/** A seal over an evidence hash. `keyId` is the SHA-256 of the sealing key's
 * SubjectPublicKeyInfo (hex), so a record names the key that sealed it and
 * stays verifiable after the evidence key is rotated. */
export interface EvidenceSeal {
  signature: Buffer;
  keyVersion: number;
  keyId: string;
}

export interface HsmAdapter {
  verifySignature(publicKeyPem: string, payload: Buffer, signature: Buffer, format: 'der' | 'raw'): Promise<boolean>;
  /** Signs an evidence payload inside the server-side HSM. Production must use PKCS#11. */
  signEvidence(payload: Buffer): Promise<EvidenceSeal>;
  /** PEM public key of the evidence signing key, published with evidence
   * exports so auditors can verify seals independently. */
  evidencePublicKeyPem(): Promise<string>;
  /** SHA-256 (hex) of the evidence public key's SubjectPublicKeyInfo. */
  evidenceKeyId(): Promise<string>;
  readonly name: string;
  healthCheck(): Promise<void>;
  close?(): Promise<void> | void;
}
