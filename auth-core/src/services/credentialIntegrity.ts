import { createHash, createPublicKey, verify } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { HsmAdapter } from '../crypto/hsmAdapter';
import { env } from '../config/env';
import { pool } from '../db/pool';
import { recordAuditEvent } from './auditService';
import { evidenceHash, getEvidenceRecord, type SealedEvidence } from './evidenceService';

/**
 * Database rows are not trusted for the keys that decide who the customer is.
 * Before a credential's keys are used (a device-signed request, a transaction
 * signature, an offline code), they are compared with the credential's sealed
 * CREDENTIAL_ENROLLED record, whose HSM seal is checked. A database writer
 * who replaces a key, or points the credential at another record, is refused
 * and the attempt is audited as `integrity_violation`.
 *
 * Verified records are cached by evidence ID (records are append-only and
 * their content is covered by the seal).
 */
export class CredentialIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialIntegrityError';
  }
}

export interface CredentialKeys {
  credentialId: string;
  nexusId: string;
  publicKeyPem: string;
  authPublicKeyPem: string | null;
  offlinePublicKeyPem: string | null;
  enrolmentEvidenceId: string | null;
}

interface VerifiedEnrolment {
  evidenceHash: string;
  keys: { signingPublicKeyPem: string; authPublicKeyPem: string | null; offlinePublicKeyPem: string | null };
}

const CACHE_LIMIT = 10_000;
const verifiedEnrolments = new Map<string, VerifiedEnrolment>();
let keyring: { hsm: HsmAdapter; retired: Map<string, string> } | null = null;

/** Called once at startup with the HSM adapter whose key seals evidence. */
export function configureEvidenceKeyring(hsm: HsmAdapter): void {
  keyring = { hsm, retired: parseRetiredKeys(env.EVIDENCE_RETIRED_PUBLIC_KEYS_PEM) };
}

/** Every evidence public key this deployment has sealed with, by key ID:
 * the current HSM key and keys retired by rotation. Published with exports. */
export async function evidencePublicKeys(): Promise<Record<string, string>> {
  if (!keyring) throw new Error('Evidence keyring is not configured');
  return { ...Object.fromEntries(keyring.retired), [await keyring.hsm.evidenceKeyId()]: await keyring.hsm.evidencePublicKeyPem() };
}

/**
 * Checks the credential's keys against its sealed enrolment and returns the
 * enrolment's evidence hash (an AUTHORIZATION record refers to it).
 */
export async function assertCredentialIntegrity(credential: CredentialKeys, runner: Pick<PoolClient, 'query'> = pool): Promise<string> {
  const failure = async (reason: string): Promise<never> => {
    await recordAuditEvent('integrity_violation', { nexusId: credential.nexusId },
      { credentialId: credential.credentialId, reason }).catch(() => undefined);
    throw new CredentialIntegrityError(`Credential integrity check failed: ${reason}`);
  };
  if (!credential.enrolmentEvidenceId) return failure('the credential has no sealed enrolment record');

  let enrolment = verifiedEnrolments.get(credential.enrolmentEvidenceId);
  if (!enrolment) {
    const record = await getEvidenceRecord(runner, credential.enrolmentEvidenceId);
    if (!record) return failure('the sealed enrolment record does not exist');
    const problem = await sealProblem(record);
    if (problem) return failure(problem);
    const payload = record.sealedPayload as { recordType?: string; credentialId?: string; nexusId?: string; keys?: VerifiedEnrolment['keys'] };
    if (payload.recordType !== 'CREDENTIAL_ENROLLED' || !payload.keys) return failure('the referenced record is not a credential enrolment');
    if (payload.credentialId !== credential.credentialId || payload.nexusId !== credential.nexusId) {
      return failure('the sealed enrolment belongs to another credential');
    }
    enrolment = { evidenceHash: record.evidenceHash, keys: payload.keys };
    if (verifiedEnrolments.size >= CACHE_LIMIT) verifiedEnrolments.clear();
    verifiedEnrolments.set(credential.enrolmentEvidenceId, enrolment);
  }
  if (!sameKey(enrolment.keys.signingPublicKeyPem, credential.publicKeyPem)
    || !sameKey(enrolment.keys.authPublicKeyPem, credential.authPublicKeyPem)
    || !sameKey(enrolment.keys.offlinePublicKeyPem, credential.offlinePublicKeyPem)) {
    return failure('the credential keys differ from the sealed enrolment');
  }
  return enrolment.evidenceHash;
}

/** Checks the hash and HSM seal of a stored record; null when both hold. */
export async function sealProblem(record: SealedEvidence): Promise<string | null> {
  if (record.schemaVersion !== '3') return 'the record is not schema 3';
  if (evidenceHash(record.sealedPayload) !== record.evidenceHash) return 'the record content does not match its evidence hash';
  const keys = await evidencePublicKeys();
  const sealKey = record.sealKeyId ? keys[record.sealKeyId] : undefined;
  if (!sealKey) return 'the record was sealed with an unknown evidence key';
  const ok = verify('sha256', Buffer.from(record.evidenceHash, 'hex'), { key: sealKey, dsaEncoding: 'der' }, Buffer.from(record.hsmSignature, 'base64'));
  return ok ? null : 'the HSM seal does not verify';
}

function sameKey(sealed: string | null | undefined, current: string | null | undefined): boolean {
  if (!sealed || !current) return !sealed && !current;
  return spki(sealed).equals(spki(current));
}

function spki(pem: string): Buffer {
  return createPublicKey(pem).export({ type: 'spki', format: 'der' });
}

function parseRetiredKeys(bundle: string | undefined): Map<string, string> {
  const keys = new Map<string, string>();
  for (const block of (bundle ?? '').match(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/g) ?? []) {
    const der = createPublicKey(block).export({ type: 'spki', format: 'der' });
    keys.set(createHash('sha256').update(der).digest('hex'), createPublicKey(block).export({ type: 'spki', format: 'pem' }).toString());
  }
  return keys;
}
