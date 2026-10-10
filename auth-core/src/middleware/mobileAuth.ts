import { verify } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { redis } from '../db/redis';
import { env } from '../config/env';
import { resolveMobileSession, type ReplacementAuthorization } from '../services/mobileSessionService';
import { getNexusIdentityStatus } from '../services/nexusIdentityService';
import { getActiveDeviceCredential } from '../services/credentialService';
import { deviceRequestSigningInput } from '../services/deviceProtocol';
import { getClientRecord } from '../services/clientService';
import { assertCredentialIntegrity, CredentialIntegrityError } from '../services/credentialIntegrity';
import { setRequestActor } from '../services/requestContext';

export interface MobileAuthenticatedRequest extends Request {
  mobileClientId?: string;
  mobileNexusId?: string;
  /** BOOTSTRAP token (enrolment) or DEVICE signature (enrolled device). */
  mobileSessionPurpose?: 'BOOTSTRAP' | 'DEVICE';
  mobileAttestationChallenge?: string;
  /** The device credential that signed the request. */
  mobileCredentialId?: string;
  /** BOOTSTRAP tokens issued with the bank's device replacement authorization. */
  mobileReplacement?: ReplacementAuthorization;
  /** Raw request body, captured by the JSON parser for signature checks. */
  rawBody?: Buffer;
}

const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Authenticates the embedded SDK in one of two ways:
 *
 * 1. Device signature (every enrolled device). Headers `X-NEXUS-Credential`,
 *    `X-NEXUS-Timestamp`, `X-NEXUS-Nonce`, `X-NEXUS-Signature`: an ECDSA P-256
 *    signature by the device's hardware authentication key over the method,
 *    path, timestamp, nonce, credential and body hash (deviceProtocol.ts).
 *    No token exists that could be stolen or replayed; each nonce is accepted
 *    once.
 * 2. A single-use BOOTSTRAP token issued through the bank backend, for
 *    enrolment only. There is no bearer token for an enrolled device.
 */
export async function authenticateMobileSession(req: MobileAuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  try {
    if (req.header('x-nexus-signature') !== undefined) {
      await authenticateDeviceSignature(req, res, next);
      return;
    }
    const match = /^Bearer (?<token>.+)$/.exec(req.header('authorization') ?? '');
    if (!match?.groups?.token) {
      res.status(401).json({ error: 'Missing bootstrap token or device signature' });
      return;
    }
    const session = await resolveMobileSession(match.groups.token);
    if (!session || session.purpose !== 'BOOTSTRAP') {
      res.status(401).json({ error: 'Missing, expired, or invalid bootstrap token' });
      return;
    }
    // A suspended or revoked bank client or identity loses mobile access
    // immediately, even with an unexpired token.
    if ((await getClientRecord(session.clientId))?.status !== 'ACTIVE') {
      res.status(401).json({ error: 'Missing, expired, or invalid bootstrap token' });
      return;
    }
    const status = await getNexusIdentityStatus(session.nexusId);
    if (status !== 'ACTIVE') {
      res.status(403).json({ error: `NEXUS ID is ${status ?? 'unknown'}` });
      return;
    }
    req.mobileClientId = session.clientId;
    req.mobileNexusId = session.nexusId;
    req.mobileSessionPurpose = 'BOOTSTRAP';
    req.mobileAttestationChallenge = session.attestationChallenge;
    req.mobileReplacement = session.replacement;
    setRequestActor(`device-enrolment:${session.nexusId}`, session.clientId);
    next();
  } catch (error) {
    next(error);
  }
}

async function authenticateDeviceSignature(req: MobileAuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  const credentialId = req.header('x-nexus-credential') ?? '';
  const timestamp = req.header('x-nexus-timestamp') ?? '';
  const nonce = req.header('x-nexus-nonce') ?? '';
  const signature = Buffer.from(req.header('x-nexus-signature') ?? '', 'base64');
  const reject = (error: string, extra: Record<string, unknown> = {}) => { res.status(401).json({ error, ...extra }); };

  if (!UUID_PATTERN.test(credentialId) || !/^\d{1,12}$/.test(timestamp) || !NONCE_PATTERN.test(nonce) || signature.length === 0) {
    reject('Malformed device signature headers');
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > env.DEVICE_REQUEST_MAX_SKEW_SECONDS) {
    // serverTime lets a device with a wrong clock correct its offset once.
    reject('Device request timestamp is outside the accepted window', { serverTime: now });
    return;
  }

  const credential = await getActiveDeviceCredential(credentialId.toLowerCase());
  if (!credential?.authPublicKeyPem) {
    reject('Unknown credential or no device authentication key');
    return;
  }
  // The authentication key is a database value: it is used only if it is
  // the key sealed at enrolment.
  if (!(await credentialIntact(credential))) {
    reject('Unknown credential or no device authentication key');
    return;
  }
  const signed = deviceRequestSigningInput({
    method: req.method,
    // The path and query as the device sent them (percent-encoded).
    path: env.DEVICE_REQUEST_PATH_PREFIX + req.originalUrl,
    timestamp,
    nonce,
    credentialId: credential.credentialId,
    body: req.rawBody ?? Buffer.alloc(0),
  });
  let valid = false;
  try {
    valid = verify('sha256', signed, { key: credential.authPublicKeyPem, dsaEncoding: 'der' }, signature);
  } catch {
    valid = false;
  }
  if (!valid) {
    reject('Device signature does not verify');
    return;
  }
  // Checked after the signature, so an unauthenticated caller cannot burn nonces.
  // A timestamp is accepted up to the skew either side of now, so a nonce must
  // be remembered for the whole 2 x skew window plus clock and rounding margin
  // (NXS-034).
  const fresh = await redis.set(`device_nonce:${credential.credentialId}:${nonce}`, '1', 'EX', deviceNonceTtlSeconds(env.DEVICE_REQUEST_MAX_SKEW_SECONDS), 'NX');
  if (fresh !== 'OK') {
    reject('Device request nonce has already been used');
    return;
  }
  const status = await getNexusIdentityStatus(credential.nexusId);
  if (status !== 'ACTIVE') {
    res.status(403).json({ error: `NEXUS ID is ${status ?? 'unknown'}` });
    return;
  }
  req.mobileClientId = credential.clientId;
  req.mobileNexusId = credential.nexusId;
  req.mobileCredentialId = credential.credentialId;
  req.mobileSessionPurpose = 'DEVICE';
  setRequestActor(`device:${credential.credentialId}`, credential.clientId);
  next();
}

async function credentialIntact(credential: Parameters<typeof assertCredentialIntegrity>[0]): Promise<boolean> {
  try {
    await assertCredentialIntegrity(credential);
    return true;
  } catch (error) {
    if (error instanceof CredentialIntegrityError) return false;
    throw error;
  }
}

/** How long a device request nonce is remembered (NXS-034). */
export function deviceNonceTtlSeconds(maxSkewSeconds: number): number {
  return maxSkewSeconds * 2 + 60;
}
