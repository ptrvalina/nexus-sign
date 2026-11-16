import { createHash, randomBytes } from 'node:crypto';
import { redis } from '../db/redis';
import { tokenKey } from '../crypto/tokenDigest';

const KEY_PREFIX = 'mobile_session:';
const BOOTSTRAP_TTL = 300;

/** Mobile tokens exist only for enrolment; an enrolled device signs its
 * requests (middleware/mobileAuth.ts). */
export type MobileSessionPurpose = 'BOOTSTRAP';

/** The bank's authorization to replace an identity's enrolled device: how it
 * re-identified the customer and its own reference for that check. */
export interface ReplacementAuthorization {
  method: 'BRANCH_VISIT' | 'VIDEO_IDENTIFICATION' | 'IN_APP_STRONG_AUTHENTICATION' | 'OTHER';
  reference: string;
  /** The approved or matured request (deviceReplacementService) the enrolment uses. */
  replacementId: string;
}

export interface MobileSession {
  token: string;
  clientId: string;
  nexusId: string;
  purpose: MobileSessionPurpose;
  expiresIn: number;
  attestationChallenge?: string;
}

interface StoredSession {
  clientId: string;
  nexusId: string;
  purpose: MobileSessionPurpose;
  attestationChallenge?: string;
  /** The enrolment may replace the enrolled device. */
  replacement?: ReplacementAuthorization;
}

export async function issueBootstrapToken(clientId: string, nexusId: string, replacement?: ReplacementAuthorization): Promise<MobileSession> {
  const purpose: MobileSessionPurpose = 'BOOTSTRAP';
  const token = `ms_${randomBytes(32).toString('base64url')}`;
  const expiresIn = BOOTSTRAP_TTL;
  const attestationChallenge = createHash('sha256').update(token, 'utf8').digest('base64url');
  const value: StoredSession = { clientId, nexusId, purpose, attestationChallenge, replacement };
  await redis.set(tokenKey(KEY_PREFIX, token), JSON.stringify(value), 'EX', expiresIn);
  return { token, clientId, nexusId, purpose, expiresIn, attestationChallenge };
}

export async function resolveMobileSession(token: string): Promise<StoredSession | null> {
  if (!token.startsWith('ms_')) return null;
  const raw = await redis.get(tokenKey(KEY_PREFIX, token));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredSession;
    if (!parsed.clientId || !/^\d{9}$/.test(parsed.nexusId)) return null;
    // SESSION tokens issued by 1.x and 2.0.0-rc.1 are no longer accepted.
    if (parsed.purpose !== 'BOOTSTRAP') return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Atomically resolves and deletes a token, so a bootstrap token can be used
 * exactly once even under concurrent requests. */
export async function consumeMobileSession(token: string): Promise<StoredSession | null> {
  if (!token.startsWith('ms_')) return null;
  const raw = await redis.getdel(tokenKey(KEY_PREFIX, token));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredSession;
    return parsed.purpose === 'BOOTSTRAP' ? parsed : null;
  } catch {
    return null;
  }
}
