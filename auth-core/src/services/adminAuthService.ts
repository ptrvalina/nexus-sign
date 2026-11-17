import { randomBytes } from 'node:crypto';
import { pool } from '../db/pool';
import { redis } from '../db/redis';
import { tokenKey } from '../crypto/tokenDigest';
import { hashPassword, needsRehash, verifyAgainstDummy, verifyPassword } from '../crypto/password';
import { decryptSecretBytes, encryptSecret } from '../crypto/secretBox';
import { verifyTotp } from '../crypto/totp';
import { env } from '../config/env';
import { recordAuditEvent } from './auditService';

export type AdminRole = 'administrator' | 'operator' | 'auditor';

export class InvalidAdminCredentialsError extends Error {
  constructor() {
    super('Invalid username, password or one-time code');
    this.name = 'InvalidAdminCredentialsError';
  }
}

export class WeakPasswordError extends Error {
  constructor(minLength: number) {
    super(`Password must be at least ${minLength} characters`);
    this.name = 'WeakPasswordError';
  }
}

const MIN_PASSWORD_LENGTH = 12;
const SESSION_KEY_PREFIX = 'admin_session:';
const SESSION_TTL_SECONDS = 8 * 60 * 60; // absolute limit, a typical operator shift
const SESSION_IDLE_SECONDS = 30 * 60; // ended after 30 minutes without a request

export interface AdminSession {
  username: string;
  role: AdminRole;
  /** The bank this account is limited to; null for a platform operator. */
  clientId: string | null;
}

export interface RegisterAdminUserInput {
  username: string;
  password: string;
  role: AdminRole;
  /** Limits the account to one bank; omitted for a platform operator. */
  clientId?: string | null;
  /** TOTP secret to enrol (replaces any previous one). */
  totpSecret?: Buffer;
}

/** Creates or updates an admin account. Not exposed over HTTP; accounts are
 * provisioned with the createAdminUser CLI. The minimum password length
 * is enforced here because scrypt cost does not protect a guessable password. */
export async function registerAdminUser(input: RegisterAdminUserInput): Promise<void> {
  if (input.password.length < MIN_PASSWORD_LENGTH) {
    throw new WeakPasswordError(MIN_PASSWORD_LENGTH);
  }

  const passwordHash = await hashPassword(input.password);
  const totp = input.totpSecret ? encryptSecret(input.totpSecret, 'admin', input.username) : null;
  await pool.query(
    `INSERT INTO admin_users (username, password_hash, role, client_id, totp_secret_encrypted)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role, client_id = EXCLUDED.client_id,
           totp_secret_encrypted = COALESCE(EXCLUDED.totp_secret_encrypted, admin_users.totp_secret_encrypted),
           totp_last_step = CASE WHEN EXCLUDED.totp_secret_encrypted IS NULL THEN admin_users.totp_last_step END,
           session_version = admin_users.session_version + 1`,
    [input.username, passwordHash, input.role, input.clientId ?? null, totp],
  );
}

interface AdminRow {
  password_hash: string;
  role: AdminRole;
  status: string;
  client_id: string | null;
  totp_secret_encrypted: string | null;
  totp_last_step: string | null;
  session_version: number;
}

/**
 * Verifies username, password and TOTP code and, on success, issues a session
 * token. Unknown user, disabled account, wrong password and wrong or reused
 * code are indistinguishable to the caller; the audit log records which.
 * An account with a TOTP secret always needs a code; without one, login is
 * refused while ADMIN_MFA_REQUIRED is on (the production setting). With
 * `requireSecondFactor`, an account without TOTP is refused even where
 * ADMIN_MFA_REQUIRED is off (used while the account-wide failure limit is hit).
 */
export async function login(username: string, password: string, totpCode?: string, options: { requireSecondFactor?: boolean } = {}): Promise<{ sessionToken: string; session: AdminSession }> {
  const result = await pool.query<AdminRow>(
    `SELECT password_hash, role, status, client_id, totp_secret_encrypted, totp_last_step, session_version FROM admin_users WHERE username = $1`,
    [username],
  );
  const row = result.rows[0];
  const refuse = async (reason: string): Promise<never> => {
    await recordAuditEvent('admin_login_failed', { actor: `admin:${username.slice(0, 64)}`, clientId: row?.client_id ?? undefined }, { reason });
    throw new InvalidAdminCredentialsError();
  };
  if (!row || row.status !== 'ACTIVE') {
    await verifyAgainstDummy(password);
    return refuse(row ? 'account_disabled' : 'unknown_account');
  }
  if (!(await verifyPassword(password, row.password_hash))) return refuse('wrong_password');

  if (row.totp_secret_encrypted) {
    const secret = decryptSecretBytes(row.totp_secret_encrypted, 'admin', username);
    const step = verifyTotp(secret, totpCode ?? '', row.totp_last_step === null ? null : Number(row.totp_last_step));
    if (step === null) return refuse(totpCode ? 'wrong_or_reused_totp' : 'totp_missing');
    // Concurrent logins with the same code: only one moves the step forward.
    const claimed = await pool.query(
      `UPDATE admin_users SET totp_last_step = $2 WHERE username = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)`,
      [username, step],
    );
    if (claimed.rowCount !== 1) return refuse('wrong_or_reused_totp');
  } else if (env.ADMIN_MFA_REQUIRED || options.requireSecondFactor) {
    return refuse('totp_not_enrolled');
  }

  // Hashes from 1.4 (scrypt N=2^14) are upgraded with the password just verified.
  const upgraded = needsRehash(row.password_hash) ? await hashPassword(password) : null;
  await pool.query(`UPDATE admin_users SET last_login_at = now(), password_hash = COALESCE($2, password_hash) WHERE username = $1`, [username, upgraded]);

  const sessionToken = randomBytes(32).toString('base64url');
  const session: AdminSession = { username, role: row.role, clientId: row.client_id };
  await redis.set(tokenKey(SESSION_KEY_PREFIX, sessionToken),
    JSON.stringify({ username, version: row.session_version, expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000 }), 'EX', SESSION_IDLE_SECONDS);
  await recordAuditEvent('admin_login', { actor: `admin:${username}`, clientId: row.client_id ?? undefined }, { role: row.role, mfa: Boolean(row.totp_secret_encrypted) });

  return { sessionToken, session };
}

/** Resolves a session and re-checks the account on every request, so
 * disabling an admin, changing their role or resetting their password or
 * TOTP secret takes effect immediately. Each request extends the idle
 * timeout, never past the absolute session lifetime. */
export async function resolveSession(sessionToken: string): Promise<AdminSession | null> {
  const raw = await redis.get(tokenKey(SESSION_KEY_PREFIX, sessionToken));
  if (!raw) return null;
  const key = tokenKey(SESSION_KEY_PREFIX, sessionToken);
  const session = JSON.parse(raw) as { username: string; version?: number; expiresAt?: number };
  const account = await pool.query<{ role: AdminRole; status: string; client_id: string | null; session_version: number }>(
    `SELECT role, status, client_id, session_version FROM admin_users WHERE username = $1`, [session.username]);
  const row = account.rows[0];
  const remainingMs = (session.expiresAt ?? 0) - Date.now();
  if (!row || row.status !== 'ACTIVE' || session.version !== row.session_version || remainingMs <= 0) {
    await redis.del(key);
    return null;
  }
  await redis.expire(key, Math.max(1, Math.min(SESSION_IDLE_SECONDS, Math.ceil(remainingMs / 1000))));
  return { username: session.username, role: row.role, clientId: row.client_id };
}

export async function logout(sessionToken: string): Promise<void> {
  await redis.del(tokenKey(SESSION_KEY_PREFIX, sessionToken));
}

/** Role hierarchy: auditor is read-only, operator can act on identities and
 * authorizations, administrator adds client and account management. Each
 * role includes the permissions of the roles below it. */
const ROLE_RANK: Record<AdminRole, number> = { auditor: 0, operator: 1, administrator: 2 };

export function roleAtLeast(role: AdminRole, minimum: AdminRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}
