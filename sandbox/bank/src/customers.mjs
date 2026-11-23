// Customer login for the bank app, and enrolment of the customer's phone in
// NEXUS-SIGN through the bank (the bank creates the NEXUS ID and issues the
// BOOTSTRAP token; the SDK creates the keys on the phone).
import { createHash, randomBytes } from 'node:crypto';
import { now } from './db.mjs';
import { recordEvent } from './events.mjs';
import { checkPassword } from './passwords.mjs';
import { BankError } from './payments.mjs';

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_FAILURES = 10;

export function createCustomers({ db, authCore }) {
  const failures = new Map();
  const tokenHash = (token) => createHash('sha256').update(token).digest('hex');
  const byId = (id) => db.prepare('SELECT * FROM customers WHERE id = ?').get(id);

  function login(loginName, password) {
    const key = String(loginName ?? '').toLowerCase();
    if ((failures.get(key) ?? 0) >= MAX_FAILURES) throw new BankError(429, 'LOCKED', 'Слишком много попыток входа. Сбросьте песочницу или подождите перезапуска.');
    const customer = db.prepare("SELECT * FROM customers WHERE login = ? AND device_kind = 'PHONE'").get(key);
    if (!customer || !checkPassword(password, customer.password_hash)) {
      failures.set(key, (failures.get(key) ?? 0) + 1);
      recordEvent(db, { type: 'LOGIN_FAILED', source: 'DEVICE', customerId: customer?.id ?? null, detail: { login: key } });
      throw new BankError(401, 'BAD_CREDENTIALS', 'Неверный логин или пароль');
    }
    failures.delete(key);
    const token = randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO app_sessions (token_hash, customer_id, expires_at) VALUES (?, ?, ?)')
      .run(tokenHash(token), customer.id, new Date(Date.now() + SESSION_TTL_MS).toISOString());
    recordEvent(db, { type: 'LOGIN', source: 'DEVICE', customerId: customer.id });
    return { token, customer: publicCustomer(customer) };
  }

  function fromToken(authorization) {
    const match = /^Bearer (\S+)$/.exec(authorization ?? '');
    if (!match) return null;
    const session = db.prepare('SELECT * FROM app_sessions WHERE token_hash = ? AND expires_at > ?').get(tokenHash(match[1]), now());
    return session ? byId(session.customer_id) : null;
  }

  function logout(authorization) {
    const match = /^Bearer (\S+)$/.exec(authorization ?? '');
    if (match) db.prepare('DELETE FROM app_sessions WHERE token_hash = ?').run(tokenHash(match[1]));
  }

  async function ensureIdentity(customer) {
    if (customer.nexus_id) return customer;
    const created = await authCore.createIdentity(`sandbox-${customer.id}`);
    if (created.status !== 201) throw new BankError(502, 'AUTH_CORE', `NEXUS ID не создан (HTTP ${created.status})`);
    db.prepare('UPDATE customers SET nexus_id = ? WHERE id = ?').run(created.json.nexusId, customer.id);
    recordEvent(db, { type: 'NEXUS_ID_CREATED', source: 'AUTH_CORE', customerId: customer.id, detail: { nexusId: created.json.nexusId } });
    return byId(customer.id);
  }

  /** BOOTSTRAP token for the customer's phone. A phone enrolling again gets a replacement token. */
  async function bootstrapToken(customer) {
    customer = await ensureIdentity(customer);
    let session = await authCore.bootstrapToken({ nexusId: customer.nexus_id });
    if (session.status === 409 && ['ACTIVE_CREDENTIAL_EXISTS', 'REPLACEMENT_REQUIRED'].includes(session.json?.code)) {
      const settings = JSON.parse(customer.settings);
      settings.replacementReference ??= `sandbox-reenrolment-${randomBytes(4).toString('hex')}`;
      db.prepare('UPDATE customers SET settings = ? WHERE id = ?').run(JSON.stringify(settings), customer.id);
      session = await authCore.bootstrapToken({ nexusId: customer.nexus_id, replacement: { method: 'OTHER', reference: settings.replacementReference } });
      if (session.status === 202) {
        recordEvent(db, { type: 'DEVICE_REPLACEMENT_HELD', source: 'AUTH_CORE', customerId: customer.id, detail: { replacementId: session.json.replacementId, notBefore: session.json.notBefore } });
        throw new BankError(409, 'REPLACEMENT_HELD', `Замена телефона ожидает подтверждения до ${session.json.notBefore}: подтвердите её на прежнем телефоне или повторите позже.`);
      }
      delete settings.replacementReference;
      db.prepare('UPDATE customers SET settings = ? WHERE id = ?').run(JSON.stringify(settings), customer.id);
    }
    if (session.status !== 201) throw new BankError(502, 'AUTH_CORE', `BOOTSTRAP-токен не выдан (HTTP ${session.status})`);
    recordEvent(db, { type: 'BOOTSTRAP_TOKEN_ISSUED', source: 'BANK', customerId: customer.id, detail: { nexusId: customer.nexus_id } });
    return { token: session.json.accessToken, nexusId: customer.nexus_id };
  }

  /** The app reports its new credential; the bank accepts it only if Auth Core lists it as ACTIVE for this NEXUS ID. */
  async function completeEnrolment(customer, credentialId) {
    if (!customer.nexus_id) throw new BankError(409, 'NO_IDENTITY', 'Сначала получите BOOTSTRAP-токен');
    const devices = await authCore.devices(customer.nexus_id);
    if (devices.status !== 200) throw new BankError(502, 'AUTH_CORE', `Auth Core не ответил (HTTP ${devices.status})`);
    const list = Array.isArray(devices.json) ? devices.json : devices.json?.devices ?? devices.json?.credentials ?? [];
    const device = list.find((d) => d.credentialId === credentialId);
    if (!device || (device.status ?? device.state) !== 'ACTIVE') throw new BankError(409, 'CREDENTIAL_NOT_ACTIVE', 'Auth Core не подтверждает это устройство как активное');
    db.prepare('UPDATE customers SET credential_id = ? WHERE id = ?').run(credentialId, customer.id);
    recordEvent(db, { type: 'DEVICE_ENROLLED', source: 'AUTH_CORE', customerId: customer.id, detail: { credentialId, platform: device.platform ?? null, securityLevel: device.securityLevel ?? null, attestation: device.attestationStatus ?? null } });
    return publicCustomer(byId(customer.id));
  }

  return { byId, login, fromToken, logout, ensureIdentity, bootstrapToken, completeEnrolment };
}

export function publicCustomer(c) {
  return { id: c.id, login: c.login, displayName: c.display_name, nexusId: c.nexus_id, credentialId: c.credential_id, deviceEnrolled: Boolean(c.credential_id), settings: JSON.parse(c.settings) };
}
