// The two callers of Auth Core in tests: a bank backend (OAuth client
// credentials) and an enrolled mobile device (hardware keys simulated with
// node:crypto, request signing exactly as in the SDKs).
import { createHash, createHmac, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, randomUUID, sign } from 'node:crypto';

export const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function newKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey, publicKey, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
}

export const signDer = (key, bytes) => sign('sha256', bytes, { key: key.privateKey, dsaEncoding: 'der' }).toString('base64');

/** Device protocol v1 request signature headers. */
export function deviceHeaders(device, method, path, rawBody) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString('base64url');
  const input = ['NEXUS-SIGN/DEVICE-REQUEST/v1', method, path, timestamp, nonce, device.credentialId, sha256hex(Buffer.from(rawBody, 'utf8'))].join('\n');
  return {
    'X-NEXUS-Credential': device.credentialId,
    'X-NEXUS-Timestamp': timestamp,
    'X-NEXUS-Nonce': nonce,
    'X-NEXUS-Signature': signDer(device.authKey, Buffer.from(input, 'utf8')),
  };
}

export async function call(baseUrl, method, path, { token, device, body, headers = {}, rawBody } = {}) {
  const raw = rawBody ?? (body !== undefined ? JSON.stringify(body) : undefined);
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(raw !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(device ? deviceHeaders(device, method, path, raw ?? '') : {}),
      ...headers,
    },
    body: raw,
  });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: response.status, json, text, headers: response.headers };
}

export function offlineCode(device, canonical) {
  const shared = diffieHellman({ privateKey: device.offlineKey.privateKey, publicKey: createPublicKey(device.offlineServerPublicKeyPem) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from('NEXUS-SIGN/OFFLINE/v1'), Buffer.from(device.credentialId), 32));
  const tag = createHmac('sha256', key)
    .update(Buffer.concat([Buffer.from('NEXUS-SIGN/OFFLINE-CODE/v1'), Buffer.from([0]), createHash('sha256').update(canonical).digest()]))
    .digest();
  const offset = tag[31] & 0x0f;
  const bin = ((tag[offset] & 0x7f) << 24) | (tag[offset + 1] << 16) | (tag[offset + 2] << 8) | tag[offset + 3];
  return String(bin % 100000000).padStart(8, '0');
}

/** A bank backend with an access token. `headers` are added to every call
 * (the mTLS gateway's headers in the gateway tests). */
export async function bankSession(server, { clientId, secret }, { headers = {} } = {}) {
  const tokenResponse = await call(server.baseUrl, 'POST', '/oauth/token', {
    body: { grant_type: 'client_credentials', client_id: clientId, client_secret: secret }, headers,
  });
  if (tokenResponse.status !== 200) throw new Error(`token for ${clientId}: ${tokenResponse.status} ${tokenResponse.text}`);
  const token = tokenResponse.json.access_token;
  const bank = {
    clientId,
    token,
    call: (method, path, options = {}) => call(server.baseUrl, method, path, { token, ...options, headers: { ...headers, ...(options.headers ?? {}) } }),
    async createIdentity(ref = `customer-${randomUUID()}`) {
      const r = await bank.call('POST', '/v1/nexus-identities', { body: { bankCustomerRef: ref } });
      if (r.status !== 201) throw new Error(`identity: ${r.status} ${r.text}`);
      return { nexusId: r.json.nexusId, bankCustomerRef: ref };
    },
    async bootstrapToken(nexusId, extra = {}) {
      return bank.call('POST', '/v1/mobile/sessions', { body: { nexusId, purpose: 'BOOTSTRAP', ...extra } });
    },
    /** Enrols a simulated device for the identity; returns it. */
    async enrolDevice(nexusId, extra = {}) {
      const issued = await bank.bootstrapToken(nexusId, extra);
      if (issued.status !== 201) throw new Error(`bootstrap token: ${issued.status} ${issued.text}`);
      return enrolWithToken(server, nexusId, issued.json.accessToken);
    },
    async createAuthorization(device, overrides = {}) {
      const r = await bank.call('POST', '/v1/authorizations', {
        headers: { 'Idempotency-Key': randomUUID() },
        body: {
          nexusId: device.nexusId,
          credentialId: device.credentialId,
          transactionReference: `tx-${randomUUID()}`,
          operationType: 'TRANSFER',
          amountMinor: '125000',
          currency: 'PLN',
          beneficiary: { name: 'Anna Nowak', iban: 'PL61109010140000071219812874' },
          policyReference: 'default',
          policyVersion: '1',
          ...overrides,
        },
      });
      if (r.status !== 201) throw new Error(`authorization: ${r.status} ${r.text}`);
      return r.json;
    },
  };
  return bank;
}

/** Enrols a device with a BOOTSTRAP token (keys generated here). */
export async function enrolWithToken(server, nexusId, bootstrapToken, { extraBody = {} } = {}) {
  const signingKey = newKey();
  const authKey = newKey();
  const offlineKey = newKey();
  const r = await call(server.baseUrl, 'POST', '/v1/mobile/bootstrap', {
    token: bootstrapToken,
    body: {
      publicKeyPem: signingKey.publicKeyPem,
      authPublicKeyPem: authKey.publicKeyPem,
      offlinePublicKeyPem: offlineKey.publicKeyPem,
      platform: 'IOS',
      securityLevel: 'SECURE_ENCLAVE',
      deviceAttestation: { supported: false },
      ...extraBody,
    },
  });
  if (r.status !== 201) {
    const error = new Error(`bootstrap: ${r.status} ${r.text}`);
    error.response = r;
    throw error;
  }
  return {
    nexusId,
    credentialId: r.json.credentialId,
    signingKey,
    authKey,
    offlineKey,
    offlineServerPublicKeyPem: r.json.offlineServerPublicKeyPem,
    response: r.json,
  };
}

/** The device fetches the authorization (with its signed bytes) and signs. */
export async function deviceSignature(server, device, authorizationId) {
  const path = `/v1/mobile/authorizations/${authorizationId}`;
  const fetched = await call(server.baseUrl, 'GET', path, { device });
  if (fetched.status !== 200) throw new Error(`fetch authorization: ${fetched.status} ${fetched.text}`);
  const canonical = Buffer.from(fetched.json.canonicalPayloadBase64, 'base64');
  return { canonical, signature: signDer(device.signingKey, canonical), authorization: fetched.json };
}

export async function submitSignature(server, device, authorizationId, signature) {
  return call(server.baseUrl, 'POST', `/v1/mobile/authorizations/${authorizationId}/signature`, {
    device, body: { signature, signatureFormat: 'der' },
  });
}

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits), written independently of Auth Core. */
export function totp(base32Secret, offsetSteps = 0, nowMs = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = ''; for (const c of base32Secret) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const secret = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 30000) + offsetSteps));
  const mac = createHmac('sha1', secret).update(counter).digest();
  const o = mac[19] & 15;
  return String((mac.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** Logs an admin in; returns a caller carrying the session cookie. */
export async function adminSession(server, { username, password, totpSecret }, { code, headers = {} } = {}) {
  const totpCode = code ?? (totpSecret ? totp(totpSecret) : undefined);
  const login = await call(server.baseUrl, 'POST', '/admin/api/login', { body: { username, password, ...(totpCode ? { totp: totpCode } : {}) }, headers });
  if (login.status !== 200) return { login };
  const cookie = login.headers.get('set-cookie').split(';')[0];
  return { login, call: (method, path, options = {}) => call(server.baseUrl, method, path, { ...options, headers: { cookie, ...headers, ...(options.headers ?? {}) } }) };
}
