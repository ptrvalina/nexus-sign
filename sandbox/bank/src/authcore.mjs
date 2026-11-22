// The bank's server-to-server client for Auth Core: OAuth client credentials,
// then bank API calls. The result of a customer's confirmation is read here,
// from Auth Core, never taken from the phone.
export function createAuthCoreClient({ baseUrl, clientId, clientSecret, fetchImpl = fetch }) {
  let token = null;
  let expiresAt = 0;

  async function accessToken() {
    if (token && Date.now() < expiresAt - 60_000) return token;
    const response = await fetchImpl(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }),
    });
    const json = await response.json().catch(() => ({}));
    if (response.status !== 200 || !json.access_token) throw new AuthCoreError(`OAuth token refused (HTTP ${response.status})`, response.status, json);
    token = json.access_token;
    expiresAt = Date.now() + (json.expires_in ?? 3600) * 1000;
    return token;
  }

  async function call(method, path, body, headers = {}) {
    const response = await fetchImpl(`${baseUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${await accessToken()}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    return { status: response.status, json, text };
  }

  return {
    baseUrl,
    clientId,
    call,
    async health() {
      try {
        const response = await fetchImpl(`${baseUrl}/readyz`);
        return { ok: response.status === 200, status: response.status };
      } catch (error) {
        return { ok: false, error: error.message };
      }
    },
    createIdentity: (bankCustomerRef) => call('POST', '/v1/nexus-identities', { bankCustomerRef }),
    bootstrapToken: (body) => call('POST', '/v1/mobile/sessions', body),
    devices: (nexusId) => call('GET', `/v1/nexus-identities/${nexusId}/devices`),
    createAuthorization: (body, idempotencyKey) => call('POST', '/v1/authorizations', body, { 'Idempotency-Key': idempotencyKey }),
    authorization: (id) => call('GET', `/v1/authorizations/${id}`),
    evidence: (id) => call('GET', `/v1/authorizations/${id}/evidence`),
    chain: (nexusId) => call('GET', `/v1/nexus-identities/${nexusId}/evidence`),
    cancel: (id, reason) => call('POST', `/v1/authorizations/${id}/cancel`, { reason }),
    offlineChallenge: (id) => call('GET', `/v1/authorizations/${id}/offline-challenge`),
    offlineConfirmation: (id, code) => call('POST', `/v1/authorizations/${id}/offline-confirmation`, { code }),
    commitRequest: (id, bankTransactionReference) => call('POST', `/v1/authorizations/${id}/bank-commit-request`, { bankTransactionReference }),
    commitResult: (id, state, error) => call('POST', `/v1/authorizations/${id}/bank-commit-result`, { state, ...(error ? { error } : {}) }),
  };
}

export class AuthCoreError extends Error {
  constructor(message, status, body) { super(message); this.status = status; this.body = body; }
}
