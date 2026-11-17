// The bank backend's client for the Auth Core calls the execution boundary
// needs. Every answer is data to check, never a decision: the evidence goes
// through bankExecutionDecision, the commit request is only a precondition.
// Network errors, non-2xx answers and timeouts throw (the boundary holds the
// payment).

export class TrustUnavailableError extends Error {}

/** Wraps every function of `client` with a timeout. */
export function withTimeouts(client, timeoutMs) {
  const wrapped = {};
  for (const [name, fn] of Object.entries(client)) {
    wrapped[name] = typeof fn !== 'function' ? fn : (...args) => {
      let timer;
      return Promise.race([
        Promise.resolve().then(() => fn(...args)),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new TrustUnavailableError(`Auth Core ${name} timed out after ${timeoutMs} ms`)), timeoutMs); }),
      ]).finally(() => clearTimeout(timer));
    };
  }
  return wrapped;
}

/**
 * @param baseUrl      Auth Core base URL
 * @param accessToken  async () => the bank's OAuth access token
 * @param timeoutMs    per request
 */
export function createAuthCoreClient({ baseUrl, accessToken, timeoutMs = 10_000, fetchImpl = fetch }) {
  const base = baseUrl.replace(/\/$/, '');
  async function request(method, path, body) {
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, {
        method,
        headers: { Authorization: `Bearer ${await accessToken()}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new TrustUnavailableError(`Auth Core unavailable (${method} ${path}): ${error.message}`);
    }
    const text = await response.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: response.status, json, text };
  }
  const ok = (r, what) => {
    if (r.status !== 200 || !r.json) throw new TrustUnavailableError(`Auth Core ${what}: HTTP ${r.status}`);
    return r.json;
  };
  return withTimeouts({
    async commitRequest(authorizationId, bankTransactionReference) {
      return request('POST', `/v1/authorizations/${authorizationId}/bank-commit-request`, { bankTransactionReference });
    },
    async commitResult(authorizationId, state, error) {
      return request('POST', `/v1/authorizations/${authorizationId}/bank-commit-result`, { state, ...(error ? { error } : {}) });
    },
    async evidence(authorizationId) {
      return ok(await request('GET', `/v1/authorizations/${authorizationId}/evidence`), 'evidence');
    },
    /** The whole chain of a customer (all pages). */
    async chain(nexusId) {
      const records = [];
      let first = null;
      for (let after = 0; ; ) {
        const page = ok(await request('GET', `/v1/nexus-identities/${nexusId}/evidence?after=${after}&limit=1000`), 'chain');
        first ??= page;
        records.push(...(page.records ?? []));
        if (!page.records || page.records.length < 1000) break;
        after = page.records.at(-1).chainSequence;
      }
      return { ...first, records };
    },
  }, timeoutMs * 2);
}
