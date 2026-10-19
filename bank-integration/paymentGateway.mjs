// The payment gateway: the only component that talks to the payment
// provider. It runs in its own process with its own database role, which can
// do nothing but call bank_submit / bank_resubmit / bank_operation_for_lookup
// (schema.mjs). Its authority to send a payment comes from the bank's
// database, not from the caller: a payment is sent only if the execution
// boundary moved it to APPROVED for that attempt, and the order sent is the
// one stored with the payment and bound by hash at approval. Callers are
// authenticated with mutual TLS (allow-listed client certificate names).
import { createServer } from 'node:https';
import { orderFromSubmission, orderHash } from './trustStore.mjs';

export class GatewayRefusedError extends Error {}
export class GatewayUnreachableError extends Error {}

const OUTCOMES = new Set(['succeeded', 'failed', 'pending']);

/**
 * @param pool      pg Pool with the gateway's role
 * @param provider  { submit(order) -> { status, providerReference }, lookup(operationId) -> { status } }
 *                  status: succeeded | failed | pending | not_found (lookup); anything else is unknown
 */
export function createPaymentGateway({ pool, provider }) {
  async function send(fn, paymentId, attemptId) {
    let row;
    try {
      row = (await pool.query(`SELECT * FROM ${fn}($1, $2)`, [paymentId, attemptId])).rows[0];
    } catch (error) {
      throw new GatewayRefusedError(`not sent: ${error.message}`);
    }
    if (!row) throw new GatewayRefusedError('not sent: no such payment');
    const order = orderFromSubmission(paymentId, row.operation_id, row.payment_order);
    if (orderHash(order) !== row.order_hash) {
      // Recorded as SUBMITTED, but the stored order is not the approved one: not sent.
      return { outcome: 'review', reason: 'the stored order does not match the approved order hash; nothing was sent' };
    }
    let answer;
    try {
      answer = await provider.submit(order);
    } catch (error) {
      return { outcome: 'unknown', reason: `provider: ${error.message}` };
    }
    const status = String(answer?.status ?? '').toLowerCase();
    return OUTCOMES.has(status)
      ? { outcome: status, providerReference: answer.providerReference ?? null }
      : { outcome: 'unknown', reason: `provider answered ${JSON.stringify(answer?.status ?? null)}` };
  }
  return {
    submit: (paymentId, attemptId) => send('bank_submit', paymentId, attemptId),
    resubmit: (paymentId, attemptId) => send('bank_resubmit', paymentId, attemptId),
    async lookup(paymentId) {
      const operationId = (await pool.query(`SELECT bank_operation_for_lookup($1) AS id`, [paymentId])).rows[0]?.id;
      if (!operationId) return { status: 'not_submitted' };
      try {
        const answer = await provider.lookup(operationId);
        const status = String(answer?.status ?? '').toLowerCase();
        return ['succeeded', 'failed', 'pending', 'not_found'].includes(status) ? { status, providerReference: answer.providerReference ?? null } : { status: 'unknown' };
      } catch (error) {
        return { status: 'unknown', reason: error.message };
      }
    },
  };
}

/**
 * HTTPS server for a gateway in its own process. Mutual TLS: only clients
 * with a certificate from `ca` whose subject CN is in `allowedClients`.
 */
export function createGatewayServer({ gateway, tls, allowedClients }) {
  const allowed = new Set(allowedClients);
  const send = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  return createServer({ key: tls.key, cert: tls.cert, ca: tls.ca, requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    const peer = req.socket.getPeerCertificate?.();
    if (!req.client.authorized || !peer?.subject?.CN || !allowed.has(peer.subject.CN)) return send(res, 403, { error: 'client not allowed' });
    try {
      const url = new URL(req.url, 'https://gateway');
      if (req.method === 'POST' && (url.pathname === '/v1/submit' || url.pathname === '/v1/resubmit')) {
        let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 4096) return send(res, 413, { error: 'too large' }); }
        const { paymentId, attemptId } = JSON.parse(raw || '{}');
        const result = await (url.pathname === '/v1/submit' ? gateway.submit : gateway.resubmit)(String(paymentId), String(attemptId));
        return send(res, 200, result);
      }
      const lookup = /^\/v1\/payments\/([0-9a-f-]{36})\/lookup$/.exec(url.pathname);
      if (req.method === 'GET' && lookup) return send(res, 200, await gateway.lookup(lookup[1]));
      return send(res, 404, { error: 'not found' });
    } catch (error) {
      if (error instanceof GatewayRefusedError) return send(res, 409, { error: error.message, refused: true });
      return send(res, 500, { error: error.message });
    }
  });
}

/** The execution boundary's client of a gateway in another process (mutual TLS). */
export function createGatewayClient({ url, tls, timeoutMs = 10_000 }) {
  const base = new URL(url);
  const call = (method, path, body) => new Promise((resolve, reject) => {
    import('node:https').then(({ request }) => {
      const payload = body ? JSON.stringify(body) : undefined;
      const req = request({
        hostname: base.hostname, port: base.port, path, method, key: tls.key, cert: tls.cert, ca: tls.ca, servername: tls.servername ?? base.hostname,
        headers: payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {},
        timeout: timeoutMs,
      }, (res) => {
        let text = ''; res.on('data', (d) => { text += d; });
        res.on('end', () => {
          let json = null; try { json = JSON.parse(text); } catch { json = null; }
          if (res.statusCode === 409 && json?.refused) reject(new GatewayRefusedError(json.error));
          else if (res.statusCode !== 200) reject(new GatewayUnreachableError(`gateway HTTP ${res.statusCode}: ${json?.error ?? text}`));
          else resolve(json);
        });
        res.on('error', (e) => reject(new GatewayUnreachableError(e.message)));
      });
      req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs} ms`)));
      req.on('error', (e) => reject(new GatewayUnreachableError(`gateway: ${e.message}`)));
      if (payload) req.write(payload);
      req.end();
    }, reject);
  });
  return {
    submit: (paymentId, attemptId) => call('POST', '/v1/submit', { paymentId, attemptId }),
    resubmit: (paymentId, attemptId) => call('POST', '/v1/resubmit', { paymentId, attemptId }),
    lookup: (paymentId) => call('GET', `/v1/payments/${paymentId}/lookup`),
  };
}

/** A provider reached over HTTP: POST /payments, GET /payments/{operationId}. */
export function createHttpProvider({ url, timeoutMs = 10_000 }) {
  const base = url.replace(/\/$/, '');
  return {
    async submit(order) {
      const r = await fetch(`${base}/payments`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(order), signal: AbortSignal.timeout(timeoutMs) });
      if (r.status >= 500) throw new Error(`provider HTTP ${r.status}`);
      return r.json();
    },
    async lookup(operationId) {
      const r = await fetch(`${base}/payments/${encodeURIComponent(operationId)}`, { signal: AbortSignal.timeout(timeoutMs) });
      if (r.status === 404) return { status: 'not_found' };
      if (r.status !== 200) throw new Error(`provider HTTP ${r.status}`);
      return r.json();
    },
  };
}
