// The payment gateway: the only component that talks to the payment
// provider. It runs in its own process with its own database role, which can
// only call bank.submit_basis, bank.submit, bank.resubmit, bank.gateway_refuse,
// bank.report and bank.operation_for_lookup (schema.mjs). Its authority to
// send a payment comes from the bank's database, not from the caller: a
// payment is sent only if it is APPROVED for that attempt, the order still has
// the hash bound at approval, and the evidence stored with the approval passes
// the bank's decision again here (pinned evidence keys, the bank's signed
// statements, the payment's terms). A holder of the boundary's role alone
// therefore cannot get a payment sent without a valid customer confirmation.
// The gateway records the provider's answers itself. Callers are
// authenticated with mutual TLS (allow-listed client certificate names).
import { createServer } from 'node:https';
import { bankExecutionDecision } from '../auth-core/scripts/lib/bankTrust.mjs';

export class GatewayRefusedError extends Error {}
export class GatewayUnreachableError extends Error {}

const OUTCOMES = new Set(['succeeded', 'failed', 'pending']);

/**
 * @param pool           pg Pool with the gateway's role
 * @param provider       { submit(order) -> { status, providerReference }, lookup(operationId) -> { status } }
 *                       status: succeeded | failed | pending | not_found (lookup); anything else is unknown
 * @param evidenceKeys   evidence public keys the bank pinned (PEM list), required
 * @param bankTrustKeys  the bank's statement-signing public keys (PEM list), required
 */
export function createPaymentGateway({ pool, provider, evidenceKeys, bankTrustKeys }) {
  if (!Array.isArray(evidenceKeys) || evidenceKeys.length === 0 || !Array.isArray(bankTrustKeys) || bankTrustKeys.length === 0) {
    throw new Error('payment gateway: evidenceKeys and bankTrustKeys are required');
  }
  const pinned = Object.freeze([...evidenceKeys]);
  const trustKeys = Object.freeze([...bankTrustKeys]);

  const report = async (paymentId, attemptId, outcome, providerReference = null, reason = null) => {
    try {
      return (await pool.query(`SELECT bank.report($1, $2, $3, $4, $5) AS ok`, [paymentId, attemptId, outcome, providerReference, reason])).rows[0].ok;
    } catch {
      return false; // left SUBMITTED: reconciliation asks the provider
    }
  };

  /** Checks the approval in one transaction with the move to SUBMITTED; returns the order, or a refusal recorded as REVIEW. */
  async function take(fn, paymentId, attemptId) {
    const client = await pool.connect().catch((error) => { throw new GatewayRefusedError(`not sent: ${error.message}`); });
    try {
      await client.query('BEGIN');
      let basis;
      try {
        basis = (await client.query(`SELECT * FROM bank.submit_basis($1, $2)`, [paymentId, attemptId])).rows[0];
      } catch (error) {
        throw new GatewayRefusedError(`not sent: ${error.message}`);
      }
      if ((fn === 'bank.submit') !== (basis.state === 'APPROVED')) throw new GatewayRefusedError(`not sent: the payment is ${basis.state}`);
      let refusal = null;
      if (!basis.order_matches) refusal = 'the stored order does not match the approved order hash; nothing was sent';
      else {
        const decision = bankExecutionDecision({ evidence: basis.evidence, evidenceKeys: pinned, bankTrustKeys: trustKeys, registry: basis.registry, expected: basis.expected });
        if (!decision.allowed) refusal = `the gateway's check of the approval failed; nothing was sent: ${decision.problems.join('; ')}`;
      }
      if (refusal) {
        await client.query(`SELECT bank.gateway_refuse($1, $2, $3)`, [paymentId, attemptId, refusal]);
        await client.query('COMMIT');
        return { refused: refusal };
      }
      let row;
      try {
        row = (await client.query(`SELECT * FROM ${fn}($1, $2)`, [paymentId, attemptId])).rows[0];
      } catch (error) {
        throw new GatewayRefusedError(`not sent: ${error.message}`);
      }
      await client.query('COMMIT');
      return { order: row.payment_order };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function send(fn, paymentId, attemptId) {
    const taken = await take(fn, paymentId, attemptId);
    if (taken.refused) return { outcome: 'review', reason: taken.refused, recorded: true };
    let answer;
    try {
      answer = await provider.submit(taken.order);
    } catch (error) {
      const reason = `provider: ${error.message}`;
      return { outcome: 'unknown', reason, recorded: await report(paymentId, attemptId, 'unknown', null, reason) };
    }
    const status = String(answer?.status ?? '').toLowerCase();
    if (!OUTCOMES.has(status)) {
      const reason = `provider answered ${JSON.stringify(answer?.status ?? null)}`;
      return { outcome: 'unknown', reason, recorded: await report(paymentId, attemptId, 'unknown', null, reason) };
    }
    const providerReference = answer.providerReference ?? null;
    return { outcome: status, providerReference, recorded: await report(paymentId, attemptId, status, providerReference) };
  }

  async function lookup(paymentId) {
    const operationId = (await pool.query(`SELECT bank.operation_for_lookup($1) AS id`, [paymentId])).rows[0]?.id;
    if (!operationId) return { status: 'not_submitted' };
    try {
      const answer = await provider.lookup(operationId);
      const status = String(answer?.status ?? '').toLowerCase();
      return ['succeeded', 'failed', 'pending', 'not_found'].includes(status) ? { status, providerReference: answer.providerReference ?? null } : { status: 'unknown' };
    } catch (error) {
      return { status: 'unknown', reason: error.message };
    }
  }

  return {
    submit: (paymentId, attemptId) => send('bank.submit', paymentId, attemptId),
    resubmit: (paymentId, attemptId) => send('bank.resubmit', paymentId, attemptId),
    /** Read-only lookup (audits). */
    lookup,
    /**
     * Lookup for a reconciling attempt: a definite answer is recorded for that
     * attempt; `not_found` is returned for the boundary to decide (resubmit or review).
     */
    async reconcile(paymentId, attemptId) {
      const found = await lookup(paymentId);
      if (OUTCOMES.has(found.status)) return { ...found, recorded: await report(paymentId, attemptId, found.status, found.providerReference) };
      if (found.status === 'not_found') return found;
      const reason = found.reason ? `lookup failed: ${found.reason}` : `lookup answered ${JSON.stringify(found.status)}`;
      return { status: 'unknown', reason, recorded: await report(paymentId, attemptId, 'unknown', null, reason) };
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
      const action = { '/v1/submit': gateway.submit, '/v1/resubmit': gateway.resubmit, '/v1/reconcile': gateway.reconcile }[url.pathname];
      if (req.method === 'POST' && action) {
        let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 4096) return send(res, 413, { error: 'too large' }); }
        const { paymentId, attemptId } = JSON.parse(raw || '{}');
        return send(res, 200, await action(String(paymentId), String(attemptId)));
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
    reconcile: (paymentId, attemptId) => call('POST', '/v1/reconcile', { paymentId, attemptId }),
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
