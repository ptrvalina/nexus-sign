// Auth Core webhooks reaching the bank's backend. A webhook is only a reason
// to look: the signature proves it came from whoever holds the webhook secret
// (Auth Core, compromised or not), so the handler never executes anything
// itself; it hands the payment to the execution boundary, which decides. A
// redelivered or forged event therefore changes nothing.
import { createHmac, timingSafeEqual } from 'node:crypto';

const TRIGGERS = new Set(['authorization.verified', 'authorization.bank_transaction.commit_requested']);

/**
 * True when one `v1=` entry of the signature header is the HMAC of
 * `<timestamp>.<raw body>` under one of `secrets`. After a rotation of the
 * webhook secret Auth Core sends one entry per secret, the previous first
 * (finding A2-08), so a receiver holding either secret accepts the request.
 */
export function webhookSignatureMatches(header, timestamp, rawBody, secrets) {
  const entries = String(header ?? '').split(',').map((e) => e.trim()).filter((e) => e.startsWith('v1=')).slice(0, 4);
  let ok = false;
  for (const secret of secrets) {
    const expected = Buffer.from(`v1=${createHmac('sha256', secret).update(`${timestamp}.${rawBody}`, 'utf8').digest('hex')}`);
    for (const entry of entries) {
      const given = Buffer.from(entry);
      if (given.length === expected.length && timingSafeEqual(given, expected)) ok = true;
    }
  }
  return ok;
}

/** `secret` is the webhook secret, or a list of them while the bank switches to a new one. */
export function createAuthCoreWebhookHandler({ secret, store, boundary, toleranceSeconds = 300, now = () => Date.now() }) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  return async function handle({ headers, rawBody }) {
    const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
    const timestamp = h['x-nexus-sign-timestamp'];
    if (!timestamp || !webhookSignatureMatches(h['x-nexus-sign-signature'], timestamp, rawBody, secrets)) return { status: 401 };
    if (Math.abs(now() / 1000 - Number(timestamp)) > toleranceSeconds) return { status: 401 };
    let event;
    try { event = JSON.parse(rawBody); } catch { return { status: 400 }; }
    if (!TRIGGERS.has(event.eventType) || typeof event.authorizationId !== 'string') return { status: 204 };
    const payment = await store.paymentForAuthorization(event.authorizationId);
    if (!payment) return { status: 204 };
    return { status: 202, result: await boundary.execute(payment.paymentId) };
  };
}
