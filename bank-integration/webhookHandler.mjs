// Auth Core webhooks reaching the bank's backend. A webhook is only a reason
// to look: the signature proves it came from whoever holds the webhook secret
// (Auth Core, compromised or not), so the handler never executes anything
// itself; it hands the payment to the execution boundary, which decides. A
// redelivered or forged event therefore changes nothing.
import { createHmac, timingSafeEqual } from 'node:crypto';

const TRIGGERS = new Set(['authorization.verified', 'authorization.bank_transaction.commit_requested']);

export function createAuthCoreWebhookHandler({ secret, store, boundary, toleranceSeconds = 300, now = () => Date.now() }) {
  return async function handle({ headers, rawBody }) {
    const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
    const timestamp = h['x-nexus-sign-timestamp'];
    const given = h['x-nexus-sign-signature'] ?? '';
    const expected = `v1=${createHmac('sha256', secret).update(`${timestamp}.${rawBody}`, 'utf8').digest('hex')}`;
    if (!timestamp || given.length !== expected.length || !timingSafeEqual(Buffer.from(given), Buffer.from(expected))) return { status: 401 };
    if (Math.abs(now() / 1000 - Number(timestamp)) > toleranceSeconds) return { status: 401 };
    let event;
    try { event = JSON.parse(rawBody); } catch { return { status: 400 }; }
    if (!TRIGGERS.has(event.eventType) || typeof event.authorizationId !== 'string') return { status: 204 };
    const payment = await store.paymentForAuthorization(event.authorizationId);
    if (!payment) return { status: 204 };
    return { status: 202, result: await boundary.execute(payment.paymentId) };
  };
}
