// The console's customer screen (public/admin/customer.js) in Chromium
// against a stubbed admin API: payments, mandate detail with debits, events
// and sealed records, devices, device requests and security events render;
// every value is escaped; the buttons offered follow the state and the role.
// The real API behind these routes is tested in
// test/integration/bank-console.test.mjs. Needs Playwright (PLAYWRIGHT_MODULE).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
let playwright = null;
try { playwright = require(process.env.PLAYWRIGHT_MODULE ?? 'playwright'); } catch { playwright = null; }
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'public', 'admin');

const nexusId = '123456789', mandateId = '5b0f3c9a-6d1e-4b7a-9c2f-0e8d7a6b5c4d';
const mandate = { mandateId, nexusId, credentialId: '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b', mandateReference: 'M-1', payee: { name: '<b>Energy</b> Co', iban: 'PL61109010140000071219812874' },
  currency: 'EUR', perPaymentLimitMinor: '15000', totalLimitMinor: null, frequency: 'MONTHLY', validFrom: '2026-11-01T00:00:00Z', validUntil: '2027-11-01T00:00:00Z',
  termsHash: 'ab'.repeat(32), state: 'ACTIVE', stateReason: 'SIGNED', signedAt: '2026-11-02T00:00:00Z', usedTotalMinor: '9000' };
const api = {
  '/admin/api/me': { username: 'anna', role: 'operator', clientId: 'bank-1' },
  [`/admin/api/identities/${nexusId}`]: { nexusId, bankCustomerRef: 'c1', status: 'ACTIVE', createdAt: '2026-11-01T00:00:00Z', lastUsedAt: null },
  [`/admin/api/identities/${nexusId}/mandates`]: { mandates: [mandate] },
  [`/admin/api/identities/${nexusId}/authorizations`]: { authorizations: [{ authorizationId: 'a1', transactionReference: 'TX-1', operationType: 'TRANSFER', amountMinor: '125000', currency: 'PLN', beneficiary: { iban: 'PL61109010140000071219812874', name: '<img src=x onerror=alert(1)>' }, state: 'REJECTED', reason: 'DECLINED_BY_CUSTOMER', createdAt: '2026-11-03T00:00:00Z', decidedAt: '2026-11-03T00:01:00Z', credentialId: 'c', evidence: true }] },
  [`/admin/api/mandates/${mandateId}`]: { mandate, debits: [{ debitId: 'd', debitReference: 'R1', amountMinor: '9000', currency: 'EUR', periodStart: '2026-11-01', decision: 'ALLOWED', reason: null, createdAt: '2026-11-03T00:00:00Z' }],
    evidence: [{ chainSequence: 4, evidenceHash: 'cd'.repeat(32), sealedPayload: { event: 'SIGNED' }, createdAt: '2026-11-02T00:00:00Z' }],
    events: [{ at: '2026-11-02T00:00:00Z', event: 'SIGNED', from: 'PENDING_SIGNATURE', to: 'ACTIVE', reason: 'SIGNED', actor: 'credential:x' }] },
  [`/admin/api/identities/${nexusId}/devices`]: { nexusId, maxDevicesPerIdentity: 2,
    devices: [{ credentialId: '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b', platform: 'IOS', securityLevel: 'SECURE_ENCLAVE', attestationStatus: 'VERIFIED', state: 'ACTIVE', enrolledAt: '2026-11-01T00:00:00Z', lastUsedAt: null, revokedAt: null, enrolmentReason: 'ENROLMENT' }],
    requests: [{ requestId: 'r1', kind: 'ADDITION', method: 'OTHER', reference: 'tablet', state: 'PENDING', requestedAt: '2026-11-03T00:00:00Z', notBefore: '2026-11-04T00:00:00Z', expiresAt: '2026-11-05T00:00:00Z', decidedAt: null, usedByCredentialId: null }],
    securityEvents: [{ eventType: 'credential_created', at: '2026-11-01T00:00:00Z', actor: 'bank:bank-1', details: {} }] },
};

test('console customer screen renders from the API and escapes every value', { skip: playwright ? false : 'Playwright is not installed (set PLAYWRIGHT_MODULE)' }, async () => {
  const { chromium } = playwright;
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1280, height: 1800 } });
  const errors = []; page.on('pageerror', (e) => errors.push(e.message)); page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.route('http://console.test/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith('/admin/api/')) {
      const body = api[url.pathname] ?? (url.pathname.endsWith('/stats') ? {} : url.pathname.endsWith('/conversations') ? { conversations: [] } : []);
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    }
    const file = path.join(root, url.pathname.replace(/^\/admin\/?/, '') || 'index.html');
    return route.fulfill({ status: 200, body: fs.readFileSync(fs.existsSync(file) && fs.statSync(file).isFile() ? file : path.join(root, 'index.html')), contentType: file.endsWith('.js') ? 'text/javascript' : 'text/html' });
  });
  await page.goto('http://console.test/admin/');
  await page.waitForTimeout(800);
  await page.evaluate(() => { state.session = { username: 'anna', role: 'operator', clientId: 'bank-1' }; showApp(); });
  await page.fill('#identity-search-input', nexusId); await page.click('#identity-search-btn');
  await page.waitForSelector('#mandates-table table');
  await page.click('button[data-mandate]'); await page.waitForSelector('#mandate-debits table');
  const text = await page.textContent('#customer-section');
  const checks = { payeeEscaped: text.includes('<b>Energy</b> Co'), hold: await page.$('[data-mandate-action=hold]') !== null, noRelease: await page.$('[data-mandate-action=release]') === null,
    revoke: await page.$('button[data-revoke]') !== null, stop: await page.$('button[data-cancel]') !== null, limit: text.includes('Bank limit: 2'), debit: text.includes('90.00 EUR'), payment: text.includes('1250.00 PLN') && text.includes('DECLINED_BY_CUSTOMER'), noImg: (await page.$('#authorizations-table img')) === null };
  await browser.close();
  assert.deepEqual(errors, []);
  assert.deepEqual(Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k), []);
});
