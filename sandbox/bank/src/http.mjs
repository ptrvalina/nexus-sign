import { BankError } from './payments.mjs';

export async function readBody(req, limit = 32_768) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new BankError(413, 'BODY_TOO_LARGE', 'Body too large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if ((req.headers['content-type'] ?? '').includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  try { return raw ? JSON.parse(raw) : {}; } catch { throw new BankError(400, 'INVALID_JSON', 'Body is not JSON'); }
}

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

export function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
  res.end(JSON.stringify(body));
}

export function sendHtml(res, status, html, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    ...SECURITY_HEADERS,
    ...extraHeaders,
  });
  res.end(html);
}

export function errorStatus(error) {
  return error instanceof BankError ? error.status : 500;
}

export function errorBody(error) {
  return error instanceof BankError ? { code: error.code, error: error.message } : { code: 'INTERNAL', error: 'Internal error' };
}

/** Structured one-line JSON log. */
export function log(level, message, fields = {}) {
  process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), level, service: 'sandbox-bank', message, ...fields })}\n`);
}

export const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
