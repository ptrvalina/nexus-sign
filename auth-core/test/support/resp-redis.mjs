// Redis for service-level tests: the real `ioredis` when it is installed,
// otherwise a minimal RESP2 client with the same call shapes for the commands
// the services use (get, set, del, eval, lrange, hget, hsetnx, ping, quit).
// Both talk to a real Redis server, so Lua scripts, NX and expiries run with
// Redis semantics; nothing here imitates Redis behaviour.
import { createRequire } from 'node:module';
import { connect } from 'node:net';

const require = createRequire(import.meta.url);

function encode(args) {
  let out = `*${args.length}\r\n`;
  for (const a of args) { const s = Buffer.from(String(a)); out += `$${s.length}\r\n${s}\r\n`; }
  return out;
}

/** Parses one reply from `buf` at `i`; returns [value, next] or null if incomplete. */
function parse(buf, i = 0) {
  const end = buf.indexOf('\r\n', i);
  if (end < 0) return null;
  const type = String.fromCharCode(buf[i]);
  const line = buf.toString('utf8', i + 1, end);
  if (type === '+') return [line, end + 2];
  if (type === '-') return [new Error(line), end + 2];
  if (type === ':') return [Number(line), end + 2];
  if (type === '$') {
    const n = Number(line);
    if (n < 0) return [null, end + 2];
    if (buf.length < end + 2 + n + 2) return null;
    return [buf.toString('utf8', end + 2, end + 2 + n), end + 2 + n + 2];
  }
  if (type === '*') {
    const n = Number(line);
    if (n < 0) return [null, end + 2];
    const items = []; let at = end + 2;
    for (let k = 0; k < n; k += 1) { const r = parse(buf, at); if (!r) return null; items.push(r[0]); at = r[1]; }
    return [items, at];
  }
  throw new Error(`unexpected RESP type ${type}`);
}

class RespRedis {
  constructor(url) {
    const u = new URL(url ?? 'redis://127.0.0.1:6379');
    this.socket = connect(Number(u.port || 6379), u.hostname);
    this.pending = []; this.buf = Buffer.alloc(0);
    this.socket.on('data', (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      for (;;) {
        const r = parse(this.buf);
        if (!r) break;
        this.buf = this.buf.subarray(r[1]);
        const p = this.pending.shift();
        if (r[0] instanceof Error) p.reject(r[0]); else p.resolve(r[0]);
      }
    });
    this.socket.on('error', (e) => { for (const p of this.pending.splice(0)) p.reject(e); });
    const db = u.pathname.slice(1);
    if (db) this.call('SELECT', db);
  }
  on() { return this; }
  call(...args) { return new Promise((resolve, reject) => { this.pending.push({ resolve, reject }); this.socket.write(encode(args)); }); }
  get(k) { return this.call('GET', k); }
  set(...a) { return this.call('SET', ...a); }
  del(...k) { return this.call('DEL', ...k); }
  eval(...a) { return this.call('EVAL', ...a); }
  lrange(...a) { return this.call('LRANGE', ...a); }
  hget(...a) { return this.call('HGET', ...a); }
  hsetnx(...a) { return this.call('HSETNX', ...a); }
  ping() { return this.call('PING'); }
  async quit() { await this.call('QUIT').catch(() => {}); this.socket.end(); }
  disconnect() { this.socket.destroy(); }
}

export function redisModule() {
  try { return require('ioredis'); } catch { return RespRedis; }
}
