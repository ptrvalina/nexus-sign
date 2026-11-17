import dns from 'node:dns/promises';
import net from 'node:net';
import { env } from '../config/env';

function isPrivateIpv4(ip: string): boolean {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  const [a,b] = octets;
  return a === 10 || a === 127 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || (a === 0) ||
    (a === 198 && (b === 18 || b === 19)) || (a === 192 && b === 0) ||
    (a === 198 && b === 51) || (a === 203 && b === 0) || a >= 224;
}

/** Expands an IPv6 address (any textual form, including an embedded
 * dotted IPv4 tail) to eight 16-bit groups. */
function ipv6Groups(ip: string): number[] | null {
  let text = ip.toLowerCase().split('%')[0];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted) {
    const o = dotted[1].split('.').map(Number);
    if (o.some((x) => x > 255)) return null;
    text = text.slice(0, -dotted[1].length) + `${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const [head, tail] = text.includes('::') ? text.split('::') : [text, null];
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const missing = 8 - left.length - right.length;
  if (tail === null ? left.length !== 8 : missing < 0) return null;
  const groups = [...left, ...Array(tail === null ? 0 : missing).fill('0'), ...right].map((g) => parseInt(g || '0', 16));
  return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : null;
}

export function isPrivateIpv6(ip: string): boolean {
  const g = ipv6Groups(ip);
  if (!g) return true; // unparseable: refuse
  const embeddedIpv4 = () => `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return isPrivateIpv4(embeddedIpv4()); // ::ffff:a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return isPrivateIpv4(embeddedIpv4()); // NAT64
  if (g.slice(0, 6).every((x) => x === 0)) return true; // ::, ::1 and IPv4-compatible
  // 6to4 (2002::/16) carries an IPv4 address in groups 1-2: judge that address.
  if (g[0] === 0x2002) return isPrivateIpv4(`${g[1] >> 8}.${g[1] & 255}.${g[2] >> 8}.${g[2] & 255}`);
  // Transition and special ranges a relay could route to an internal host:
  // Teredo 2001::/32, local-use NAT64 64:ff9b:1::/48, discard 100::/64,
  // benchmarking 2001:2::/48, ORCHIDv2 2001:20::/28.
  if (g[0] === 0x2001 && (g[1] === 0 || g[1] === 2 || (g[1] & 0xfff0) === 0x20)) return true;
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;
  if (g[0] === 0x100 && g.slice(1, 4).every((x) => x === 0)) return true;
  return (g[0] & 0xfe00) === 0xfc00 // fc00::/7 unique local
    || (g[0] & 0xffc0) === 0xfe80 // fe80::/10 link local
    || (g[0] & 0xffc0) === 0xfec0 // fec0::/10 site local
    || (g[0] & 0xff00) === 0xff00 // ff00::/8 multicast
    || (g[0] === 0x2001 && g[1] === 0x0db8); // 2001:db8::/32 documentation
}

export interface AllowedWebhookTarget {
  url: URL;
  /** The vetted IP address the delivery must connect to. Pinning it closes
   * the DNS-rebinding gap between this check and the connection. */
  address: string;
  family: 4 | 6;
}

/**
 * Validates a webhook destination and resolves the address to connect to.
 * Egress firewall rules remain mandatory in production; this check is defense
 * in depth.
 */
export async function assertWebhookUrlAllowed(raw: string): Promise<AllowedWebhookTarget> {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error('Webhook URL is invalid'); }
  if (url.username || url.password) throw new Error('Webhook URL must not contain credentials');
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Webhook URL protocol is not allowed');
  if (env.WEBHOOK_REQUIRE_HTTPS && url.protocol !== 'https:') throw new Error('Webhook URL must use HTTPS');

  const hostname = url.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!hostname) throw new Error('Webhook URL hostname is required');
  if (env.WEBHOOK_ALLOWED_HOSTS.length > 0 && !env.WEBHOOK_ALLOWED_HOSTS.includes(hostname)) {
    throw new Error('Webhook host is not allow-listed');
  }

  const literal = net.isIP(hostname);
  const candidates = literal
    ? [{ address: hostname, family: literal }]
    : await dns.lookup(hostname, { all: true, verbatim: true });
  if (candidates.length === 0) throw new Error('Webhook hostname has no DNS address');
  for (const candidate of candidates) {
    if ((candidate.family === 4 && isPrivateIpv4(candidate.address)) || (candidate.family === 6 && isPrivateIpv6(candidate.address))) {
      throw new Error('Webhook target resolves to a private or reserved address');
    }
  }
  const chosen = candidates[0];
  return { url, address: chosen.address, family: chosen.family === 6 ? 6 : 4 };
}
