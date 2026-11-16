import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { exportAuditEvents, toCef, toJsonLine } from '../services/auditExport';

/**
 * Writes audit events after a cursor to stdout for a SIEM collector, one per
 * line, and remembers where it stopped (src/services/auditExport.ts).
 *
 *   AUDIT_EXPORT_DATABASE_URL=postgres://nexus_audit_reader@... \
 *     node dist/cli/exportAudit.js --format jsonl|cef --cursor-file /var/lib/nexus/audit.cursor \
 *       [--limit 1000] [--lag-seconds 60] [--client <clientId>]
 *
 * With --cursor-file the cursor is read before and written (atomically,
 * after the events were written to stdout) after each run, so a collector
 * that runs it every minute gets every event once. Without it, --after
 * <cursor> starts after a given position and the next cursor goes to stderr.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const value = (flag: string): string | undefined => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
  const url = process.env.AUDIT_EXPORT_DATABASE_URL ?? process.env.DATABASE_URL;
  if (!url) throw new Error('set AUDIT_EXPORT_DATABASE_URL (a role with SELECT on audit_logs, for example nexus_audit_reader)');
  const format = value('--format') ?? 'jsonl';
  if (format !== 'jsonl' && format !== 'cef') throw new Error('--format is jsonl or cef');
  const cursorFile = value('--cursor-file');
  let after = value('--after');
  if (cursorFile) { try { after = readFileSync(cursorFile, 'utf8').trim() || undefined; } catch { after = undefined; } }
  const version = (() => { try { return JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8')).version as string; } catch { return ''; } })();

  const db = new Client({ connectionString: url });
  await db.connect();
  try {
    const { events, next } = await exportAuditEvents(db, {
      after, limit: Number(value('--limit') ?? 1000), lagSeconds: Number(value('--lag-seconds') ?? 60), clientId: value('--client'),
    });
    const product = { vendor: 'NEXIS', name: 'NEXUS-SIGN', version };
    const out = events.map((e) => (format === 'cef' ? toCef(e, product) : toJsonLine(e, product))).join('\n');
    if (out) await new Promise<void>((resolve, reject) => process.stdout.write(`${out}\n`, (err) => (err ? reject(err) : resolve())));
    if (cursorFile && next) { writeFileSync(`${cursorFile}.tmp`, `${next}\n`); renameSync(`${cursorFile}.tmp`, cursorFile); }
    if (!cursorFile && next) process.stderr.write(`next cursor: ${next}\n`);
  } finally {
    await db.end();
  }
}

main().catch((error: unknown) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
