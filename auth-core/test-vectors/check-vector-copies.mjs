// The iOS copies of the shared vectors are identical to auth-core/test-vectors,
// and no other copy exists in the repository (Android and the sandbox read the
// originals), so no suite can silently run stale vectors.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { IOS_RESOURCES, REPOSITORY, SHARED_VECTORS } from './vector-files.mjs';

const problems = [];
const here = join(REPOSITORY, 'auth-core', 'test-vectors');
for (const name of SHARED_VECTORS) {
  const original = readFileSync(join(here, name));
  const copy = join(IOS_RESOURCES, name);
  let bytes;
  try { bytes = readFileSync(copy); } catch { problems.push(`missing ${relative(REPOSITORY, copy)}`); continue; }
  if (!bytes.equals(original)) problems.push(`${relative(REPOSITORY, copy)} differs from auth-core/test-vectors/${name}; run npm run generate:vectors`);
}

const allowed = new Set([here, IOS_RESOURCES]);
const skip = new Set(['node_modules', 'dist', 'build', '.git', '.gradle', '.build', '.swiftpm']);
(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (skip.has(entry)) continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path);
    else if (SHARED_VECTORS.includes(entry) && !allowed.has(dir)) problems.push(`unexpected copy ${relative(REPOSITORY, path)}; read auth-core/test-vectors/${entry} instead`);
  }
})(REPOSITORY);

if (problems.length) {
  for (const p of problems) console.error(`error: ${p}`);
  process.exit(1);
}
console.log(`ok: ${SHARED_VECTORS.length} shared vector files, one iOS copy each, no other copies`);
