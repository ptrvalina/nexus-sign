// Fails when a route registered in src/routes or src/app.ts is missing from
// openapi.yaml, or when openapi.yaml documents a path that is not implemented.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../', import.meta.url).pathname;
const read = (file) => readFileSync(join(root, file), 'utf8');

const routeFiles = ['routes/nexusV1.ts', 'routes/mobileV1.ts', 'routes/recovery.ts', 'routes/oauth.ts'];
const implemented = new Set([
  ...routeFiles.flatMap((file) => [...read(`src/${file}`).matchAll(/router\.(get|post|put|patch|delete)\('([^']+)'/g)]
    .map((m) => `${m[1].toUpperCase()} ${m[2].replace(/:([A-Za-z]+)/g, '{$1}')}`)),
  ...[...read('src/app.ts').matchAll(/app\.get\('([^']+)'/g)].map((m) => `GET ${m[1]}`),
]);

const documented = new Set();
let currentPath = null;
for (const line of read('openapi.yaml').split('\n')) {
  const path = /^ {2}(\/[^:]+):\s*$/.exec(line);
  if (path) { currentPath = path[1]; continue; }
  const method = /^ {4}(get|post|put|patch|delete):/.exec(line);
  if (method && currentPath) documented.add(`${method[1].toUpperCase()} ${currentPath}`);
  if (/^[a-z]/.test(line)) currentPath = null;
}

const undocumented = [...implemented].filter((route) => !documented.has(route));
const unimplemented = [...documented].filter((route) => !implemented.has(route));
for (const route of undocumented) console.error(`error: ${route} is not documented in openapi.yaml`);
for (const route of unimplemented) console.error(`error: ${route} is documented in openapi.yaml but not implemented`);
if (undocumented.length || unimplemented.length) process.exit(1);
console.log(`ok: ${implemented.size} routes match openapi.yaml`);
