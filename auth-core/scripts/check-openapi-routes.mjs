// Fails when a route registered in src/routes or src/app.ts is missing from
// openapi.yaml, or when openapi.yaml documents a path that is not implemented;
// the same for the console routes of src/routes/admin.ts and admin-openapi.yaml.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = (file) => readFileSync(join(root, file), 'utf8');

const routeFiles = ['routes/nexusV1.ts', 'routes/mobileV1.ts', 'routes/recovery.ts', 'routes/oauth.ts'];
const implemented = new Set([
  ...routeFiles.flatMap((file) => [...read(`src/${file}`).matchAll(/router\.(get|post|put|patch|delete)\('([^']+)'/g)]
    .map((m) => `${m[1].toUpperCase()} ${m[2].replace(/:([A-Za-z]+)/g, '{$1}')}`)),
  ...[...read('src/app.ts').matchAll(/app\.get\('([^']+)'/g)].map((m) => `GET ${m[1]}`),
]);

/** METHOD /path pairs documented in an OpenAPI file. */
function documentedRoutes(file) {
  const routes = new Set();
  let currentPath = null;
  for (const line of read(file).split('\n')) {
    const path = /^ {2}(\/[^:]+):\s*$/.exec(line);
    if (path) { currentPath = path[1]; continue; }
    const method = /^ {4}(get|post|put|patch|delete):/.exec(line);
    if (method && currentPath) routes.add(`${method[1].toUpperCase()} ${currentPath}`);
    if (/^[a-z]/.test(line)) currentPath = null;
  }
  return routes;
}

/** The console routes of admin.ts, including those registered in a loop over [path, ...] pairs (finding A2-12). */
function adminRoutes() {
  const text = read('src/routes/admin.ts');
  const routes = new Set([...text.matchAll(/router\.(get|post|put|patch|delete)\('([^']+)'/g)]
    .map((m) => `${m[1].toUpperCase()} ${m[2].replace(/:([A-Za-z]+)/g, '{$1}')}`));
  for (const loop of text.matchAll(/for \(const \[path, \w+\] of \[([^\n]*?)\] as const\) \{\s*router\.(get|post|put|patch|delete)\(`([^`]+)`/g)) {
    for (const [, name] of loop[1].matchAll(/\['([a-z-]+)', '[A-Z_]+'\]/g)) {
      routes.add(`${loop[2].toUpperCase()} ${loop[3].replace('${path}', name).replace(/:([A-Za-z]+)/g, '{$1}')}`);
    }
  }
  return routes;
}

let failed = false;
function compare(name, implemented, documented) {
  const undocumented = [...implemented].filter((route) => !documented.has(route));
  const unimplemented = [...documented].filter((route) => !implemented.has(route));
  for (const route of undocumented) console.error(`error: ${route} is not documented in ${name}`);
  for (const route of unimplemented) console.error(`error: ${route} is documented in ${name} but not implemented`);
  if (undocumented.length || unimplemented.length) failed = true;
  else console.log(`ok: ${implemented.size} routes match ${name}`);
}
compare('openapi.yaml', implemented, documentedRoutes('openapi.yaml'));
compare('admin-openapi.yaml', adminRoutes(), documentedRoutes('admin-openapi.yaml'));
if (failed) process.exit(1);
