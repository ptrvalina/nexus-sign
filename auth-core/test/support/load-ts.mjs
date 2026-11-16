// Loads project TypeScript modules for unit tests without a build step: each
// module is transpiled in memory with the project's TypeScript compiler and
// its relative imports are loaded the same way. `stubs` replaces modules that
// need infrastructure (database pool, Redis) with test doubles.
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ts = require('typescript');
export const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'src');

// Minimal configuration so src/config/env.ts validates in unit tests.
process.env.NODE_ENV ??= 'test';
process.env.DATABASE_URL ??= 'postgres://unit:unit@127.0.0.1:1/unit';
process.env.REDIS_URL ??= 'redis://127.0.0.1:1';

// `cache`: pass the same Map to several calls so that they share one module
// graph (one database pool, one configuration), e.g. to end the pool after a test.
export function loadTs(relativePath, { stubs = {}, cache = new Map() } = {}) {
  const load = (file) => {
    if (cache.has(file)) return cache.get(file).exports;
    const module = { exports: {} };
    cache.set(file, module);
    const { outputText } = ts.transpileModule(readFileSync(file, 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    });
    const localRequire = (specifier) => {
      if (specifier in stubs) return stubs[specifier];
      if (specifier.startsWith('.')) {
        const target = join(dirname(file), specifier);
        const candidate = [`${target}.ts`, join(target, 'index.ts')].find(existsSync);
        if (candidate) return load(candidate);
      }
      return require(specifier);
    };
    new Function('exports', 'require', 'module', '__filename', '__dirname', outputText)(module.exports, localRequire, module, file, dirname(file));
    return module.exports;
  };
  return load(join(SRC, relativePath));
}
