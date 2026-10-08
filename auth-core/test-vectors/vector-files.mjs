// The shared protocol vectors: written here, in auth-core/test-vectors, and
// read from here by Auth Core, the Android SDK (Gradle test resources) and the
// sandbox. SwiftPM only bundles resources inside the package, so the iOS SDK
// keeps the one copy, which check-vector-copies.mjs compares byte for byte.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const here = dirname(new URL(import.meta.url).pathname);
export const REPOSITORY = join(here, '..', '..');
export const SHARED_VECTORS = ['signed-payload-v1.json', 'device-protocols-v1.json', 'secure-push-v1.json', 'recovery-v2.json'];
export const IOS_RESOURCES = join(REPOSITORY, 'ios-sdk', 'Tests', 'NEXUSSignTests', 'Resources');

/** Writes a vector file and its iOS copy. */
export function writeVectors(name, text) {
  for (const target of [join(here, name), join(IOS_RESOURCES, name)]) {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
  }
  console.log(`wrote ${name} (and the iOS copy)`);
}
