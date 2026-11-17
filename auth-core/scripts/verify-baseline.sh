#!/usr/bin/env bash
# Reproducible source baseline check. Run from auth-core/ in a clone
# of the authoritative repository. Records what it ran and stops at the first
# failure. Writes baseline-report.txt next to it; never modifies the lockfile.
#
#   bash scripts/verify-baseline.sh [--docker]
set -euo pipefail
cd "$(dirname "$0")/.."
REPORT=baseline-report.txt
: > "$REPORT"
log() { echo "$*" | tee -a "$REPORT"; }
step() { log ""; log "== $*"; }

step "Source"
log "commit: $(git rev-parse HEAD)"
log "describe: $(git describe --tags --always --dirty)"
log "remote: $(git config --get remote.origin.url || echo none)"
if [ -n "$(git status --porcelain)" ]; then log "FAIL: working tree is not clean"; exit 1; fi

step "Tools"
log "node $(node --version), npm $(npm --version)"
log "$(uname -srm)"

step "Lockfile"
if [ ! -f package-lock.json ]; then log "FAIL: package-lock.json is missing; do not generate one here, restore it from the repository"; exit 1; fi
log "lockfileVersion: $(node -p "require('./package-lock.json').lockfileVersion")"
log "sha256: $(sha256sum package-lock.json | cut -d' ' -f1)"
# The lockfile must describe exactly the manifest's dependencies.
node -e '
  const pkg = require("./package.json"); const lock = require("./package-lock.json");
  const root = lock.packages?.[""] ?? {};
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const a = JSON.stringify(pkg[field] ?? {}); const b = JSON.stringify(root[field] ?? {});
    if (a !== b) { console.error(`FAIL: ${field} in package.json and package-lock.json differ`); process.exit(1); }
  }
  if (lock.name !== pkg.name || lock.version !== pkg.version) { console.error("FAIL: name or version differs"); process.exit(1); }
  console.log("manifest and lockfile agree");' | tee -a "$REPORT"

step "Deterministic install"
cp package-lock.json /tmp/lock.before
npm ci --ignore-scripts --no-audit --no-fund 2>&1 | tail -3 | tee -a "$REPORT"
npm rebuild pkcs11js 2>&1 | tail -1 | tee -a "$REPORT"
cmp -s package-lock.json /tmp/lock.before || { log "FAIL: npm ci changed package-lock.json"; exit 1; }
npm ls --all >/dev/null 2>&1 && log "npm ls: dependency tree complete" || { log "FAIL: npm ls reports problems"; npm ls --all 2>&1 | tail -20 | tee -a "$REPORT"; exit 1; }

step "Audit and SBOM"
npm audit --omit=dev --audit-level=high 2>&1 | tail -5 | tee -a "$REPORT" || log "WARN: npm audit reports high or critical advisories (see above)"
npm sbom --sbom-format cyclonedx --omit dev > sbom.cdx.json && log "SBOM: sbom.cdx.json ($(node -p "require('./sbom.cdx.json').components.length") components)"
node -e '
  const s = require("./sbom.cdx.json"); const by = {};
  for (const c of s.components) { const l = (c.licenses ?? []).map((x) => x.license?.id ?? x.license?.name ?? x.expression).join(" OR ") || "UNKNOWN"; by[l] = (by[l] ?? 0) + 1; }
  console.log("licences:", JSON.stringify(by));' | tee -a "$REPORT"

step "Build and tests"
npm run typecheck 2>&1 | tail -2 | tee -a "$REPORT"
npm run build 2>&1 | tail -2 | tee -a "$REPORT"
npm run check:all 2>&1 | tail -5 | tee -a "$REPORT"

if [ "${1:-}" = "--docker" ]; then
  step "Container"
  docker build --pull -t nexus-sign/auth-core:baseline . 2>&1 | tail -3 | tee -a "$REPORT"
  log "image: $(docker image inspect nexus-sign/auth-core:baseline --format '{{.Id}}')"
fi

step "Result"
log "BASELINE VERIFIED for $(git rev-parse HEAD)"
