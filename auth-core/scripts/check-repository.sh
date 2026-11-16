#!/usr/bin/env bash
# Repository hygiene: no secret material and no build output in source control.
# Inside a git checkout only tracked files are inspected, so local build
# output (dist/, node_modules/) does not fail the check.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  files=$(git ls-files)
else
  files=$(find . -type f -not -path '*/node_modules/*' | sed 's#^\./##')
fi
# Key and certificate formats, environment files (except templates), token
# directories and Redis snapshots (which hold live tokens). Public certificate chains used as test fixtures are listed by
# exact path in auth-core/scripts/public-material.txt and must not contain a
# private key.
allowed="auth-core/scripts/public-material.txt"
secrets=$(printf '%s\n' "$files" \
  | grep -E '(^|/)\.env(\.[^/]*)?$|\.(pem|key|p8|p12|pfx|jks|keystore|der|crt|cer)$|(^|/)service-account[^/]*\.json$|(^|/)softhsm-tokens/|(^|/)tokens/[^/]+\.object$|\.rdb$' \
  | grep -vE '(^|/)\.env\.example$' \
  | grep -vxF -f <(grep -vE '^(#|$)' "$allowed") || true)
if [ -n "$secrets" ]; then
  printf 'Potential secret material:\n%s\n' "$secrets" >&2
  exit 1
fi
while IFS= read -r listed; do
  case "$listed" in ''|'#'*) continue ;; esac
  if [ -f "$listed" ] && grep -q 'PRIVATE KEY' "$listed"; then
    printf 'Listed as public material but contains a private key: %s\n' "$listed" >&2
    exit 1
  fi
done < "$allowed"
output=$(printf '%s\n' "$files" | grep -E '(^|/)(dist|build|\.build|__pycache__|\.gradle)/' || true)
if [ -n "$output" ]; then
  printf 'Build output committed:\n%s\n' "$output" >&2
  exit 1
fi
version=$(tr -d '[:space:]' < VERSION)
mismatched=""
grep -q "\"version\": \"$version\"" auth-core/package.json || mismatched="$mismatched auth-core/package.json"
for spec in auth-core/openapi.yaml sandbox/openapi.yaml; do
  grep -q "^  version: $version\$" "$spec" || mismatched="$mismatched $spec"
done
grep -q "NEXUS_SIGN_SDK_VERSION = \"$version\"" android-sdk/src/main/kotlin/com/nexis/nexussign/NEXUSSignVersion.kt || mismatched="$mismatched android-sdk"
grep -q "current = \"$version\"" ios-sdk/Sources/NEXUSSign/NEXUSSignVersion.swift || mismatched="$mismatched ios-sdk"
if [ -n "$mismatched" ]; then
  printf 'Version differs from VERSION (%s):%s\n' "$version" "$mismatched" >&2
  exit 1
fi
latest=$(ls auth-core/migrations | grep -E '^[0-9]{3}_.*\.sql$' | sort | tail -1 | cut -c1-3)
stated=$(sed -n 's/^-- schema-version: \([0-9]\{3\}\)$/\1/p' auth-core/src/db/schema.sql)
if [ "$latest" != "$stated" ]; then
  printf 'auth-core/src/db/schema.sql states schema-version %s, the last migration is %s: append the migration to schema.sql and update the line\n' "$stated" "$latest" >&2
  exit 1
fi
echo 'ok: repository hygiene'
