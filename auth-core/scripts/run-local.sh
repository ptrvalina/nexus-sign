#!/usr/bin/env bash
# Runs Auth Core on this machine in development mode, with PostgreSQL and
# Redis from docker-compose.yml: a fresh database, the schema and database
# roles, a bank client, an admin account, then the service on port 8080.
#
#   bash scripts/run-local.sh            # from auth-core/
#
# Development mode uses the software HSM, whose evidence key exists only while
# the process runs, so every start begins with an empty database. Not for any
# shared or production environment.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
ENV_FILE=".env.local-run"
CREDENTIALS="${CREDENTIALS_FILE:-$HOME/nexus-local-credentials.txt}"
# Without Docker (USE_DOCKER=0) the database is reached with psql at ADMIN_DATABASE_URL.
USE_DOCKER="${USE_DOCKER:-1}"
ADMIN_DATABASE_URL="${ADMIN_DATABASE_URL:-postgres://nexus:nexus@localhost:5432/nexus_sign}"
APP_DATABASE_URL="${APP_DATABASE_URL:-postgres://nexus_app:nexus-app-local@localhost:5432/nexus_sign}"
REDIS_URL="${REDIS_URL:-redis://localhost:6379}"

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

sql() {
  if [ "$USE_DOCKER" = 1 ]; then
    docker compose exec -T postgres psql -U nexus -d nexus_sign -v ON_ERROR_STOP=1 -q "$@"
  else
    psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -q "$@"
  fi
}

step "Checking tools"
command -v node >/dev/null || fail "Node.js 22 or later is required"
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ] || fail "Node.js 22 or later is required (found $(node -v))"
command -v openssl >/dev/null || fail "openssl is required"
if [ "$USE_DOCKER" = 1 ]; then
  command -v docker >/dev/null || fail "Docker is required (Docker Desktop with WSL integration on Windows)"
  docker info >/dev/null 2>&1 || fail "Docker is not running"
fi
echo "node $(node -v)"

if [ "$USE_DOCKER" = 1 ]; then
  step "Starting PostgreSQL 16 and Redis 7 (fresh database)"
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose up -d
  # A cold Docker Desktop (first start after a reboot) can take minutes.
  for _ in $(seq 1 180); do
    docker compose exec -T postgres pg_isready -U nexus -d nexus_sign >/dev/null 2>&1 && break
    sleep 1
  done
  docker compose exec -T postgres pg_isready -U nexus -d nexus_sign >/dev/null 2>&1 \
    || { docker compose logs --tail 30 postgres; fail "PostgreSQL did not become ready (log above)"; }
fi

step "Applying the schema and the database roles"
export PGOPTIONS='-c client_min_messages=warning'
sql < src/db/schema.sql
sql < scripts/db/roles.sql
sql -c "ALTER ROLE nexus_app WITH LOGIN PASSWORD 'nexus-app-local'"

step "Installing dependencies and building"
[ -d node_modules ] || npm ci --no-audit --no-fund
npm run build --silent

step "Writing $ENV_FILE (new keys for this run)"
key() { openssl rand -base64 32; }
cat > "$ENV_FILE" <<EOF
NODE_ENV=development
ALLOW_INSECURE_DEVELOPMENT=true
PORT=$PORT
DATABASE_URL=$APP_DATABASE_URL
DATABASE_SSL=false
REDIS_URL=$REDIS_URL
REDIS_TLS_REQUIRED=false
HSM_ADAPTER=software
REQUIRE_VALID_ATTESTATION=false
REQUIRE_MTLS_HEADER=false
OFFLINE_CONFIRMATION_ENABLED=true
DEVICE_SECRET_ENCRYPTION_KEY=$(key)
WEBHOOK_SECRET_ENCRYPTION_KEY=$(key)
ADMIN_SECRET_ENCRYPTION_KEY=$(key)
ADMIN_COOKIE_SECURE=false
ADMIN_MFA_REQUIRED=true
EOF

step "Registering the bank client 'local-bank' and the admin account 'admin'"
client_output=$(node --env-file="$ENV_FILE" dist/cli/registerClient.js local-bank)
client_secret=$(printf '%s\n' "$client_output" | awk '/client_secret:/ {print $2}')
[ -n "$client_secret" ] || { printf '%s\n' "$client_output"; fail "no client_secret in the output"; }
admin_output=$(node --env-file="$ENV_FILE" dist/cli/createAdminUser.js admin administrator)
admin_password=$(printf '%s\n' "$admin_output" | awk '/ password:/ {print $2}')
totp_secret=$(printf '%s\n' "$admin_output" | awk '/ totp_secret:/ {print $2}')
[ -n "$admin_password" ] && [ -n "$totp_secret" ] || { printf '%s\n' "$admin_output"; fail "no admin password or TOTP secret in the output"; }

umask 077
cat > "$CREDENTIALS" <<EOF
NEXUS-SIGN Auth Core, local development run ($(date '+%Y-%m-%d %H:%M'))
Service:        http://localhost:$PORT
Admin console:  http://localhost:$PORT/admin/
  username:     admin
  password:     $admin_password
  TOTP key:     $totp_secret
                (add it to an authenticator app as a time-based key, or print
                the current one-time code from auth-core/ with:
                node -e "const t=require('./dist/crypto/totp');console.log(t.totpCode(t.base32Decode('$totp_secret'),t.currentStep()))")
Bank client:    local-bank
  client_secret: $client_secret

End-to-end flow, in a second terminal (from auth-core/):
  NEXUS_SIGN_SMOKE_CLIENT_ID=local-bank NEXUS_SIGN_SMOKE_CLIENT_SECRET=$client_secret node scripts/e2e-smoke.mjs http://localhost:$PORT
EOF

step "Starting Auth Core"
node --env-file="$ENV_FILE" dist/server.js > auth-core-local.log 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT INT TERM
for _ in $(seq 1 30); do
  curl -sf "http://localhost:$PORT/readyz" >/dev/null 2>&1 && break
  kill -0 $server 2>/dev/null || { cat auth-core-local.log; fail "Auth Core exited"; }
  sleep 1
done
curl -sf "http://localhost:$PORT/readyz" >/dev/null || { cat auth-core-local.log; fail "Auth Core is not ready"; }

printf '\nAuth Core is running. Credentials are also saved in %s\n\n' "$CREDENTIALS"
cat "$CREDENTIALS"
printf '\nLog: auth-core/auth-core-local.log. Press Ctrl+C to stop.\n'
wait $server
