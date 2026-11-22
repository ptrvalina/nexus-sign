#!/bin/sh
# Runs once, when the sandbox database is created (after the unchanged
# auth-core/src/db/schema.sql and auth-core/scripts/db/roles.sql).
set -eu
: "${SANDBOX_APP_DB_PASSWORD:?}"
psql -v ON_ERROR_STOP=1 -q --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v pw="$SANDBOX_APP_DB_PASSWORD" <<'SQL'
ALTER ROLE nexus_app WITH LOGIN PASSWORD :'pw';
SQL
