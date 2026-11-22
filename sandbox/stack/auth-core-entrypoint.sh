#!/bin/sh
# Auth Core inside the sandbox: first start creates the SoftHSM token and the
# evidence key, registers the sandbox bank's OAuth client and an admin login,
# and writes their credentials to the sandbox's own credentials volume.
# Then it runs the unchanged Auth Core server.
set -eu
[ "${SANDBOX_ENVIRONMENT:-}" = "sandbox" ] || { echo "SANDBOX_ENVIRONMENT=sandbox is required" >&2; exit 2; }
: "${PKCS11_PIN:?}" "${PKCS11_SO_PIN:?}" "${BANK_CLIENT_ID:?}"

export PKCS11_MODULE_PATH=/opt/softhsm/lib/softhsm/libsofthsm2.so
export PKCS11_TOKEN_LABEL="${PKCS11_TOKEN_LABEL:-nexus-sandbox}"
export PKCS11_EVIDENCE_KEY_LABEL="${PKCS11_EVIDENCE_KEY_LABEL:-nexus-sandbox-evidence}"
HSM_DIR=/var/lib/sandbox-hsm
CREDENTIALS=/run/sandbox-credentials
umask 077

if [ ! -f "$HSM_DIR/softhsm2.conf" ]; then
  mkdir -p "$HSM_DIR/tokens"
  printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$HSM_DIR" > "$HSM_DIR/softhsm2.conf.tmp"
  mv "$HSM_DIR/softhsm2.conf.tmp" "$SOFTHSM2_CONF"
  /opt/softhsm/bin/softhsm2-util --init-token --free --label "$PKCS11_TOKEN_LABEL" --so-pin "$PKCS11_SO_PIN" --pin "$PKCS11_PIN" >/dev/null
  node /sandbox/hsm-init.cjs
fi

if [ ! -s "$CREDENTIALS/bank-client-secret" ]; then
  out=$(node dist/cli/registerClient.js "$BANK_CLIENT_ID")
  secret=$(printf '%s\n' "$out" | awk '/client_secret:/ {print $2}')
  [ -n "$secret" ] || { printf '%s\n' "$out" >&2; echo "registerClient printed no client_secret" >&2; exit 1; }
  admin=$(node dist/cli/createAdminUser.js sandbox-admin administrator)
  printf '%s\n' "$admin" | awk '/ password:| totp_secret:/ {print $1, $2}' > "$CREDENTIALS/auth-core-admin.txt"
  printf '%s' "$secret" > "$CREDENTIALS/bank-client-secret.tmp"
  chmod 644 "$CREDENTIALS/bank-client-secret.tmp"
  mv "$CREDENTIALS/bank-client-secret.tmp" "$CREDENTIALS/bank-client-secret"
  echo "sandbox bank client '$BANK_CLIENT_ID' registered"
fi

exec node dist/server.js
