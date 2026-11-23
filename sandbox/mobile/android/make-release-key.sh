#!/usr/bin/env bash
# Creates the signing key of the sandbox bank app for Android (once) and
# prints the four values to store as GitHub secrets. Keep the .jks file and
# its password: every later release must be signed with the same key, or
# phones refuse the update.
set -euo pipefail
command -v keytool >/dev/null || { echo "keytool (JDK 17) is required" >&2; exit 1; }
out="${1:-$HOME/voxtel-sandbox-release.jks}"
[ -e "$out" ] && { echo "$out already exists; not overwriting it" >&2; exit 1; }
alias=voxtel
password="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
keytool -genkeypair -v -keystore "$out" -alias "$alias" -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
  -validity 9125 -storepass "$password" -keypass "$password" \
  -dname "CN=VoxTel Demo Bank (sandbox), O=Nexis Trust Technologies AG" >/dev/null
chmod 600 "$out"
echo "Key written to $out. Add these repository secrets (GitHub → Settings → Secrets and variables → Actions):"
echo
echo "VOXTEL_ANDROID_KEY_ALIAS          $alias"
echo "VOXTEL_ANDROID_KEYSTORE_PASSWORD  $password"
echo "VOXTEL_ANDROID_KEY_PASSWORD       $password"
echo "VOXTEL_ANDROID_KEYSTORE_BASE64    (the next line)"
base64 < "$out" | tr -d '\n'; echo
