#!/usr/bin/env bash
# Creates a local certificate authority and an HTTPS certificate for the demo
# bank's device port, for an iPhone on the same Wi-Fi as this computer.
#
#   bash demo/bank-backend/make-cert.sh 192.168.1.23    # the computer's Wi-Fi IPv4 address
#
# Writes demo/bank-backend/tls/ (ca.crt, server.crt, server.key; the CA key
# stays in ca.key). Install ca.crt on the iPhone and trust it; remove it from
# the iPhone after the demo. Development only.
set -euo pipefail
ip="${1:-}"
[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Usage: $0 <IPv4 address of this computer on the Wi-Fi>" >&2; exit 2; }
dir="$(cd "$(dirname "$0")" && pwd)/tls"
mkdir -p "$dir"
cd "$dir"
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/CN=NEXUS-SIGN Demo Local CA $(date +%Y-%m-%d)" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=$ip" -out server.csr
printf 'subjectAltName=IP:%s,DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n' "$ip" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -sha256 -extfile server.ext -out server.crt 2>/dev/null
rm -f server.csr server.ext ca.srl
chmod 644 ca.crt server.crt
echo "Certificate for https://$ip:8443 written to $dir"
echo "Install on the iPhone: $dir/ca.crt"
