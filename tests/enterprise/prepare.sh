#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p tls
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls/ca.key -out tls/ca.crt -days 1 -subj '/CN=MP8 fixture CA' >/dev/null 2>&1
for component in authority keycloak bridge; do
  openssl req -new -newkey rsa:2048 -nodes -keyout "tls/$component.key" -out "tls/$component.csr" -subj "/CN=$component" >/dev/null 2>&1
  if [ "$component" = bridge ]; then
    printf 'extendedKeyUsage=clientAuth\n' > tls/extensions
  else
    printf 'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > tls/extensions
  fi
  openssl x509 -req -in "tls/$component.csr" -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -out "tls/$component.crt" -days 1 -extfile tls/extensions >/dev/null 2>&1
done
openssl pkcs12 -export -inkey tls/bridge.key -in tls/bridge.crt -certfile tls/ca.crt -out tls/bridge.p12 -passout pass:fixture-only-password >/dev/null 2>&1
# The pinned Keycloak keytool creates the trusted CA entry before startup.
printf '%s\n' fixture-only-password > tls/password
printf '%s\n' fixture-only-bridge-bearer > tls/bearer
chmod 644 tls/ca.crt tls/keycloak.crt tls/bridge.crt tls/authority.crt
chmod 755 tls
sudo chown 1000:1000 tls/bridge.p12 tls/password tls/bearer tls/keycloak.key
