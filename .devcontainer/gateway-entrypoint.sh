#!/usr/bin/env bash
# Gateway start. Uses what the vault-init job (scripts/stack_init.py) left in
# .dev/ (gitignored):
#   - .dev/tokens/gateway: the gateway's Vault token (policy: read
#     kv/gateway/* only), handed to APISIX as $env://APISIX_VAULT_TOKEN. APISIX
#     reads its TLS certificate and key from Vault with it (conf/apisix.yaml);
#   - .dev/ca.pem: the CA certificate of Vault's PKI, trusted inside the
#     container: system-wide (curl, Python) and in the NSS database Chromium
#     reads (Playwright tests).
# Then APISIX's own entrypoint takes over.
set -euo pipefail

DEV=/workspace/.dev
for f in ca.pem tokens/gateway; do
    if [ ! -f "$DEV/$f" ]; then
        echo "gateway: $DEV/$f is missing; the vault-init job did not run (docker compose up)" >&2
        exit 1
    fi
done

APISIX_VAULT_TOKEN="$(cat "$DEV/tokens/gateway")"
export APISIX_VAULT_TOKEN

sudo install -m 644 "$DEV/ca.pem" /usr/local/share/ca-certificates/example-test-dev-ca.crt
sudo update-ca-certificates --fresh >/dev/null

NSSDB="$HOME/.pki/nssdb"
mkdir -p "$NSSDB"
[ -f "$NSSDB/cert9.db" ] || certutil -d "sql:$NSSDB" -N --empty-password
certutil -d "sql:$NSSDB" -D -n "example.test dev CA" 2>/dev/null || true
certutil -d "sql:$NSSDB" -A -t "C,," -n "example.test dev CA" -i "$DEV/ca.pem"

exec /docker-entrypoint.sh "$@"
