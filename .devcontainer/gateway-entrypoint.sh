#!/usr/bin/env bash
# Gateway start. The dev PKI in conf/pki (made per machine by the `pki` service,
# scripts/dev_pki.py; gitignored) goes
#   - into the environment, where conf/apisix.yaml references certificate and
#     key ($env://APISIX_TLS_CERT, $env://APISIX_TLS_KEY), and
#   - into the container's trust stores: system-wide (curl, Python) and the
#     NSS database Chromium reads (Playwright tests).
# Then APISIX's own entrypoint takes over.
set -euo pipefail

PKI=/workspace/conf/pki
for f in ca.pem server.pem server-key.pem; do
    if [ ! -f "$PKI/$f" ]; then
        echo "gateway: $PKI/$f is missing; run: python scripts/dev_pki.py" >&2
        exit 1
    fi
done

APISIX_TLS_CERT="$(cat "$PKI/server.pem")"
APISIX_TLS_KEY="$(cat "$PKI/server-key.pem")"
export APISIX_TLS_CERT APISIX_TLS_KEY

sudo install -m 644 "$PKI/ca.pem" /usr/local/share/ca-certificates/example-test-dev-ca.crt
sudo update-ca-certificates >/dev/null

NSSDB="$HOME/.pki/nssdb"
mkdir -p "$NSSDB"
[ -f "$NSSDB/cert9.db" ] || certutil -d "sql:$NSSDB" -N --empty-password
certutil -d "sql:$NSSDB" -D -n "example.test dev CA" 2>/dev/null || true
certutil -d "sql:$NSSDB" -A -t "C,," -n "example.test dev CA" -i "$PKI/ca.pem"

exec /docker-entrypoint.sh "$@"
