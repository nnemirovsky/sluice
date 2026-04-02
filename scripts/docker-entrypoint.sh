#!/bin/sh
set -e

# Generate CA certificate for HTTPS MITM if it does not exist yet.
# The cert and key are stored in the vault dir. The public cert is
# then copied to /home/sluice/ca/ (shared volume) so the agent
# container can trust it via update-ca-certificates.
sluice cert generate

CERT_SRC="/home/sluice/.sluice/ca-cert.pem"
CERT_DST="/home/sluice/ca/sluice-ca.crt"
if [ -f "$CERT_SRC" ] && [ -d "/home/sluice/ca" ]; then
  cp "$CERT_SRC" "$CERT_DST"
fi

exec sluice "$@"
