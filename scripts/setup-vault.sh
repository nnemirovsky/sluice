#!/usr/bin/env bash
# scripts/setup-vault.sh
# Interactive credential setup for Sluice vault
set -euo pipefail

SLUICE=${SLUICE:-./sluice}
VAULT_DIR=${SLUICE_VAULT_DIR:-$HOME/.sluice}

echo "=== Sluice Vault Setup ==="
echo ""

# Generate CA certificate for HTTPS MITM if it doesn't exist.
if [ ! -f "$VAULT_DIR/ca-cert.pem" ]; then
  echo "Generating CA certificate for HTTPS interception..."
  $SLUICE cert generate --out "$VAULT_DIR"
  echo ""
else
  echo "CA certificate already exists at $VAULT_DIR/ca-cert.pem"
  echo ""
fi

read -p "Add Anthropic API key? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  read -sp "Anthropic API key: " key; echo
  echo "$key" | $SLUICE cred add anthropic_api_key
fi

read -p "Add OpenAI API key? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  read -sp "OpenAI API key: " key; echo
  echo "$key" | $SLUICE cred add openai_api_key
fi

read -p "Add GitHub token? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  read -sp "GitHub token: " key; echo
  echo "$key" | $SLUICE cred add github_token
fi

echo ""
echo "Vault contents:"
$SLUICE cred list
echo ""
echo "Done. Run 'docker compose up' to start."
