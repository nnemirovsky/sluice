#!/usr/bin/env bash
# scripts/setup-vault.sh
# Interactive credential setup for Sluice vault
set -euo pipefail

SLUICE=${SLUICE:-./sluice}

echo "=== Sluice Vault Setup ==="
echo ""

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
