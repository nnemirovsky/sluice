#!/usr/bin/env bash
# scripts/gen-phantom-env.sh
# Generates .env.phantom with fake tokens for the OpenClaw container
set -euo pipefail

cat > .env.phantom << 'EOF'
# Phantom tokens. These are NOT real credentials.
# Sluice proxy injects real credentials on the wire.
ANTHROPIC_API_KEY=sk-ant-phantom-not-real-00000000000000000000
OPENAI_API_KEY=sk-phantom-not-real-00000000000000000000000000
GITHUB_TOKEN=ghp_phantom0000000000000000000000000000
EOF

echo "Generated .env.phantom"
echo "These are fake tokens. Real credentials live in the Sluice vault."
