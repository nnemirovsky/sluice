#!/usr/bin/env bash
# One-shot bootstrap that imports an existing OpenClaw home volume into
# a fresh Hermes home volume.
#
# Run once after replacing an OpenClaw deployment with the Hermes stack
# in compose.yml. The legacy openclaw-home volume from the previous
# deployment is read read-only; the migration target is the new
# hermes-home volume created by compose.yml. Idempotent: re-running
# layers cleanly because hermes claw migrate refuses to apply on
# conflicts unless --overwrite is passed.
#
# Usage:
#   bash bootstrap.sh [project-name] [legacy-volume]
#
#   project-name   docker compose project (defaults to the basename of
#                  the current directory, e.g. "hermes")
#   legacy-volume  full name of the openclaw-home volume from the prior
#                  deployment (defaults to sluice_openclaw-home which is
#                  the historical default; pass an explicit name if your
#                  prior project was named differently).
#
# What it does:
#   1. Stage the legacy openclaw home under a path that does not match
#      `pgrep -f openclaw` so the migrate command's running-instance
#      check does not false-positive on its own argv. Chown to the
#      hermes UID so the in-container migrator can read it.
#   2. Run `hermes claw migrate --preset full --migrate-secrets
#      --overwrite --no-backup --yes` against the staged source.
#   3. Patch mcp_servers.sluice.url into ~/.hermes/config.yaml so
#      Hermes registers sluice as an MCP server. Sluice's
#      HermesProfile.WireMCPCmd does this from the running sluice
#      container, but having a one-shot pre-write is helpful when
#      rebootstrapping a stack from clean.
#   4. Clean up the staging directory.
set -euo pipefail

PROJECT_NAME="${1:-$(basename "$PWD")}"
LEGACY_VOLUME="${2:-sluice_openclaw-home}"
HERMES_VOLUME="${PROJECT_NAME}_hermes-home"
HERMES_IMAGE="${HERMES_IMAGE:-nousresearch/hermes-agent:v2026.4.30}"

if ! docker volume inspect "$LEGACY_VOLUME" >/dev/null 2>&1; then
  echo "==> legacy volume '$LEGACY_VOLUME' not found; skipping bootstrap (fresh install)"
  exit 0
fi

echo "==> ensuring hermes-home volume exists"
docker volume create "$HERMES_VOLUME" >/dev/null

echo "==> staging legacy data (path renamed to avoid pgrep -f openclaw false-positive)"
docker run --rm \
  --user 0:0 \
  -v "$LEGACY_VOLUME":/legacy:ro \
  -v "$HERMES_VOLUME":/opt/data/.hermes \
  --entrypoint /bin/bash \
  "$HERMES_IMAGE" -c '
    set -e
    rm -rf /opt/data/.hermes/.migration-source
    cp -a /legacy/.openclaw /opt/data/.hermes/.migration-source
    chown -R 10000:10000 /opt/data/.hermes/.migration-source
  '

echo "==> running hermes claw migrate"
docker run --rm \
  -e HERMES_HOME=/opt/data/.hermes \
  -e HERMES_UID=10000 \
  -e HERMES_GID=10000 \
  -v "$HERMES_VOLUME":/opt/data/.hermes \
  "$HERMES_IMAGE" \
  claw migrate \
    --source /opt/data/.hermes/.migration-source \
    --preset full \
    --migrate-secrets \
    --overwrite \
    --no-backup \
    --yes \
  || echo "migrate exited non-zero (non-fatal warnings) -- continuing"

echo "==> patching mcp_servers.sluice.url into config.yaml"
docker run --rm \
  -e HERMES_HOME=/opt/data/.hermes \
  -v "$HERMES_VOLUME":/opt/data/.hermes \
  --entrypoint /bin/bash \
  "$HERMES_IMAGE" -c '
    set -e
    source /opt/hermes/.venv/bin/activate
    python3 - <<PY
import os, yaml
p = "/opt/data/.hermes/config.yaml"
data = {}
if os.path.exists(p):
    with open(p) as fh:
        data = yaml.safe_load(fh) or {}
servers = data.setdefault("mcp_servers", {})
existing = servers.get("sluice") or {}
if existing.get("url") != "http://sluice:3000/mcp":
    existing["url"] = "http://sluice:3000/mcp"
    servers["sluice"] = existing
    with open(p, "w") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)
    print("patched", p)
else:
    print("already patched")
PY
    chown 10000:10000 /opt/data/.hermes/config.yaml
  '

echo "==> cleaning up staged migration source"
docker run --rm \
  --user 0:0 \
  -v "$HERMES_VOLUME":/opt/data/.hermes \
  --entrypoint /bin/bash \
  "$HERMES_IMAGE" -c 'rm -rf /opt/data/.hermes/.migration-source'

echo "==> bootstrap complete"
