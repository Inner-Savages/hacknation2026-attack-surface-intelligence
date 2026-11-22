#!/usr/bin/env bash
# One-time setup: generates secrets/ and .env next to this script. Idempotent:
# existing files are never overwritten.
set -euo pipefail
cd "$(dirname "$0")"
rnd() { head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c "${1:-32}"; }

umask 077
mkdir -p secrets
# The directory is 0700; the files are 0444 so the unprivileged container user
# (uid 65532) can read the bind-mounted secret.
mk() { [ -e "secrets/$1" ] || { printf '%s\n' "$2" >"secrets/$1"; chmod 0444 "secrets/$1"; echo "created secrets/$1"; }; }
mk data_key "$(head -c 32 /dev/urandom | base64)"
mk admin_password "$(rnd 24)"
mk viewer_password "$(rnd 16)"

if [ ! -e .env ]; then
  cp .env.example .env
  sed -i "s|^ASI_CENTRAL_TOKEN=.*|ASI_CENTRAL_TOKEN=$(rnd 40)|" .env
  chmod 0600 .env
  echo "created .env (fill in TUNNEL_TOKEN and optional API keys)"
fi
echo "admin password: $(cat secrets/admin_password)"
echo "viewer password: $(cat secrets/viewer_password)"
