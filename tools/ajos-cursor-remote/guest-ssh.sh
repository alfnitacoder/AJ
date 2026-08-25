#!/usr/bin/env bash
# SSH into the AJOS guest (QEMU hostfwd, default 127.0.0.1:9022).
# Password is the documented test account (user / pass), via sshpass if present.
set -euo pipefail

HOST="${AJOS_SSH_HOST:-127.0.0.1}"
PORT="${HOST_SSH_PORT:-9022}"
USER="${AJOS_SSH_USER:-user}"
PASS="${AJOS_SSH_PASSWORD:-pass}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
  -p "${PORT}"
)

if command -v sshpass >/dev/null 2>&1; then
  exec sshpass -p "${PASS}" ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@"
fi

exec ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@"
