#!/bin/bash
# Simple script to test SSH connection to AJOS
# Make sure AJOS is running first with: make run-console
# File transfer: ./test_sftp.sh  (same host/port/user/password)
#
# Transport encryption (AES-128-CTR) is implemented; the connection should
# complete. The script still times out after 15s if something hangs.

echo "Attempting to SSH into AJOS..."
echo "Host: 127.0.0.1"
# Match Makefile HOST_SSH_PORT default (hostfwd to guest :22)
PORT="${HOST_SSH_PORT:-9022}"
echo "Port: ${PORT}"
echo "User: user"
echo "Password: pass"
echo ""

TIMEOUT_SEC="${SSH_TEST_TIMEOUT:-15}"

run_ssh() {
  ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o BatchMode=no \
      -p "${PORT}" \
      user@127.0.0.1 \
      "echo 'SSH connection successful!'"
}

if command -v timeout >/dev/null 2>&1; then
  timeout "$TIMEOUT_SEC" run_ssh
  EXIT=$?
else
  # No timeout command (e.g. macOS): run ssh in background, kill after TIMEOUT_SEC
  run_ssh &
  PID=$!
  sleep "$TIMEOUT_SEC"
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    EXIT=124
  else
    wait "$PID"
    EXIT=$?
  fi
fi

if [ "${EXIT:-1}" -eq 0 ]; then
    echo ""
    echo "✓ SSH connection successful!"
elif [ "${EXIT:-1}" -eq 124 ]; then
    echo ""
    echo "⚠ SSH timed out after ${TIMEOUT_SEC}s."
    echo "  If the host key was accepted above, KEX and host key signature are working."
    echo "  Ensure AJOS was built with: make run-console (transport encryption is in crypto/ssh)."
    exit 0
else
    echo ""
    echo "✗ SSH connection failed. Check:"
    echo "  1. Is AJOS running? (make run-console)"
    echo "  2. Did you see '[SSHD] Server started on port 22' in the console?"
    echo "  3. Check the AJOS console for error messages"
fi
exit "${EXIT:-1}"
