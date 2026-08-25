#!/bin/bash
# Test OpenSSH sftp(1) against a running AJOS guest.
#
# Start the guest first. Prefer file serial so the guest does not stall:
#   make run-console-file
#   tail -f build/guest.log   # wait for "[SSHD] Server started on port 22"
# Then:
#   ./test_sftp.sh
#
# `make run-console` (stdio serial) also works if the pipe is drained, but
# SSH/SFTP is more reliable with run-console-file.
#
# Exercises ls / get / put against the FAT/VFS tree (README.TXT, /tmp, ...).
# Do not use sftp -b: that enables SSH BatchMode and disables password auth.

set -u

HOST="${AJOS_SSH_HOST:-127.0.0.1}"
PORT="${HOST_SSH_PORT:-9022}"
USER="${AJOS_SSH_USER:-user}"
PASS="${AJOS_SSH_PASSWORD:-pass}"
TIMEOUT_SEC="${SFTP_TEST_TIMEOUT:-25}"

echo "Attempting SFTP into AJOS..."
echo "Host: ${HOST}"
echo "Port: ${PORT}"
echo "User: ${USER}"
echo ""

if ! command -v sftp >/dev/null 2>&1; then
  echo "✗ sftp not found (install openssh-client)"
  exit 1
fi
if ! command -v sshpass >/dev/null 2>&1; then
  echo "✗ sshpass not found (needed for non-interactive password auth)"
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/ajos-sftp-XXXXXX)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

PUT_SRC="${WORKDIR}/put-src.txt"
GET_README="${WORKDIR}/got-readme.txt"
GET_PUT="${WORKDIR}/got-put.txt"
OUT="${WORKDIR}/out"
ERR="${WORKDIR}/err"
CMDS="${WORKDIR}/cmds"
echo "hello-from-sftp-test" > "${PUT_SRC}"

cat > "${CMDS}" <<EOF
ls
get README.TXT ${GET_README}
put ${PUT_SRC} /tmp/sftptest.txt
ls /tmp
get /tmp/sftptest.txt ${GET_PUT}
bye
EOF

SFTP_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectTimeout=10
  -P "${PORT}"
)

# Feed commands on stdin (not sftp -b) so sshpass can answer the password prompt.
if command -v timeout >/dev/null 2>&1; then
  timeout "${TIMEOUT_SEC}" sshpass -p "${PASS}" sftp "${SFTP_OPTS[@]}" \
    "${USER}@${HOST}" < "${CMDS}" >"${OUT}" 2>"${ERR}"
  EXIT=$?
else
  sshpass -p "${PASS}" sftp "${SFTP_OPTS[@]}" \
    "${USER}@${HOST}" < "${CMDS}" >"${OUT}" 2>"${ERR}"
  EXIT=$?
fi

cat "${OUT}" 2>/dev/null || true
cat "${ERR}" 2>/dev/null || true

if [ "${EXIT:-1}" -eq 124 ]; then
  echo ""
  echo "⚠ SFTP timed out after ${TIMEOUT_SEC}s."
  echo "  Is AJOS running? (make run-console)"
  echo "  Did you see '[SSHD] Server started on port 22' and '[SSH] SFTP subsystem started'?"
  exit 124
fi

FAIL=0
if [ "${EXIT:-1}" -ne 0 ]; then
  echo ""
  echo "✗ sftp exited ${EXIT}"
  FAIL=1
fi

if [ ! -s "${GET_README}" ]; then
  echo "✗ get README.TXT produced no data"
  FAIL=1
else
  echo "✓ got README.TXT ($(wc -c < "${GET_README}" | tr -d ' ') bytes)"
fi

if ! grep -q "hello-from-sftp-test" "${GET_PUT}" 2>/dev/null; then
  echo "✗ put/get round-trip of /tmp/sftptest.txt failed"
  FAIL=1
else
  echo "✓ put/get round-trip of /tmp/sftptest.txt"
fi

if [ "${FAIL}" -ne 0 ]; then
  echo ""
  echo "✗ SFTP test failed. Check:"
  echo "  1. Is AJOS running? (make run-console)"
  echo "  2. Did you see '[SSHD] Server started on port 22'?"
  echo "  3. sshpass installed?  ssh ${USER}@${HOST} -p ${PORT}  (password: ${PASS})"
  exit 1
fi

echo ""
echo "✓ SFTP ls/get/put succeeded"
exit 0
