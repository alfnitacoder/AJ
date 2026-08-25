#!/bin/bash
# Test OpenSSH sftp(1) against a running AJOS guest.
# Start the guest first: make run-console
#
# Exercises ls / get / put against the FAT/VFS tree (README.TXT, /tmp, ...).

set -u

HOST="${AJOS_SSH_HOST:-127.0.0.1}"
PORT="${HOST_SSH_PORT:-9022}"
USER="${AJOS_SSH_USER:-user}"
PASS="${AJOS_SSH_PASSWORD:-pass}"
TIMEOUT_SEC="${SFTP_TEST_TIMEOUT:-20}"

echo "Attempting SFTP into AJOS..."
echo "Host: ${HOST}"
echo "Port: ${PORT}"
echo "User: ${USER}"
echo ""

if ! command -v sftp >/dev/null 2>&1; then
  echo "✗ sftp not found (install openssh-client)"
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/ajos-sftp-XXXXXX)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

PUT_SRC="${WORKDIR}/put-src.txt"
GET_README="${WORKDIR}/got-readme.txt"
GET_PUT="${WORKDIR}/got-put.txt"
BATCH="${WORKDIR}/batch"
OUT="${WORKDIR}/out"
ERR="${WORKDIR}/err"
echo "hello-from-sftp-test" > "${PUT_SRC}"

cat > "${BATCH}" <<EOF
ls
get README.TXT ${GET_README}
put ${PUT_SRC} /tmp/sftptest.txt
ls /tmp
get /tmp/sftptest.txt ${GET_PUT}
EOF

SFTP_ARGS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectTimeout=10
  -P "${PORT}"
  -b "${BATCH}"
  "${USER}@${HOST}"
)

if command -v sshpass >/dev/null 2>&1; then
  CMD=(sshpass -p "${PASS}" sftp "${SFTP_ARGS[@]}")
else
  ASK="${WORKDIR}/askpass"
  printf '#!/bin/sh\nprintf %%s "%s"\n' "${PASS}" > "${ASK}"
  chmod +x "${ASK}"
  export DISPLAY="${DISPLAY:-:0}"
  export SSH_ASKPASS="${ASK}"
  export SSH_ASKPASS_REQUIRE=force
  CMD=(sftp "${SFTP_ARGS[@]}")
fi

if command -v timeout >/dev/null 2>&1; then
  timeout "${TIMEOUT_SEC}" "${CMD[@]}" >"${OUT}" 2>"${ERR}"
  EXIT=$?
else
  "${CMD[@]}" >"${OUT}" 2>"${ERR}"
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
