#!/usr/bin/env bash
# sshfs smoke test against a running AJOS guest.
#
#   make run-console-file
#   ./tools/ajos-cursor-remote/test-sshfs.sh
#
# Requires: sshfs, fuse, sshpass. Skips with exit 0 and a note if fuse cannot
# mount in this environment (some CI/VMs).
set -u

HOST="${AJOS_SSH_HOST:-127.0.0.1}"
PORT="${HOST_SSH_PORT:-9022}"
USER="${AJOS_SSH_USER:-user}"
PASS="${AJOS_SSH_PASSWORD:-pass}"
MNT="${AJOS_SSHFS_MNT:-}"

if ! command -v sshfs >/dev/null 2>&1; then
  echo "SKIP: sshfs not installed"
  echo "  Linux: sudo apt install sshfs"
  echo "  macOS: brew install macfuse && brew install gromgit/fuse/sshfs-mac"
  echo "  Then: sshfs -o port=${PORT},password_stdin,reconnect ${USER}@${HOST}:/ /mnt/ajos  <<< '${PASS}'"
  exit 0
fi
if ! command -v sshpass >/dev/null 2>&1; then
  echo "SKIP: sshpass not installed (needed for non-interactive guest password)"
  exit 0
fi
if [ ! -e /dev/fuse ]; then
  echo "SKIP: /dev/fuse missing (cannot mount sshfs here)"
  exit 0
fi

if [ -z "${MNT}" ]; then
  MNT="$(mktemp -d /tmp/ajos-sshfs-XXXXXX)"
  CLEAN_MNT=1
else
  mkdir -p "${MNT}"
  CLEAN_MNT=0
fi

cleanup() {
  if mount | grep -F " ${MNT} " >/dev/null 2>&1; then
    fusermount3 -u "${MNT}" 2>/dev/null || fusermount -u "${MNT}" 2>/dev/null || umount "${MNT}" 2>/dev/null || true
  fi
  if [ "${CLEAN_MNT:-0}" -eq 1 ]; then
    rmdir "${MNT}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "sshfs ${USER}@${HOST}:${PORT} -> ${MNT}"
UIDN="$(id -u)"
GIDN="$(id -g)"
if ! echo "${PASS}" | sshfs -o "reconnect,password_stdin,StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null,port=${PORT},uid=${UIDN},gid=${GIDN},idmap=user,max_read=8192,max_write=16384,PasswordAuthentication=yes,PubkeyAuthentication=no" \
     "${USER}@${HOST}:/" "${MNT}"; then
  echo "SKIP: sshfs mount failed (guest down, or FUSE not usable)"
  echo "  Start AJOS: make run-console-file"
  echo "  Laptop:     echo pass | sshfs -o port=${PORT},password_stdin user@127.0.0.1:/ ~/ajos-mnt"
  exit 0
fi

FAIL=0
if [ ! -e "${MNT}/README.TXT" ] && [ ! -e "${MNT}/readme.txt" ]; then
  echo "✗ README.TXT not visible on sshfs mount"
  ls -la "${MNT}" || true
  FAIL=1
else
  echo "✓ listed guest root (README.TXT)"
fi

echo "sshfs-hello" > "${MNT}/tmp/sshfs-test.txt" || {
  echo "✗ write /tmp/sshfs-test.txt failed"
  FAIL=1
}

if grep -q "sshfs-hello" "${MNT}/tmp/sshfs-test.txt" 2>/dev/null; then
  echo "✓ write/read round-trip of /tmp/sshfs-test.txt"
else
  echo "✗ read back of /tmp/sshfs-test.txt failed"
  FAIL=1
fi

if [ "${FAIL}" -ne 0 ]; then
  echo "✗ sshfs test failed"
  exit 1
fi
echo "✓ sshfs mount looks solid"
exit 0
