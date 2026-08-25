#!/usr/bin/env bash
# Unmount sshfs and stop the per-user AJOS Cursor gateway sshd.
set -euo pipefail

STATE="${AJOS_CURSOR_REMOTE_DIR:-${HOME}/.ajos-cursor-remote}"
MNT="${STATE}/mnt"
PIDFILE="${STATE}/sshd.pid"

umount_mnt() {
  if [ -d "${MNT}" ] && mountpoint -q "${MNT}" 2>/dev/null; then
    fusermount3 -u "${MNT}" 2>/dev/null || fusermount -u "${MNT}" 2>/dev/null || umount "${MNT}" 2>/dev/null || true
  elif [ -d "${MNT}" ]; then
    # macOS: mountpoint(1) is often missing
    umount "${MNT}" 2>/dev/null || diskutil unmount "${MNT}" 2>/dev/null || true
  fi
}

umount_mnt

if [ -f "${PIDFILE}" ]; then
  pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
  if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    sleep 0.3
    kill -9 "${pid}" 2>/dev/null || true
  fi
  rm -f "${PIDFILE}"
fi

echo "AJOS Cursor remote gateway stopped."
echo "SSH config snippet left at ${STATE}/ssh_config (safe to keep or delete)."
