#!/bin/bash
# AJOS dev bridge: use Cursor (local) + AJOS (guest in QEMU) like a remote target.
# Usage:
#   ajos_dev.sh push <local-file> <remote-path>   # upload via SFTP
#   ajos_dev.sh pull <remote-path> <local-file>   # download via SFTP
#   ajos_dev.sh run "<shell command>"             # run command on guest via SSH
#   ajos_dev.sh sync <local-dir> <remote-dir>     # upload a whole web app dir
#   ajos_dev.sh url                               # print the guest HTTP preview URL
set -eu
HOST=127.0.0.1; PORT=9022; USER_NAME=user; PASS=pass
SFTP_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
           -o PreferredAuthentications=password -o PubkeyAuthentication=no
           -o ConnectTimeout=15 -P "$PORT")
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o PreferredAuthentications=password -o PubkeyAuthentication=no
          -o ConnectTimeout=15 -p "$PORT")

case "${1:-help}" in
  push)  printf 'put "%s" "%s"\nbye\n' "$2" "$3" \
           | sshpass -p "$PASS" sftp "${SFTP_OPTS[@]}" "$USER_NAME@$HOST" ;;
  pull)  printf 'get "%s" "%s"\nbye\n' "$2" "$3" \
           | sshpass -p "$PASS" sftp "${SFTP_OPTS[@]}" "$USER_NAME@$HOST" ;;
  run)   sshpass -p "$PASS" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "$2" ;;
  sync)  # upload every file in $2 to $3 (flat; guest dirs must exist or use /tmp)
         REMOTE_DIR="$3"; for f in "$2"/*; do
           [ -f "$f" ] || continue
           base=$(basename "$f")
           printf 'put "%s" "%s/%s"\n' "$f" "$REMOTE_DIR" "$base"
         done
         printf 'bye\n' \
           | sshpass -p "$PASS" sftp "${SFTP_OPTS[@]}" "$USER_NAME@$HOST" ;;
  url)   echo "http://127.0.0.1:9080/" ;;
  *)     sed -n '2,10p' "$0" ;;
esac
