#!/bin/bash
# AJOS guest VM launcher / keepalive (QEMU, i386)
# Usage: run_aj.sh [start|status|stop]
#   start  (default) launch the guest if not already running (idempotent)
#   status           print "running" or "stopped"
#   stop             terminate the guest
# Ports on host: 9022 -> guest ssh (22), 9080 -> guest http (80)
# Login: user / pass        Web preview: http://127.0.0.1:9080/
cd /Users/ageorge/AJOS || exit 1

# launchd runs with a minimal PATH; resolve QEMU absolutely
QEMU="$(command -v qemu-system-i386 || echo /opt/homebrew/bin/qemu-system-i386)"

PAT="qemu-system-i386.*ajos.img"

case "${1:-start}" in
  start)
    if pgrep -f "$PAT" >/dev/null 2>&1; then
      echo "AJOS VM already running (pid $(pgrep -f "$PAT" | head -1))"
      exit 0
    fi
    # keep the serial-input fifo open so QEMU's stdin never blocks
    (sleep 3600 > build/ttyin.fifo &)
    nohup "$QEMU" -m 512M -boot "${AJOS_BOOT_ORDER:-a}" \
      -drive file=build/ajos.img,format=raw,if=floppy \
      -drive file=build/data.img,format=raw,if=ide \
      -netdev user,id=n0,hostfwd=tcp::9022-10.0.2.15:22,hostfwd=tcp::9080-10.0.2.15:80 \
      -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot \
      < build/ttyin.fifo >> build/console.log 2>&1 &
    echo "AJOS VM launched (pid $!)"
    ;;
  status)
    if pgrep -f "$PAT" >/dev/null 2>&1; then echo "running"; else echo "stopped"; fi
    ;;
  stop)
    pkill -f "$PAT" && echo "stopped" || echo "not running"
    ;;
  serve)
    # For launchd (KeepAlive): hold the serial-input fifo open, then exec
    # QEMU in the foreground; launchd restarts it instantly if it dies.
    (while true; do sleep 3600; done > build/ttyin.fifo &)
    exec "$QEMU" -m 512M -boot "${AJOS_BOOT_ORDER:-a}" \
      -drive file=build/ajos.img,format=raw,if=floppy \
      -drive file=build/data.img,format=raw,if=ide \
      -netdev user,id=n0,hostfwd=tcp::9022-10.0.2.15:22,hostfwd=tcp::9080-10.0.2.15:80 \
      -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot \
      < build/ttyin.fifo
    ;;
  *)
    sed -n '2,10p' "$0"
    ;;
esac
