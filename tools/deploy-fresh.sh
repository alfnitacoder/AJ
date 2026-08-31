#!/bin/sh
# deploy-fresh.sh - create/start VM 106 "ajos-fresh": a fresh-user AJOS box
# that boots with NO apps and installs the web-app set from the App Store
# (203.191.130.131) via its boot manifest at every boot.
#
# Run when this Mac is on the 172.16.0.x management network.
set -e
cd "$(dirname "$0")/.."
PVE=root@172.16.0.36

echo "[1/4] Building the fresh-user image (no apps baked)..."
make fresh-img

echo "[2/4] Uploading..."
scp -q build/ajos-fresh.img "$PVE:/tmp/ajos-fresh.img"

echo "[3/4] Creating/starting VM 106..."
ssh "$PVE" "qm status 106 > /dev/null 2>&1 && qm stop 106; qm destroy 106 2>/dev/null; sleep 1; \
  qm create 106 --name ajos-fresh --cores 1 --cpu qemu32 --memory 2048 --ostype l26 \
    --net0 e1000=BC:24:11:99:6F:5B,bridge=vmbr4 --serial0 socket --vga none >/dev/null && \
  qm importdisk 106 /tmp/ajos-fresh.img local-lvm 2>&1 | tail -1 && \
  qm set 106 -ide0 local-lvm:vm-106-disk-0,size=4M && qm set 106 -boot order=ide0 && \
  qm start 106 && echo '  VM 106 started'"

echo "[4/4] Booting + store installs take ~60s. Then check:"
echo "  curl http://203.191.130.132/app/index"
echo "  curl http://203.191.130.132/app/todo"
echo "  curl http://203.191.130.132/app/editor"
echo "  curl http://203.191.130.132/app/hotspot"
echo "  curl http://203.191.130.132/app/notes"
