#!/bin/sh
# deploy-store.sh - rebuild the AJOS App Store image and redeploy it to
# Proxmox VM 105 (203.191.130.131). Run this after adding/updating any
# webapp/*.aj file (or store.aj catalog cards).
#
# Usage:  tools/deploy-store.sh
# Needs:  ssh/scp key access to root@172.16.0.36 (pxx3)
set -e
cd "$(dirname "$0")/.."
PVE=root@172.16.0.36
VM=105

echo "[1/4] Building store image (stages all of webapp/)..."
python3 tools/mkfat12.py build/ajos-store.img \
  --boot build/boot.bin --kernel build/kernel.bin \
  --netcfg etc/NETWORK.STORE.CFG

echo "[2/4] Uploading image to PVE host..."
scp -q build/ajos-store.img "$PVE:/tmp/ajos-store.img"

echo "[3/4] Swapping VM $VM disk and restarting..."
ssh "$PVE" "qm stop $VM 2>/dev/null; sleep 2; echo stopped"
OUT=$(ssh "$PVE" "qm importdisk $VM /tmp/ajos-store.img local-lvm 2>&1 | tail -1")
echo "  $OUT"
NEWDISK=$(echo "$OUT" | sed -n "s/.*imported disk 'local-lvm:\(vm-$VM-disk-[0-9]*\)'.*/\1/p")
if [ -z "$NEWDISK" ]; then echo "ERROR: could not parse imported disk name"; exit 1; fi
ssh "$PVE" "qm set $VM -ide0 local-lvm:$NEWDISK,size=4M && \
            qm set $VM -boot order=ide0 && \
            qm start $VM && echo '  VM $VM started on' \$NEWDISK"

echo "[4/4] Done. Store: http://203.191.130.131/app/store (boots in ~20s)"
