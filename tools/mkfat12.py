#!/usr/bin/env python3
"""
Create a FAT12 or FAT16 disk image for AJOS.
Supports arbitrary sizes and automatically selects FAT type.
"""

from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


SECTOR_SIZE = 512
MEDIA = 0xF8  # Fixed disk
SECTORS_PER_TRACK = 32
NUM_HEADS = 16
NUM_FATS = 2
ROOT_ENTRIES = 512


def lba_of_cluster(cluster: int, data_lba: int, sectors_per_cluster: int) -> int:
    if cluster < 2:
        raise ValueError("cluster must be >= 2")
    return data_lba + (cluster - 2) * sectors_per_cluster


def set_fat12_entry(fat: bytearray, cluster: int, value: int) -> None:
    value &= 0xFFF
    off = cluster + (cluster // 2)
    if cluster & 1:
        fat[off] = (fat[off] & 0x0F) | ((value << 4) & 0xF0)
        fat[off + 1] = (value >> 4) & 0xFF
    else:
        fat[off] = value & 0xFF
        fat[off + 1] = (fat[off + 1] & 0xF0) | ((value >> 8) & 0x0F)


def set_fat16_entry(fat: bytearray, cluster: int, value: int) -> None:
    value &= 0xFFFF
    struct.pack_into("<H", fat, cluster * 2, value)


def to_83(name: str) -> bytes:
    name = name.strip()
    if "." in name:
        parts = name.split(".")
        base = "".join(parts[:-1])
        ext = parts[-1]
    else:
        base, ext = name, ""
    base = base.upper().replace(" ", "")[:8].ljust(8)
    ext = ext.upper().replace(" ", "")[:3].ljust(3)
    return (base + ext).encode("ascii")


@dataclass
class FileEntry:
    name: str
    data: bytes
    lfn: str | None = None  # long name to store in LFN entries (mixed case)


def lfn_checksum(name83: bytes) -> int:
    s = 0
    for b in name83:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def needs_lfn(name: str) -> bool:
    """A name needs an LFN entry if it isn't a plain uppercase 8.3 name."""
    if len(name) > 12:
        return True
    base, _, ext = name.partition(".")
    if len(base) > 8 or len(ext) > 3:
        return True
    return name != name.upper() or " " in name


def lfn_entries(name: str, name83: bytes) -> list[bytes]:
    """Build VFAT LFN directory entries (13 UTF-16 chars per entry) that
    precede the 8.3 entry on disk."""
    u16 = name.encode("utf-16-le")
    assert len(u16) % 2 == 0
    chars = [u16[i:i+2] for i in range(0, len(u16), 2)]
    n_entries = (len(chars) + 12) // 13
    # Pad the tail with 0x0000 terminator then 0xFFFF fill per spec.
    chars.append(b"\x00\x00")
    while len(chars) < n_entries * 13:
        chars.append(b"\xff\xff")
    cksum = lfn_checksum(name83)
    out = []
    for e in range(n_entries, 0, -1):
        seq = e | 0x40 if e == n_entries else e
        part = chars[(e - 1) * 13:(e - 1) * 13 + 13]
        ent = bytearray(32)
        ent[0] = seq
        ent[1:11] = b"".join(part[0:5])    # name1
        ent[11] = 0x0F                     # attr: LFN
        ent[12] = 0                        # type
        ent[13] = cksum
        ent[14:26] = b"".join(part[5:11])  # name2
        ent[26:28] = b"\x00\x00"           # first cluster
        ent[28:32] = b"".join(part[11:13]) # name3
        out.append(bytes(ent))
    return out


def build_image(files: list[FileEntry], total_sectors: int, boot_bin: bytes | None = None, kernel_bin: bytes | None = None) -> bytearray:
    # Determine cluster size and FAT type
    # For a simple implementation: 
    # FAT12 if clusters < 4085
    # FAT16 if clusters < 65525
    
    # Heuristic for sectors per cluster
    if total_sectors < 8192: # < 4MB
        sectors_per_cluster = 1
    elif total_sectors < 65536: # < 32MB
        sectors_per_cluster = 4
    elif total_sectors < 262144: # < 128MB
        sectors_per_cluster = 8
    else:
        sectors_per_cluster = 16

    # Reserve sectors for boot + kernel
    reserved_sectors = 1
    if kernel_bin:
        kernel_sectors = (len(kernel_bin) + SECTOR_SIZE - 1) // SECTOR_SIZE
        reserved_sectors += kernel_sectors
    
    # Roughly calculate data area to estimate FAT size
    # data_sectors approx total_sectors - reserved - root_dir
    root_dir_sectors = (ROOT_ENTRIES * 32 + (SECTOR_SIZE - 1)) // SECTOR_SIZE
    rough_data_sectors = total_sectors - reserved_sectors - root_dir_sectors - 32 # buffer
    rough_clusters = rough_data_sectors // sectors_per_cluster
    
    if rough_clusters < 4085:
        fat_type = 12
        sectors_per_fat = (rough_clusters * 3 // 2 + SECTOR_SIZE - 1) // SECTOR_SIZE
    else:
        fat_type = 16
        sectors_per_fat = (rough_clusters * 2 + SECTOR_SIZE - 1) // SECTOR_SIZE

    fat1_lba = reserved_sectors
    fat2_lba = reserved_sectors + sectors_per_fat
    root_lba = fat2_lba + sectors_per_fat
    data_lba = root_lba + root_dir_sectors
    
    actual_data_sectors = total_sectors - data_lba
    actual_clusters = actual_data_sectors // sectors_per_cluster
    
    img = bytearray(SECTOR_SIZE * total_sectors)

    # Boot sector (BPB)
    if boot_bin:
        img[0:len(boot_bin)] = boot_bin
    else:
        img[0:3] = b"\xEB\x3C\x90"

    bpb = img[0:SECTOR_SIZE]
    if not boot_bin:
        bpb[3:11] = b"AJOSFAT "

    struct.pack_into("<H", bpb, 11, SECTOR_SIZE)
    struct.pack_into("<B", bpb, 13, sectors_per_cluster)
    struct.pack_into("<H", bpb, 14, reserved_sectors)
    struct.pack_into("<B", bpb, 16, NUM_FATS)
    struct.pack_into("<H", bpb, 17, ROOT_ENTRIES)
    
    if total_sectors < 65536:
        struct.pack_into("<H", bpb, 19, total_sectors)
        struct.pack_into("<I", bpb, 32, 0)
    else:
        struct.pack_into("<H", bpb, 19, 0)
        struct.pack_into("<I", bpb, 32, total_sectors)

    struct.pack_into("<B", bpb, 21, MEDIA if total_sectors > 2880 else 0xF0)
    struct.pack_into("<H", bpb, 22, sectors_per_fat)
    struct.pack_into("<H", bpb, 24, SECTORS_PER_TRACK)
    struct.pack_into("<H", bpb, 26, NUM_HEADS)
    
    # Extended BPB
    off = 36
    bpb[off] = 0x80 if total_sectors > 2880 else 0x00 # drive
    bpb[off+2] = 0x29 # boot sig
    struct.pack_into("<I", bpb, off+3, 0x12345678) # vol id
    bpb[off+7:off+18] = b"AJOS DATA  "
    if fat_type == 12:
        bpb[off+18:off+26] = b"FAT12   "
    else:
        bpb[off+18:off+26] = b"FAT16   "

    bpb[510:512] = b"\x55\xAA"
    img[0:SECTOR_SIZE] = bpb

    if kernel_bin:
        img[SECTOR_SIZE:SECTOR_SIZE+len(kernel_bin)] = kernel_bin

    fat = bytearray(SECTOR_SIZE * sectors_per_fat)
    if fat_type == 12:
        fat[0] = MEDIA if total_sectors > 2880 else 0xF0
        fat[1] = 0xFF
        fat[2] = 0xFF
    else:
        fat[0] = MEDIA if total_sectors > 2880 else 0xF0
        fat[1] = 0xFF
        fat[2] = 0xFF
        fat[3] = 0xFF

    root = bytearray(SECTOR_SIZE * root_dir_sectors)
    next_cluster = 2
    root_idx = 0

    def alloc_file(data: bytes, filename: str) -> tuple[int, int]:
        nonlocal next_cluster
        size = len(data)
        if size == 0: return 0, 0
        clusters_needed = (size + (sectors_per_cluster * SECTOR_SIZE) - 1) // (sectors_per_cluster * SECTOR_SIZE)
        
        first_cluster = next_cluster
        remaining = data
        for ci in range(clusters_needed):
            cluster = next_cluster
            next_cluster += 1
            if cluster >= actual_clusters + 2:
                raise RuntimeError(f"Disk full allocating {filename}!")
            
            lba = lba_of_cluster(cluster, data_lba, sectors_per_cluster)
            start = lba * SECTOR_SIZE
            chunk_len = sectors_per_cluster * SECTOR_SIZE
            chunk = remaining[:chunk_len]
            img[start:start + len(chunk)] = chunk
            remaining = remaining[len(chunk):]

            if ci == clusters_needed - 1:
                if fat_type == 12: set_fat12_entry(fat, cluster, 0xFFF)
                else: set_fat16_entry(fat, cluster, 0xFFFF)
            else:
                if fat_type == 12: set_fat12_entry(fat, cluster, cluster + 1)
                else: set_fat16_entry(fat, cluster, cluster + 1)
        return first_cluster, size

    def alloc_dir_cluster(parent_cluster: int) -> int:
        """Allocate a cluster holding an empty directory ('.' and '..')."""
        nonlocal next_cluster
        cluster = next_cluster
        next_cluster += 1
        if cluster >= actual_clusters + 2:
            raise RuntimeError("Disk full allocating directory!")
        if fat_type == 12: set_fat12_entry(fat, cluster, 0xFFF)
        else: set_fat16_entry(fat, cluster, 0xFFFF)
        lba = lba_of_cluster(cluster, data_lba, sectors_per_cluster)
        sec = bytearray(sectors_per_cluster * SECTOR_SIZE)
        dot = bytearray(32)
        dot[0:11] = b".          "
        dot[11] = 0x10
        struct.pack_into("<H", dot, 26, cluster)
        dotdot = bytearray(32)
        dotdot[0:11] = b"..         "
        dotdot[11] = 0x10
        struct.pack_into("<H", dotdot, 26, parent_cluster)
        sec[0:32] = dot
        sec[32:64] = dotdot
        img[lba * SECTOR_SIZE:lba * SECTOR_SIZE + len(sec)] = sec
        return cluster

    def dir_entry_83(name83: bytes, attr: int, cluster: int) -> bytes:
        ent = bytearray(32)
        ent[0:11] = name83
        ent[11] = attr
        struct.pack_into("<H", ent, 26, cluster)
        return bytes(ent)

    def add_system_dirs() -> None:
        """Linux-style system directories baked into every image."""
        etc_c = alloc_dir_cluster(0)
        add_root_entry_raw(dir_entry_83(b"ETC        ", 0x10, etc_c))
        var_c = alloc_dir_cluster(0)
        add_root_entry_raw(dir_entry_83(b"VAR        ", 0x10, var_c))
        log_c = alloc_dir_cluster(var_c)
        # 'log' entry goes inside var's directory cluster, after . and ..
        var_lba = lba_of_cluster(var_c, data_lba, sectors_per_cluster)
        off = var_lba * SECTOR_SIZE + 64
        img[off:off + 32] = dir_entry_83(b"LOG        ", 0x10, log_c)
        bin_c = alloc_dir_cluster(0)
        add_root_entry_raw(dir_entry_83(b"BIN        ", 0x10, bin_c))
        tmp_c = alloc_dir_cluster(0)
        add_root_entry_raw(dir_entry_83(b"TMP        ", 0x10, tmp_c))

    def add_root_entry_raw(entry: bytes) -> None:
        nonlocal root_idx
        if root_idx >= ROOT_ENTRIES: raise RuntimeError("root dir full")
        root[root_idx * 32:(root_idx + 1) * 32] = entry
        root_idx += 1

    def add_root_entry(name: str, attr: int, first_cluster: int, size: int) -> None:
        nonlocal root_idx
        name83 = to_83(name)
        long_name = None
        if needs_lfn(name):
            long_name = name
        if long_name:
            for ent in lfn_entries(long_name, name83):
                if root_idx >= ROOT_ENTRIES: raise RuntimeError("root dir full")
                root[root_idx * 32:(root_idx + 1) * 32] = ent
                root_idx += 1
        if root_idx >= ROOT_ENTRIES: raise RuntimeError("root dir full")
        entry = bytearray(32)
        entry[0:11] = name83
        entry[11] = attr
        struct.pack_into("<H", entry, 26, first_cluster)
        struct.pack_into("<I", entry, 28, size)
        root[root_idx * 32:(root_idx + 1) * 32] = entry
        root_idx += 1

    for f in files:
        first_cluster, size = alloc_file(f.data, f.name)
        add_root_entry(f.name, 0x20, first_cluster, size)

    add_system_dirs()

    img[fat1_lba * SECTOR_SIZE:(fat1_lba + sectors_per_fat) * SECTOR_SIZE] = fat
    img[fat2_lba * SECTOR_SIZE:(fat2_lba + sectors_per_fat) * SECTOR_SIZE] = fat
    img[root_lba * SECTOR_SIZE:(root_lba + root_dir_sectors) * SECTOR_SIZE] = root

    return img


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("output", help="Output image file")
    parser.add_argument("--boot", help="Bootloader binary")
    parser.add_argument("--kernel", help="Kernel binary")
    parser.add_argument("--model", help="Path to model.bin")
    parser.add_argument("--size-mb", type=int, default=0, help="Total size in MB")
    args = parser.parse_args()

    files = []
    
    # If it's a floppy (no size or 1.44), add standard files
    is_floppy = args.size_mb <= 1
    if is_floppy:
        default_passwd = b"user:7C9C25DC:1000:0:/:/bin/sh\r\n"
        files.extend([
            FileEntry("README.TXT", b"AJOS Boot Floppy\r\n"),
            FileEntry("HELLO.AJ", b'print "hello from floppy"\r\n'),
            FileEntry("PASSWD", default_passwd),
        ])

    if args.model:
        p = Path(args.model)
        if p.exists():
            print(f"Adding model {p.name}...")
            files.append(FileEntry(p.name.upper(), p.read_bytes()))

    if os.path.exists("data"):
        for name in os.listdir("data"):
            p = Path("data") / name
            if p.is_file():
                # On floppy, exclude large files (>50KB) to avoid overflow / slow builds
                if is_floppy and p.stat().st_size > 50000:
                    continue
                # Avoid duplicates
                if any(f.name == name.upper() for f in files): continue
                files.append(FileEntry(name, p.read_bytes()))

    boot_bin = None
    if args.boot:
        with open(args.boot, "rb") as f: boot_bin = f.read()

    kernel_bin = None
    if args.kernel:
        with open(args.kernel, "rb") as f: kernel_bin = f.read()

    sectors = args.size_mb * 1024 * 1024 // SECTOR_SIZE if args.size_mb > 0 else 2880
    
    img = build_image(files, sectors, boot_bin, kernel_bin)
    Path(args.output).write_bytes(img)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

