#!/usr/bin/env python3
"""
Run AJOS in QEMU with AJOS_NET_AUTOTEST (see kernel.c): pings 10.0.2.2 and 1.1.1.1.
Exits 0 if gateway ping shows replies; exits 1 on build/run failure.
Public IP ping may timeout under QEMU user networking (expected).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT_SEC = 180


def main() -> int:
    os.chdir(ROOT)
    run_img = os.path.join("build", "ajos.run.img")
    data_img = os.path.join("build", "data.img")
    if not os.path.isfile(run_img) or not os.path.isfile(data_img):
        print("ERROR: build/ajos.run.img and build/data.img required.", file=sys.stderr)
        print("Run: make test-net  (from Makefile)", file=sys.stderr)
        return 1

    cmd = [
        "qemu-system-i386",
        "-m",
        "512M",
        "-boot",
        "a",
        "-drive",
        f"file={run_img},format=raw,if=floppy",
        "-drive",
        f"file={data_img},format=raw,if=ide",
        "-netdev",
        "user,id=n0",
        "-device",
        "e1000,netdev=n0",
        "-nographic",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
    ]

    print("Running:", " ".join(cmd), flush=True)
    print(f"(timeout {TIMEOUT_SEC}s)\n", flush=True)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT_SEC,
            text=True,
            errors="replace",
        )
        out = proc.stdout or ""
        if proc.returncode != 0 and not out.strip():
            print(f"ERROR: qemu exited with code {proc.returncode}", file=sys.stderr)
            return 1
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "").decode("utf-8", errors="replace") if e.stdout else ""
        print(out)
        print(f"\nERROR: QEMU still running after {TIMEOUT_SEC}s (timeout).", file=sys.stderr)
        return 1

    log_path = os.path.join("build", "net-autotest.log")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(out)
    print(out)
    print(f"\nFull log: {log_path}")

    if "Failed to get" in out and "lock" in out:
        print(
            "\nERROR: QEMU could not open a disk image (another qemu may be using it). "
            "Run: pkill -9 qemu-system-i386  (or close other AJOS VMs), then retry.",
            file=sys.stderr,
        )
        return 2

    if "[AUTOTEST] Network smoke test starting" not in out:
        print(
            "\nFAIL: autotest block did not run (missing AJOS_NET_AUTOTEST or boot failed).",
            file=sys.stderr,
        )
        return 1

    # After first "PING 10.0.2.2", look for reply line
    gw_ok = bool(re.search(r"64 bytes from 10\.0\.2\.2[:\s]", out)) or bool(
        re.search(r"10\.0\.2\.2: icmp_seq=", out)
    )
    if not gw_ok:
        print("\nFAIL: no ICMP echo reply from gateway 10.0.2.2 (check ARP/routing).", file=sys.stderr)
        return 1

    pub_timeouts = len(re.findall(r"Request timeout for icmp_seq", out))
    pub_replies = len(re.findall(r"64 bytes from 1\.1\.1\.1", out))

    print("\n--- Summary ---")
    print(f"  Gateway ping 10.0.2.2: {'OK (replies seen)' if gw_ok else 'FAIL'}")
    if pub_replies:
        print(f"  Public ping 1.1.1.1:   OK ({pub_replies} reply line(s)) — uncommon with QEMU user-net")
    elif pub_timeouts:
        print(
            f"  Public ping 1.1.1.1:   no replies ({pub_timeouts} timeout line(s)) — "
            "expected with QEMU -netdev user (ICMP often not forwarded)"
        )
    else:
        print("  Public ping 1.1.1.1:   (no clear reply/timeout in log)")

    if "[AUTOTEST] Done." in out:
        print("  Autotest finished and called shutdown path.")
    else:
        print("  Note: [AUTOTEST] Done. not seen (QEMU may still be running until timeout).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
