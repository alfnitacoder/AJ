#!/usr/bin/env python3
"""Run AJOS in QEMU, send login+commands, capture DBG| lines to debug.log."""
import json
import subprocess
import sys
import time
import threading
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
LOG_PATH = WORKSPACE / ".cursor" / "debug.log"
OS_IMG = WORKSPACE / "build" / "ajos.run.img"
DATA_IMG = WORKSPACE / "build" / "data.img"


def parse_dbg_line(line: str) -> dict | None:
    """Parse DBG|H1|msg|k1=v1|k2=v2 into NDJSON dict."""
    if "DBG|" not in line:
        return None
    try:
        parts = line.strip().split("|")
        if len(parts) < 2:
            return None
        hid = parts[1] if len(parts) > 1 else ""
        msg = parts[2] if len(parts) > 2 else ""
        data = {}
        for p in parts[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                data[k] = v
        return {"hypothesisId": hid, "location": msg, "message": msg, "data": data}
    except Exception:
        return None


def main():
    img = WORKSPACE / "build" / "ajos.img"
    if not img.exists():
        print("Build first: make run-console", file=sys.stderr)
        sys.exit(1)
    if not OS_IMG.exists() or img.stat().st_mtime > OS_IMG.stat().st_mtime:
        import shutil
        shutil.copy(img, OS_IMG)

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "w") as f:
        pass  # clear log

    qemu = [
        "qemu-system-i386", "-m", "512M", "-boot", "a",
        "-drive", f"file={OS_IMG},format=raw,if=floppy",
        "-netdev", "user,id=n0",
        "-device", "e1000,netdev=n0",
        "-nographic", "-monitor", "none", "-serial", "stdio", "-no-reboot",
    ]

    proc = subprocess.Popen(
        qemu,
        cwd=str(WORKSPACE),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    script = ["user\n", "pass\n", "ls\n", "llm hello\n"]
    sent = [0]
    output_lines = []

    def reader():
        for line in proc.stdout:
            output_lines.append(line)
            if "DBG|" in line:
                obj = parse_dbg_line(line)
                if obj:
                    with open(LOG_PATH, "a") as f:
                        f.write(json.dumps(obj) + "\n")
            if "Username:" in line and sent[0] == 0:
                proc.stdin.write(script[0])
                proc.stdin.flush()
                sent[0] = 1
            elif "Password:" in line and sent[0] == 1:
                proc.stdin.write(script[1])
                proc.stdin.flush()
                sent[0] = 2
            elif "AJOS [user]:" in line and sent[0] == 2:
                proc.stdin.write(script[2])
                proc.stdin.flush()
                sent[0] = 3
            elif "AJOS [user]:" in line and sent[0] == 3:
                proc.stdin.write(script[3])
                proc.stdin.flush()
                sent[0] = 4
            print(line, end="")

    t = threading.Thread(target=reader)
    t.daemon = True
    t.start()
    try:
        proc.wait(timeout=90)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=3)
    print("DBG lines written to", LOG_PATH)


if __name__ == "__main__":
    main()
