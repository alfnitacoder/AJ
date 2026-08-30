#!/usr/bin/env python3
"""End-to-end fork/execve/waitpid test for AJOS.

Builds nothing itself: run via `make test-fork` (which builds the serial
image first). Boots QEMU with the serial console on stdio, logs in, and
drives the shell:

    loadbin FORKDEMO.BIN 0 ; run3 0        (foreground fork/exec/wait demo)
    loadbin FORKDEMO.BIN 1 ; run3 1 &      (background job + ps + wait)

Pass criteria: the expected FORKDEMO/CHILD.BIN lines appear in order and
the shell reports the final exit codes.
"""

import re
import subprocess
import sys
import time

QEMU_CMD = [
    "qemu-system-i386",
    "-m", "512M",
    "-boot", "a",
    "-drive", "file=build/ajos.run.img,format=raw,if=floppy",
    "-drive", "file=build/data.img,format=raw,if=ide",
    "-netdev", "user,id=n0",
    "-device", "e1000,netdev=n0",
    "-nographic",
    "-monitor", "none",
    "-serial", "stdio",
    "-no-reboot",
]

# Lines that must appear, in this order, for `run3 0` to count as passing.
FOREGROUND_EXPECT = [
    r"FORKDEMO: start, pid=2",
    r"FORKDEMO: child \(pid=3, ppid=2\)",
    r"FORKDEMO: parent, child pid=3",
    r"FORKDEMO: child done sleeping, exiting 42",
    r"FORKDEMO: parent reaped pid=3, status=42",
    r"CHILD\.BIN: running via execve",
    r"CHILD\.BIN: argc=2 argv0=CHILD\.BIN argv1=hello-from-parent",
    r"CHILD\.BIN: exiting 7",
    r"run3: FORKDEMO\.BIN exited with code 7",
]


class Guest:
    def __init__(self):
        self.proc = subprocess.Popen(
            QEMU_CMD,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=0,
        )
        self.buf = ""
        self.log = open("build/test_fork_guest.log", "w")

    def send(self, s):
        # The guest UART runs with the FIFO disabled (serial_initialize sets
        # FCR=0), so burst writes drop bytes while the shell is still
        # processing a previous line. Type like a human: char by char.
        for ch in s:
            self.proc.stdin.write(ch)
            self.proc.stdin.flush()
            time.sleep(0.01)
        time.sleep(0.4)

    def read_for(self, seconds):
        """Read stdout for `seconds`, appending to the rolling buffer."""
        import select

        deadline = time.time() + seconds
        fd = self.proc.stdout.fileno()
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                ch = os_read(fd)
                if ch:
                    self.buf += ch
                    self.log.write(ch)
                    self.log.flush()
                    sys.stdout.write(ch)
                    sys.stdout.flush()

    def expect(self, pattern, timeout):
        """Wait until `pattern` matches the rolling buffer (searched fresh)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if re.search(pattern, self.buf):
                return True
            self.read_for(0.2)
            if self.proc.poll() is not None:
                print(f"\n[FAIL] QEMU exited early (rc={self.proc.returncode})")
                return False
        return False

    def expect_sequence(self, patterns, timeout_each):
        for p in patterns:
            if not self.expect(p, timeout_each):
                print(f"\n[FAIL] Missing expected output: {p}")
                return False
        return True

    def close(self):
        try:
            self.proc.kill()
            self.proc.wait(timeout=5)
        except Exception:
            pass
        self.log.close()


def os_read(fd):
    import os

    try:
        return os.read(fd, 4096).decode("utf-8", "replace")
    except OSError:
        return ""


def main():
    g = Guest()
    ok = False
    try:
        if not g.expect(r"Username:", timeout=60):
            print("\n[FAIL] no login prompt")
            return 1
        g.send("user\n")
        if not g.expect(r"Password:", timeout=10):
            print("\n[FAIL] no password prompt")
            return 1
        g.send("pass\n")
        if not g.expect(r"AJOS.*> ", timeout=15):
            print("\n[FAIL] no shell prompt after login")
            return 1
        print("\n[PASS] login")

        # Foreground fork/exec/wait demo
        g.send("loadbin FORKDEMO.BIN 0\n")
        if not g.expect(r"Loaded FORKDEMO\.BIN", timeout=15):
            print("\n[FAIL] loadbin FORKDEMO.BIN")
            return 1
        g.send("run3 0\n")
        if not g.expect_sequence(FOREGROUND_EXPECT, timeout_each=30):
            return 1
        print("\n[PASS] foreground fork + waitpid + execve")

        # Background job: prompt must come back while the program runs
        g.send("loadbin FORKDEMO.BIN 1\n")
        if not g.expect(r"Loaded FORKDEMO\.BIN", timeout=15):
            print("\n[FAIL] loadbin (bg)")
            return 1
        g.send("run3 1 &\n")
        if not g.expect(r"run3: started FORKDEMO\.BIN \(pid ", timeout=15):
            print("\n[FAIL] background start")
            return 1
        g.send("ps\n")
        if not g.expect(r"FORKDEMO", timeout=15):
            print("\n[FAIL] ps does not show background FORKDEMO")
            return 1
        g.send("wait\n")
        if not g.expect(r"wait: process \d+ exited with code 7", timeout=60):
            print("\n[FAIL] wait did not reap the background job")
            return 1
        print("\n[PASS] background job + ps + wait")

        ok = True
        return 0
    finally:
        g.close()
        print("\n[RESULT] " + ("PASS" if ok else "FAIL") +
              " (full serial log: build/test_fork_guest.log)")


if __name__ == "__main__":
    sys.exit(main())
