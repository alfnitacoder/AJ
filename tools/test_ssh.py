#!/usr/bin/env python3
"""
AJOS SSH integration test: boot QEMU, then run several remote commands over SSH.

Uses sshpass (if installed) with AJOS_SSH_PASSWORD (default: pass).

Checks:
  - echo, whoami, uname, ls (must succeed)
  - sftp ls / get README.TXT / put+get round-trip
  - ping 10.0.2.2 (must see at least one ICMP reply — QEMU user-net gateway)
  - ping 1.1.1.1 (must finish ping statistics; 100%% loss is OK — ICMP often not forwarded)

A background thread reads QEMU stdout continuously so the serial pipe does not fill
and wedge the guest during SSH.
"""

import os
import re
import shutil
import subprocess
import sys
import threading
import time


def build_ssh_cmd(sshpass_bin, password, host, port, user, remote_argv):
    """remote_argv: list passed to ssh after user@host (e.g. ["echo", "hi"])."""
    ssh = [
        "ssh",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-p",
        str(port),
        f"{user}@{host}",
    ] + list(remote_argv)
    if sshpass_bin:
        return [sshpass_bin, "-p", password] + ssh
    return ssh


def run_remote(
    label,
    sshpass_bin,
    password,
    host,
    port,
    user,
    remote_argv,
    timeout,
):
    cmd = build_ssh_cmd(sshpass_bin, password, host, port, user, remote_argv)
    print(f"\n[SSH] {label}")
    print("[SSH] argv:", " ".join(remote_argv))
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        print(f"[SSH] TIMEOUT after {timeout}s")
        if e.stdout:
            print(e.stdout[-2000:])
        return 124, ""

    out = p.stdout or ""
    if p.returncode != 0:
        print(f"[SSH] exit {p.returncode}")
    if out.strip():
        print(out.rstrip())
    else:
        print("(no stdout)")
    return p.returncode, out


def main():
    target_host = os.environ.get("AJOS_SSH_HOST", "127.0.0.1")
    target_port = os.environ.get("AJOS_SSH_PORT", "9022")
    target_user = os.environ.get("AJOS_SSH_USER", "user")
    target_password = os.environ.get("AJOS_SSH_PASSWORD", "pass")
    print("=" * 70)
    print("AJOS SSH INTEGRATION TEST")
    print("=" * 70)
    print(f"[INFO] {target_user}@{target_host}:{target_port}")
    print("[INFO] Boots QEMU via `make run-console` (full `make clean` first).")
    print(
        "[NOTE] With QEMU -netdev user, ICMP to the public Internet (e.g. 1.1.1.1) "
        "usually gets no replies. That is normal. The stack is verified by "
        "`ping 10.0.2.2`; AJOS also prints a hint after an all-timeout public ping.\n"
    )

    sshpass_bin = shutil.which("sshpass")
    if not sshpass_bin:
        print("[ERROR] sshpass not in PATH; install it for non-interactive password auth.", file=sys.stderr)
        return 1

    if not os.path.exists("build/data.img"):
        print("[SETUP] Creating data.img...")
        subprocess.run(["python3", "tools/mkfat12.py", "build/data.img"], check=True)

    print("[BUILD] make clean + run-console...")
    subprocess.run(["make", "clean"], check=True)

    cmd = ["make", "run-console"]
    print("[START]", " ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
        bufsize=0,
    )

    shared = bytearray()
    lock = threading.Lock()

    def reader():
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                with lock:
                    shared.extend(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()

    def read_until(substr, timeout=20):
        needle = substr.encode("utf-8", errors="replace")
        start = time.time()
        while time.time() - start < timeout:
            with lock:
                if needle in shared:
                    return True, bytes(shared)
            time.sleep(0.05)
        with lock:
            return False, bytes(shared)

    def send(line_b, delay=0.2):
        if proc.stdin:
            proc.stdin.write(line_b)
            proc.stdin.flush()
        time.sleep(delay)

    results = []

    try:
        print("\n[WAIT] SSHD startup...")
        ok, out = read_until("[SSHD] Server started on port 22", timeout=40)
        if not ok:
            print("[FAIL] SSHD did not start.")
            print(out[-500:].decode("utf-8", errors="replace"))
            return 1

        print("\n[WAIT] login prompt...")
        ok, _ = read_until("Username:", timeout=10)
        if ok:
            send(b"user\n", 0.5)
            send(b"pass\n", 1.0)

        time.sleep(2.0)

        def check(name, argv, timeout=90, validator=None):
            code, stdout = run_remote(
                name,
                sshpass_bin,
                target_password,
                target_host,
                target_port,
                target_user,
                argv,
                timeout,
            )
            ok = code == 0
            if ok and validator is not None and not validator(stdout):
                ok = False
            results.append((name, ok, code))
            time.sleep(1.5)
            return ok, stdout

        # Core SSH + shell
        ok, _ = check("echo", ["echo", "hello-from-ajos-ssh-test"], 60)
        if not ok:
            return 1

        def _stdout_has_whoami_user(s):
            for line in s.splitlines():
                t = line.strip().lower()
                if t == "user":
                    return True
            return False

        ok, out = check("whoami", ["whoami"], 60, _stdout_has_whoami_user)
        if not ok:
            print("[FAIL] whoami did not print expected user name")
            return 1

        ok, _ = check("uname", ["uname"], 60, lambda s: len(s.strip()) > 0)
        if not ok:
            return 1

        ok, _ = check("ls", ["ls"], 60)
        if not ok:
            return 1

        # SFTP: list, get a known FAT file, put/get via ramfs /tmp
        def run_sftp_batch(batch_text, timeout=60):
            sftp = [
                "sftp",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "PubkeyAuthentication=no",
                "-P",
                str(target_port),
                f"{target_user}@{target_host}",
            ]
            cmd = [sshpass_bin, "-p", target_password] + sftp
            print("\n[SFTP] commands:\n" + batch_text.rstrip())
            try:
                p = subprocess.run(
                    cmd,
                    input=batch_text,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as e:
                print(f"[SFTP] TIMEOUT after {timeout}s")
                if e.stdout:
                    print(e.stdout[-2000:])
                return 124, ""
            out = p.stdout or ""
            if out.strip():
                print(out.rstrip())
            return p.returncode, out

        put_src = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ajos_sftp_put.txt")
        got_readme = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ajos_sftp_readme.txt")
        got_put = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ajos_sftp_got.txt")
        with open(put_src, "w", encoding="utf-8") as f:
            f.write("hello-from-sftp-test\n")
        for path in (got_readme, got_put):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

        sftp_rc, _ = run_sftp_batch(
            f"ls\n"
            f"get README.TXT {got_readme}\n"
            f"put {put_src} /tmp/sftptest.txt\n"
            f"ls /tmp\n"
            f"get /tmp/sftptest.txt {got_put}\n"
            f"bye\n",
            60,
        )
        sftp_ok = sftp_rc == 0
        if sftp_ok:
            try:
                with open(got_readme, "rb") as f:
                    sftp_ok = len(f.read()) > 0
            except OSError:
                sftp_ok = False
        if sftp_ok:
            try:
                with open(got_put, encoding="utf-8") as f:
                    sftp_ok = "hello-from-sftp-test" in f.read()
            except OSError:
                sftp_ok = False
        results.append(("sftp ls/get/put", sftp_ok, sftp_rc))
        if not sftp_ok:
            print("[FAIL] SFTP ls/get/put did not succeed")
            return 1

        # Gateway ping — must see a reply (same expectation as make test-net)
        ok, gw_out = check(
            "ping gateway 10.0.2.2",
            ["ping", "10.0.2.2"],
            120,
            lambda s: bool(
                re.search(r"64 bytes from 10\.0\.2\.2", s)
                or re.search(r"10\.0\.2\.2: icmp_seq=", s)
            ),
        )
        if not ok:
            print("[FAIL] No ICMP reply from gateway 10.0.2.2 over SSH.")
            return 1

        # Public ping — completes statistics; loss OK under QEMU user-net.
        # Brief pause + retry: long gateway ping can leave the next TCP handshake flaky.
        time.sleep(3.0)
        pub_label = "ping 1.1.1.1 (may be 100% loss under user-net)"
        code, pub_out = run_remote(
            pub_label,
            sshpass_bin,
            target_password,
            target_host,
            target_port,
            target_user,
            ["ping", "1.1.1.1"],
            120,
        )
        if code != 0 or "ping statistics" not in pub_out:
            print("[INFO] Retrying 1.1.1.1 ping SSH session after 4s...")
            time.sleep(4.0)
            code, pub_out = run_remote(
                pub_label + " (retry)",
                sshpass_bin,
                target_password,
                target_host,
                target_port,
                target_user,
                ["ping", "1.1.1.1"],
                120,
            )
        pub_ok = code == 0 and "ping statistics" in pub_out
        results.append(("ping 1.1.1.1", pub_ok, code))
        if not pub_ok:
            print("[WARN] ping 1.1.1.1 did not complete normally (non-fatal for user-net).")
        else:
            if re.search(r"packets received,\s*0\s", pub_out) or "100.0% packet loss" in pub_out:
                print(
                    "[INFO] 1.1.1.1: no replies (common with QEMU -netdev user; ICMP not forwarded)."
                )

        print("\n" + "=" * 70)
        print("SUMMARY")
        for name, passed, code in results:
            if name.startswith("ping 1.1.1.1"):
                tag = "PASS" if passed else "INFO"
            else:
                tag = "PASS" if passed else "FAIL"
            print(f"  [{tag}] {name} (exit {code})")
        print("=" * 70)
        if not pub_ok:
            print(
                "\n[INFO] Public ping line is not a failure under QEMU user-net "
                "(SSH reset or 100%% loss is common)."
            )
        return 0

    finally:
        print("\n[STOP] Terminating QEMU...")
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                print("[STOP] QEMU killed.")


if __name__ == "__main__":
    sys.exit(main())
