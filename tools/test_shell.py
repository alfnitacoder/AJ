import subprocess
import time
import sys
import re

def test_shell():
    print("Building and starting OS in console mode...")
    # We use stdbuf to disable buffering if possible, though qemu -nographic usually behaves well.
    # forcing make run-console
    cmd = ["make", "run-console"]
    
    print("Cleaning previous build...")
    subprocess.run(["make", "clean"], check=True)
    
    # Start the process
    # Use Piped IO. 
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=0  # Unbuffered
    )

    try:
        # Helper to read until a prompt or timeout
        def read_until(pattern, timeout=5):
            start = time.time()
            buffer = ""
            while time.time() - start < timeout:
                char = process.stdout.read(1)
                if char:
                    buffer += char
                    sys.stdout.write(char) # Echo to our log
                    if re.search(pattern, buffer, re.DOTALL):
                        return True, buffer
                else:
                    time.sleep(0.01)
            return False, buffer

        # Helper to send a command
        def send_cmd(cmd_str):
            print(f"\n[TEST] Sending: {cmd_str.strip()}")
            process.stdin.write(cmd_str)
            process.stdin.flush()

        # 1. Wait for login prompt and log in
        print("\n[TEST] Waiting for login prompt...")
        found, output = read_until(r"Username:", timeout=15)
        if not found:
            print(f"\n[FAIL] Did not see Username prompt. Output:\n{output}")
            return False
        print("\n[PASS] Username prompt found, sending credentials.")

        # Default AJOS user created by PASSWD logic: user / pass
        send_cmd("user\n")
        found, output = read_until(r"Password:", timeout=5)
        if not found:
            print(f"\n[FAIL] Did not see Password prompt after Username. Output:\n{output}")
            return False

        send_cmd("pass\n")
        # Now wait for the shell prompt, which looks like: "AJOS [user]:/path> "
        found, output = read_until(r"AJOS.*> ", timeout=10)
        if not found:
            print(f"\n[FAIL] Did not see shell prompt after login. Output:\n{output}")
            return False
        print("\n[PASS] Login successful, shell prompt found.")

        # 2. Test 'help'
        send_cmd("help\n")
        found, output = read_until(r"Commands:", timeout=3)
        if found:
            print("\n[PASS] 'help' command works.")
        else:
            print("\n[FAIL] 'help' command failed.")
            return False

        # 3. Test 'echo'
        unique_str = "testing_echo_123"
        send_cmd(f"echo {unique_str}\n")
        found, output = read_until(unique_str, timeout=3)
        if found:
            print("\n[PASS] 'echo' command works.")
        else:
            print("\n[FAIL] 'echo' command failed.")
            return False
            
        # 4. Test 'uptime'
        send_cmd("uptime\n")
        found, output = read_until(r"uptime_ms=", timeout=3)
        if found:
            print("\n[PASS] 'uptime' command works.")
        else:
            print("\n[FAIL] 'uptime' command failed.")
            return False

        # 5. Test 'ticks'
        send_cmd("ticks\n")
        found, output = read_until(r"ticks=", timeout=3)
        if found:
            print("\n[PASS] 'ticks' command works.")
        else:
            print("\n[FAIL] 'ticks' command failed.")
            return False

        # 6. Test SSH daemon status
        send_cmd("sshd status\n")
        found, output = read_until(r"[SSHD] Server status:", timeout=3)
        if found and "RUNNING" in output:
            print("\n[PASS] SSH daemon is running and reports status correctly.")
        else:
            print("\n[FAIL] SSH daemon status check failed.")
            print("Output:\n", output)
            return False

        print("\n[SUCCESS] All checked commands (including sshd status) passed.")
        return True

    except Exception as e:
        print(f"\n[ERROR] Exception: {e}")
        return False
    finally:
        print("\n[TEST] Terminating QEMU...")
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()

if __name__ == "__main__":
    success = test_shell()
    if not success:
        sys.exit(1)
