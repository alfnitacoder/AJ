#!/usr/bin/env python3
"""Test editor with a new file that doesn't exist"""
import subprocess
import time
import sys
import signal
import os

def main():
    print("=" * 70)
    print("EDITOR TEST - New File Creation")
    print("=" * 70)
    
    # Ensure data.img exists
    if not os.path.exists("build/data.img"):
        print("[SETUP] Creating data.img...")
        subprocess.run(["python3", "tools/mkfat12.py", "build/data.img"], check=True)
    
    # Start QEMU
    print("\n[STARTING] QEMU...")
    cmd = ["make", "run-console"]
    
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=0
    )
    
    try:
        def send(cmd_str, wait=0.5):
            if process.stdin:
                process.stdin.write(cmd_str)
                process.stdin.flush()
            time.sleep(wait)
        
        # Wait for boot and login
        print("[WAIT] Booting (10 seconds)...")
        time.sleep(10)
        send("\n", 0.2)

        # Handle login with default credentials
        print("[LOGIN] Sending default credentials (user/pass)...")
        send("user\n", 0.5)
        send("pass\n", 1.0)
        
        # Test with a unique filename that doesn't exist
        unique_name = "newfile_12345.txt"
        print(f"\n[TEST] Opening editor with NEW file: {unique_name}")
        send(f"edit {unique_name}\n", 2.0)
        
        # Type text
        print("[TEST] Typing text...")
        send("This is a new file!\n", 1.0)
        send("Created by editor test.\n", 1.0)
        
        # Save (Ctrl+O = 0x0F)
        print("[TEST] Saving (Ctrl+O)...")
        send("\x0f", 1.5)
        
        # Exit (Ctrl+X = 0x18)
        print("[TEST] Exiting (Ctrl+X)...")
        send("\x18", 1.5)
        
        # Verify
        print("[VERIFY] Checking file...")
        send(f"ls\n", 1.0)
        send(f"cat {unique_name}\n", 1.0)
        
        # Read output
        print("\n" + "=" * 70)
        print("OUTPUT:")
        print("=" * 70)
        time.sleep(3)
        
        # Read what we can
        output = ""
        for _ in range(100):
            try:
                char = process.stdout.read(1)
                if char:
                    output += char
                    sys.stdout.write(char)
                    sys.stdout.flush()
                else:
                    time.sleep(0.05)
            except:
                break
        
        print("\n" + "=" * 70)
        
        # Check results
        if "Editor started new file" in output:
            print("✓ SUCCESS: Editor created new file!")
        elif "Editor loaded" in output:
            print("⚠ WARNING: Editor loaded existing file (may have existed)")
        
        if f"[Slot] Saved '{unique_name}" in output or f"Saved '{unique_name}" in output:
            print("✓ SUCCESS: File was saved!")
        
        if unique_name.upper() in output or unique_name in output:
            print("✓ SUCCESS: File found in directory listing!")
        
        if "This is a new file" in output:
            print("✓ SUCCESS: File contents verified!")
        
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[STOPPING] QEMU...")
        if process:
            process.terminate()
            try:
                process.wait(timeout=2)
            except:
                process.kill()

if __name__ == "__main__":
    main()
