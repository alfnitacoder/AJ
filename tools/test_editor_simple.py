#!/usr/bin/env python3
"""Simple editor test - runs QEMU and tests edit command"""
import subprocess
import time
import sys
import signal
import os

qemu_process = None

def signal_handler(sig, frame):
    global qemu_process
    if qemu_process:
        qemu_process.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    global qemu_process
    
    print("=" * 70)
    print("EDITOR TEST - Testing 'edit' command for new file creation")
    print("=" * 70)
    print("\nThis will:")
    print("  1. Start QEMU")
    print("  2. Wait for boot")
    print("  3. Run: edit test.txt")
    print("  4. Type: Hello World")
    print("  5. Save: Ctrl+O")
    print("  6. Exit: Ctrl+X")
    print("  7. Verify: ls and cat test.txt")
    print("\nStarting in 2 seconds...\n")
    time.sleep(2)
    
    # Ensure data.img exists
    if not os.path.exists("build/data.img"):
        print("[SETUP] Creating data.img...")
        subprocess.run(["python3", "tools/mkfat12.py", "build/data.img"], check=True)
    
    # Start QEMU
    print("[1/7] Starting QEMU...")
    cmd = ["make", "run-console"]
    
    qemu_process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=0
    )
    
    try:
        def send(cmd_str, wait=0.3):
            if qemu_process.stdin:
                qemu_process.stdin.write(cmd_str)
                qemu_process.stdin.flush()
            time.sleep(wait)
        
        # Wait for boot
        print("[2/7] Waiting for boot (8 seconds)...")
        time.sleep(8)
        send("\n", 0.2)
        
        # Send edit command
        print("[3/7] Opening editor: edit test.txt")
        send("edit test.txt\n", 2.0)
        
        # Type text
        print("[4/7] Typing: Hello World")
        send("Hello World\n", 1.0)
        
        # Save (Ctrl+O = 0x0F)
        print("[5/7] Saving file (Ctrl+O)...")
        send("\x0f", 1.5)
        
        # Exit (Ctrl+X = 0x18)
        print("[6/7] Exiting editor (Ctrl+X)...")
        send("\x18", 1.5)
        
        # Verify
        print("[7/7] Verifying file creation...")
        send("ls\n", 1.0)
        send("cat test.txt\n", 1.0)
        
        # Read final output
        print("\n" + "=" * 70)
        print("FINAL OUTPUT (last 2000 chars):")
        print("=" * 70)
        time.sleep(2)
        
        # Try to read remaining output
        output_lines = []
        for _ in range(50):  # Try reading for a bit
            try:
                line = qemu_process.stdout.readline()
                if line:
                    output_lines.append(line)
                    sys.stdout.write(line)
                    sys.stdout.flush()
                else:
                    time.sleep(0.1)
            except:
                break
        
        print("\n" + "=" * 70)
        print("Test sequence completed!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]")
    except Exception as e:
        print(f"\n[ERROR] {e}")
    finally:
        print("\n[TEST] Stopping QEMU...")
        if qemu_process:
            qemu_process.terminate()
            try:
                qemu_process.wait(timeout=2)
            except:
                qemu_process.kill()

if __name__ == "__main__":
    main()
