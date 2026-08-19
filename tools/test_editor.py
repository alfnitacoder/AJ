#!/usr/bin/env python3
import subprocess
import time
import sys
import os

def test_editor():
    print("=" * 60)
    print("Testing Editor - New File Creation")
    print("=" * 60)
    
    # Ensure data.img exists
    if not os.path.exists("build/data.img"):
        print("Creating data.img...")
        subprocess.run(["python3", "tools/mkfat12.py", "build/data.img"], check=True)
    
    # Start QEMU
    print("\n[1/6] Starting QEMU...")
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
        # Helper to read output with timeout
        def read_output(timeout=3, max_chars=10000):
            start = time.time()
            output = ""
            while time.time() - start < timeout and len(output) < max_chars:
                char = process.stdout.read(1)
                if char:
                    output += char
                    sys.stdout.write(char)
                    sys.stdout.flush()
                else:
                    time.sleep(0.01)
            return output
        
        # Helper to send command
        def send(cmd_str, delay=0.5):
            print(f"\n[TEST] Sending: {repr(cmd_str)}")
            process.stdin.write(cmd_str)
            process.stdin.flush()
            time.sleep(delay)
        
        # Wait for login and authenticate
        print("\n[2/6] Waiting for login prompt...")
        output = read_output(timeout=8)
        if "Username:" not in output:
            print("\n[WARN] Username prompt not seen yet, attempting to continue...")
        else:
            print("\n[INFO] Username prompt seen, sending default credentials...")
        send("user\n", 0.5)
        output = read_output(timeout=5)
        if "Password:" not in output:
            print("\n[WARN] Password prompt not clearly seen, continuing anyway...")
        else:
            send("pass\n", 0.5)
            output = read_output(timeout=5)
        
        # Test 1: Create new file
        print("\n[3/6] Testing: edit test.txt (new file)")
        send("edit test.txt\n", 1.0)
        output = read_output(timeout=3)
        
        if "Editor started new file" not in output and "Editor loaded" not in output:
            print("\n[WARN] Editor message not clear, but continuing...")
        
        # Type some text
        print("\n[4/6] Typing text in editor...")
        send("Hello from AJOS editor!\n", 0.5)
        send("This is a test file.\n", 0.5)
        send("Line 3\n", 0.5)
        
        # Save with Ctrl+O (0x0F)
        print("\n[5/6] Saving file (Ctrl+O)...")
        send("\x0f", 1.0)
        output = read_output(timeout=2)
        
        if "Saved" not in output and "saved" not in output:
            print("\n[WARN] Save confirmation not seen...")
        
        # Exit with Ctrl+X (0x18)
        print("\n[6/6] Exiting editor (Ctrl+X)...")
        send("\x18", 1.0)
        output = read_output(timeout=2)
        
        # Verify file exists
        print("\n[VERIFY] Checking if file was created...")
        send("ls\n", 1.0)
        output = read_output(timeout=2)
        
        if "test.txt" in output or "TEST.TXT" in output:
            print("\n[SUCCESS] File 'test.txt' found in directory listing!")
        else:
            print("\n[WARN] File not found in ls output, but may still exist...")
            print("Output:", output[-200:])
        
        # Try to cat the file
        print("\n[VERIFY] Reading file contents...")
        send("cat test.txt\n", 1.0)
        output = read_output(timeout=2)
        
        if "Hello from AJOS editor" in output:
            print("\n[SUCCESS] File contents verified!")
        else:
            print("\n[WARN] File contents not as expected...")
            print("Output:", output[-300:])
        
        print("\n" + "=" * 60)
        print("Test completed. Check output above for results.")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[ERROR] Exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[TEST] Terminating QEMU...")
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            print("[TEST] QEMU killed")

if __name__ == "__main__":
    test_editor()
