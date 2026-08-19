import serial
import time
import subprocess
import os

def run_qemu_test():
    # Start QEMU in the background
    qemu_cmd = ["make", "run-console"]
    proc = subprocess.Popen(qemu_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    time.sleep(10) # Wait for boot

    # Interaction loop
    def send(cmd):
        proc.stdin.write(cmd)
        proc.stdin.flush()
        time.sleep(1)

    print("--- Starting Test ---")
    send("edit test.txt\n")
    time.sleep(2)
    send("Hello from editor!\n")
    time.sleep(1)
    # Send Ctrl+O (Save)
    send("\x0f")
    time.sleep(1)
    # Send Ctrl+X (Exit)
    send("\x18")
    time.sleep(2)
    send("files\n")
    time.sleep(2)

    # Read output
    output = ""
    try:
        # Stop QEMU
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=5)
        output = stdout
    except:
        proc.kill()
    
    print("--- QEMU Output ---")
    print(output)

if __name__ == "__main__":
    run_qemu_test()
