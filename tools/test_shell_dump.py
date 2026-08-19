import subprocess
import time
import sys

def test_shell_dump():
    print("Building and starting OS in console mode (DUMP)...")
    cmd = ["make", "run-console"]
    
    print("Cleaning previous build...")
    subprocess.run(["make", "clean"], check=True)
    
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Merge stderr into stdout
        text=True,
        bufsize=0
    )

    try:
        # Refactored to use a reader thread for simplicity in this constrained env
        import threading
        def reader():
            while True:
                char = process.stdout.read(1)
                if not char:
                    break
                sys.stdout.write(char)
                sys.stdout.flush()
        
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        
        start_time = time.time()
        cmds = [
            ("dhcp\n", 4),
            ("dns web.simmons.edu\n", 2),
            ("http_get 69.43.111.82 web.simmons.edu /\n", 8),
            ("uptime\n", 1)
        ]
        
        # Main thread handles sending
        time.sleep(10) # Wait for build/boot and E1000 init
        for c, delay in cmds:
            print(f"\n[TEST] Sending: {c.strip()}")
            process.stdin.write(c)
            process.stdin.flush()
            time.sleep(delay)
            
        time.sleep(2) # Wait for last output

    except Exception as e:
        print(f"Error: {e}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except:
            process.kill()

if __name__ == "__main__":
    test_shell_dump()
