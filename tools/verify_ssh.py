import socket
import struct
import sys
import time

# SSH Message Types
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_GEX_REQUEST_OLD = 30
SSH_MSG_KEXDH_GEX_GROUP = 31
SSH_MSG_KEXDH_GEX_INIT = 32
SSH_MSG_KEXDH_GEX_REPLY = 33
SSH_MSG_KEXDH_GEX_REQUEST = 34

def log(msg):
    print(f"[SSH-VERIFY] {msg}")

def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("Socket closed prematurely")
        data += chunk
    return data

def make_packet(msg_type, payload):
    # packet_length (4) + padding_length (1) + payload + padding
    # packet_length = length of (padding_length + payload + padding)
    
    # Calculate padding
    # Min padding is 4 bytes. Total packet length (including length field) must be multiple of 8
    # Actually RFC 4253: packet_length does not include itself.
    # Total stream size = 4 + packet_length
    # (4 + packet_length) % 8 == 0
    
    base_len = 1 + 1 + len(payload) # padding_length(1) + type(1) + payload
    padding_len = 8 - ((4 + base_len) % 8)
    if padding_len < 4:
        padding_len += 8
        
    packet_len = base_len + padding_len - 1 # -1 because base_len includes type which is part of payload in generic sense but separated here?
    # Wait, payload arg usually doesn't include type. Let's include type in payload for simplicity
    
    # Structure:
    # uint32 packet_length
    # byte   padding_length
    # byte[n1]  payload; n1 = packet_length - padding_length - 1
    # byte[n2]  random padding; n2 = padding_length
    
    content = bytes([msg_type]) + payload
    content_len = len(content)
    
    # 4 (len) + 1 (padlen) + content + pad
    current_size = 4 + 1 + content_len
    padding_len = 8 - (current_size % 8)
    if padding_len < 4:
        padding_len += 8
        
    packet_len = 1 + content_len + padding_len
    
    pkt = struct.pack(">I", packet_len)
    pkt += bytes([padding_len])
    pkt += content
    pkt += bytes([0] * padding_len)
    
    return pkt

def read_packet(sock):
    # Read length
    raw_len = read_exact(sock, 4)
    packet_len = struct.unpack(">I", raw_len)[0]
    
    # Read padding length
    pad_len = read_exact(sock, 1)[0]
    
    # Read payload + padding
    # payload_len = packet_len - 1 - pad_len
    remaining = packet_len - 1
    data = read_exact(sock, remaining)
    
    payload = data[:-pad_len]
    msg_type = payload[0]
    msg_data = payload[1:]
    
    return msg_type, msg_data

def run_test():
    host = "127.0.0.1"
    port = 2222
    
    try:
        log(f"Connecting to {host}:{port}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)
        s.connect((host, port))
        
        # 1. Version Exchange
        server_ver = b""
        while b"\n" not in server_ver:
            server_ver += s.recv(1)
        log(f"Server version: {server_ver.strip().decode()}")
        
        client_ver = b"SSH-2.0-TestClient\r\n"
        s.sendall(client_ver)
        log("Sent client version")
        
        # 2. Receive KEXINIT
        msg_type, payload = read_packet(s)
        if msg_type != SSH_MSG_KEXINIT:
            log(f"ERROR: Expected KEXINIT (20), got {msg_type}")
            return False
        log("Received KEXINIT")
        
        # 3. Send KEXINIT
        # Construct dummy KEXINIT payload (mostly random/zeros + algos)
        kex_payload = bytes([0]*16) # Cookie
        # Algos... we can cheat and just send what we know the server supports or garbage (server might ignore if we are verifying server behavior up to GEX)
        # But to be safe, let's copy a minimal valid KEXINIT
        
        # We need to send a valid-ish KEXINIT structure so the server parses it
        # Cookie(16), kex_algs(len+str), ...
        
        def write_string(s):
            return struct.pack(">I", len(s)) + s.encode()
            
        k = kex_payload
        k += write_string("diffie-hellman-group-exchange-sha256") # kex
        k += write_string("ssh-rsa") # host key
        k += write_string("aes128-ctr") # enc c2s
        k += write_string("aes128-ctr") # enc s2c
        k += write_string("hmac-sha2-256") # mac c2s
        k += write_string("hmac-sha2-256") # mac s2c
        k += write_string("none") # comp c2s
        k += write_string("none") # comp s2c
        k += write_string("") # lang c2s
        k += write_string("") # lang s2c
        k += bytes([0]) # first kex packet follows
        k += struct.pack(">I", 0) # reserved
        
        s.sendall(make_packet(SSH_MSG_KEXINIT, k))
        log("Sent KEXINIT")
        
        # 4. GEX Request
        # [min][preferred][max]
        gex_req = struct.pack(">III", 2048, 2048, 8192)
        s.sendall(make_packet(SSH_MSG_KEXDH_GEX_REQUEST, gex_req))
        log("Sent GEX_REQUEST")
        
        # 5. Receive GEX Group (31)
        msg_type, payload = read_packet(s)
        if msg_type != SSH_MSG_KEXDH_GEX_GROUP:
            log(f"ERROR: Expected GEX_GROUP (31), got {msg_type}")
            return False
        log("Received GEX_GROUP")
        
        # 6. Send GEX Init (32)
        # Send e (client public key)
        # e = g^x mod p. We'll just send a dummy e (mpint)
        # e = 12345
        e_val = b"\x30\x39" # dummy value
        e_mpint = struct.pack(">I", len(e_val)) + e_val
        s.sendall(make_packet(SSH_MSG_KEXDH_GEX_INIT, e_mpint))
        log("Sent GEX_INIT")
        
        # 7. Receive GEX Reply (33) -- THIS IS THE CRITICAL STEP
        # If this parses correctly, our crypto fix worked (it didn't crash parsing signature)
        log("Waiting for GEX_REPLY...")
        msg_type, payload = read_packet(s)
        if msg_type != SSH_MSG_KEXDH_GEX_REPLY:
            log(f"ERROR: Expected GEX_REPLY (33), got {msg_type}")
            return False
        log("Received GEX_REPLY (Success!)")
        
        # 8. Send NEWKEYS (21)
        s.sendall(make_packet(SSH_MSG_NEWKEYS, b""))
        log("Sent NEWKEYS")
        
        # 9. Receive NEWKEYS (21)
        # Server sends NEWKEYS after sending GEX_REPLY
        msg_type, payload = read_packet(s)
        if msg_type != SSH_MSG_NEWKEYS:
             # It's possible server hasn't sent it yet or we read out of order?
             # Actually server sends GEX_REPLY then NEWKEYS immediately.
            log(f"ERROR: Expected NEWKEYS (21), got {msg_type}")
            return False
        log("Received NEWKEYS")
        
        log("[SUCCESS] Full Key Exchange Handshake Completed!")
        return True
        
    except Exception as e:
        log(f"Test failed with exception: {e}")
        return False
    finally:
        s.close()

if __name__ == "__main__":
    if run_test():
        sys.exit(0)
    else:
        sys.exit(1)
