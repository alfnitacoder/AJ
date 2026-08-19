import sys
import secrets

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_prime(n, k=5):
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        # random odd number
        n = secrets.randbits(bits)
        if n % 2 == 0: 
            n |= 1
        if is_prime(n, 10):
            return n

def generate_keypair(bits):
    # e = 65537
    e = 65537
    
    # We need p and q such that (p-1)(q-1) is relatively prime to e
    print(f"Generating {bits}-bit primes...")
    while True:
        p = generate_prime(bits // 2)
        if (p - 1) % e != 0:
            break
            
    while True:
        q = generate_prime(bits // 2)
        if q != p and (q - 1) % e != 0:
            break
            
    n = p * q
    phi = (p - 1) * (q - 1)
    
    d = modinv(e, phi)
    
    return ((e, n), (d, n))

def print_c_array(name, val, size=256):
    b = val.to_bytes(size, 'big')
    print(f"  static const uint8_t {name}[{size}] = {{")
    for i in range(0, size, 12):
        chunk = b[i:i+12]
        hex_chunk = ", ".join([f"0x{x:02x}" for x in chunk])
        comma = "," if i + 12 < size else "};"
        print(f"      {hex_chunk}{comma}")
    print()

if __name__ == "__main__":
    print("Generating RSA-2048 Key Pair...")
    public, private = generate_keypair(2048)
    e, n = public
    d = private[0]
    
    print("\n/* Generated RSA Key */")
    print_c_array("key_n", n)
    print_c_array("key_e", e)
    print_c_array("key_d", d)
