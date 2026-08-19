#!/usr/bin/env python3
import hashlib
import os
import socket
import struct
import sys

# SSH message numbers (RFC 4253 / RFC 4419)
SSH_MSG_KEXINIT = 20
SSH_MSG_KEXDH_GEX_REQUEST = 34
SSH_MSG_KEXDH_GEX_GROUP = 31
SSH_MSG_KEXDH_GEX_INIT = 32
SSH_MSG_KEXDH_GEX_REPLY = 33


def read_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("socket closed")
        out += chunk
    return out


def ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def ssh_u32(x: int) -> bytes:
    return struct.pack(">I", x & 0xFFFFFFFF)


def mpint_from_int(x: int) -> bytes:
    if x == 0:
        return b"\x00\x00\x00\x01\x00"
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return struct.pack(">I", len(b)) + b


def mpint_to_int(mp: bytes) -> int:
    if len(mp) < 4:
        raise ValueError("mpint too short")
    l = struct.unpack(">I", mp[:4])[0]
    if len(mp) != 4 + l:
        raise ValueError("mpint length mismatch")
    if l == 0:
        return 0
    v = mp[4:]
    # mpint is two's complement; for our use (DH/RSA), it should always be non-negative.
    if v and v[0] == 0x00:
        v = v[1:]
    return int.from_bytes(v, "big") if v else 0


def make_packet(msg_type: int, msg_payload_without_type: bytes) -> bytes:
    payload = bytes([msg_type]) + msg_payload_without_type
    # packet_length excludes itself; packet = len(4) + padlen(1) + payload + padding
    padlen = 4
    while (4 + 1 + len(payload) + padlen) % 8 != 0 or padlen < 4:
        padlen += 1
    packet_length = 1 + len(payload) + padlen
    return struct.pack(">I", packet_length) + bytes([padlen]) + payload + (b"\x00" * padlen)


def read_packet(sock: socket.socket):
    packet_length = struct.unpack(">I", read_exact(sock, 4))[0]
    padlen = read_exact(sock, 1)[0]
    data = read_exact(sock, packet_length - 1)
    payload = data[:-padlen]
    msg_type = payload[0]
    msg_data = payload[1:]
    return msg_type, msg_data, payload  # payload includes msg_type


def parse_ssh_string(buf: bytes, off: int):
    if off + 4 > len(buf):
        raise ValueError("string length OOB")
    l = struct.unpack(">I", buf[off : off + 4])[0]
    off += 4
    if off + l > len(buf):
        raise ValueError("string data OOB")
    return buf[off : off + l], off + l


def parse_mpint(buf: bytes, off: int):
    if off + 4 > len(buf):
        raise ValueError("mpint length OOB")
    l = struct.unpack(">I", buf[off : off + 4])[0]
    if off + 4 + l > len(buf):
        raise ValueError("mpint data OOB")
    return buf[off : off + 4 + l], off + 4 + l


def parse_hostkey_ssh_rsa(k_s_string: bytes):
    # k_s_string is SSH string on-wire: u32 len + keyblob
    if len(k_s_string) < 4:
        raise ValueError("K_S too short")
    keyblob_len = struct.unpack(">I", k_s_string[:4])[0]
    keyblob = k_s_string[4 : 4 + keyblob_len]
    off = 0
    keytype, off = parse_ssh_string(keyblob, off)
    if keytype != b"ssh-rsa":
        raise ValueError(f"unexpected key type: {keytype!r}")
    e_mp, off = parse_mpint(keyblob, off)
    n_mp, off = parse_mpint(keyblob, off)
    e = mpint_to_int(e_mp)
    n = mpint_to_int(n_mp)
    return n, e


SHA512_DIGESTINFO_PREFIX = bytes.fromhex(
    "3051300d060960864801650304020305000440"
)
SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
SHA1_DIGESTINFO_PREFIX = bytes.fromhex(
    "3021300906052b0e03021a05000414"
)


def rsa_verify_pkcs1_v15_sha512_over_H(n: int, e: int, H: bytes, sig: bytes) -> bool:
    if len(sig) == 0:
        return False
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    h = hashlib.sha512(H).digest()
    t = SHA512_DIGESTINFO_PREFIX + h
    if len(t) > k - 11:
        return False
    ps = b"\xff" * (k - 3 - len(t))
    em = b"\x00\x01" + ps + b"\x00" + t
    s = int.from_bytes(sig, "big")
    m = pow(s, e, n).to_bytes(k, "big")
    return m == em


def build_exchange_hash(
    v_c: bytes,
    v_s: bytes,
    i_c_payload: bytes,
    i_s_payload: bytes,
    k_s_string_onwire: bytes,
    minbits: int,
    nbits: int,
    maxbits: int,
    p_mpint_onwire: bytes,
    g_mpint_onwire: bytes,
    e_mpint_onwire: bytes,
    f_mpint_onwire: bytes,
    K_mpint_onwire: bytes,
    variant: str,
) -> bytes:
    """
    Variants:
      - "rfc": strings are length-prefixed; K_S and mpints are on-wire already.
      - "no_msgtype": I_C/I_S omit message number byte.
      - "k_s_nolen": hash K_S keyblob without its outer u32 length.
      - "mpint_nolen": hash p,g,e,f,K without their u32 lengths.
    """
    if variant == "no_msgtype":
        i_c_payload = i_c_payload[1:]  # drop msg_type
        i_s_payload = i_s_payload[1:]

    h = hashlib.sha256()
    h.update(ssh_string(v_c))
    h.update(ssh_string(v_s))
    h.update(ssh_string(i_c_payload))
    h.update(ssh_string(i_s_payload))

    if variant == "k_s_nolen":
        # k_s_string_onwire = u32 len + keyblob
        keyblob_len = struct.unpack(">I", k_s_string_onwire[:4])[0]
        h.update(k_s_string_onwire[4 : 4 + keyblob_len])
    else:
        h.update(k_s_string_onwire)

    h.update(ssh_u32(minbits))
    h.update(ssh_u32(nbits))
    h.update(ssh_u32(maxbits))

    if variant == "mpint_nolen":
        for mp in (p_mpint_onwire, g_mpint_onwire, e_mpint_onwire, f_mpint_onwire, K_mpint_onwire):
            l = struct.unpack(">I", mp[:4])[0]
            h.update(mp[4 : 4 + l])
    else:
        h.update(p_mpint_onwire)
        h.update(g_mpint_onwire)
        h.update(e_mpint_onwire)
        h.update(f_mpint_onwire)
        h.update(K_mpint_onwire)

    return h.digest()

def find_matching_H_variant(
    *,
    v_c: bytes,
    v_s: bytes,
    i_c_payload: bytes,
    i_s_payload: bytes,
    k_s_string_onwire: bytes,
    minbits: int,
    nbits: int,
    maxbits: int,
    p_mpint_onwire: bytes,
    g_mpint_onwire: bytes,
    e_mpint_onwire: bytes,
    f_mpint_onwire: bytes,
    K_mpint_onwire: bytes,
    target_sha512: bytes,
):
    def u32be(x: int) -> bytes:
        return struct.pack(">I", x & 0xFFFFFFFF)

    def u32le(x: int) -> bytes:
        return struct.pack("<I", x & 0xFFFFFFFF)

    def drop_len_prefix(b: bytes) -> bytes:
        l = struct.unpack(">I", b[:4])[0]
        return b[4 : 4 + l]

    v_modes = {
        "strip": (v_c, v_s),
        "crlf": (v_c + b"\r\n", v_s + b"\r\n"),
    }
    i_modes = {
        "msgtype": (i_c_payload, i_s_payload),
        "no_msgtype": (i_c_payload[1:], i_s_payload[1:]),
    }
    ks_modes = {
        "onwire": lambda ks: ks,
        "wrapped": lambda ks: ssh_string(ks),
        "keyblob": lambda ks: drop_len_prefix(ks),
    }
    mp_modes = {
        "onwire": lambda mp: mp,
        "wrapped": lambda mp: ssh_string(mp),
        "value": lambda mp: drop_len_prefix(mp),
    }
    u32_modes = {"be": u32be, "le": u32le}

    for v_mode, (vc, vs) in v_modes.items():
        for i_mode, (ic, is_) in i_modes.items():
            for ks_mode, ks_fn in ks_modes.items():
                for mp_mode, mp_fn in mp_modes.items():
                    for u32_mode, u32_fn in u32_modes.items():
                        h = hashlib.sha256()
                        h.update(ssh_string(vc))
                        h.update(ssh_string(vs))
                        h.update(ssh_string(ic))
                        h.update(ssh_string(is_))
                        h.update(ks_fn(k_s_string_onwire))
                        h.update(u32_fn(minbits))
                        h.update(u32_fn(nbits))
                        h.update(u32_fn(maxbits))
                        for mp in (p_mpint_onwire, g_mpint_onwire, e_mpint_onwire, f_mpint_onwire, K_mpint_onwire):
                            h.update(mp_fn(mp))
                        H = h.digest()
                        if hashlib.sha512(H).digest() == target_sha512:
                            return {
                                "v_mode": v_mode,
                                "i_mode": i_mode,
                                "ks_mode": ks_mode,
                                "mp_mode": mp_mode,
                                "u32_mode": u32_mode,
                                "H": H,
                            }
    return None


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2226

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((host, port))

    # Version exchange
    server_ver_line = b""
    while b"\n" not in server_ver_line:
        server_ver_line += s.recv(1)
    v_s = server_ver_line.strip().replace(b"\r", b"")
    v_c = b"SSH-2.0-AJOS-SigCheck"
    s.sendall(v_c + b"\r\n")

    # Receive server KEXINIT
    mt, md, payload_server_kexinit = read_packet(s)
    if mt != SSH_MSG_KEXINIT:
        raise RuntimeError(f"expected KEXINIT, got {mt}")

    # Send client KEXINIT (valid-ish; includes rsa-sha2-512 preference)
    def write_str(txt: str) -> bytes:
        return ssh_string(txt.encode())

    cookie = b"\x00" * 16
    kex = (
        cookie
        + write_str("diffie-hellman-group-exchange-sha256")
        + write_str("rsa-sha2-512,rsa-sha2-256,ssh-rsa")
        + write_str("aes128-ctr")
        + write_str("aes128-ctr")
        + write_str("hmac-sha2-256")
        + write_str("hmac-sha2-256")
        + write_str("none")
        + write_str("none")
        + write_str("")
        + write_str("")
        + b"\x00"
        + ssh_u32(0)
    )
    payload_client_kexinit = bytes([SSH_MSG_KEXINIT]) + kex
    s.sendall(make_packet(SSH_MSG_KEXINIT, kex))

    # GEX request: min, n, max
    minbits, nbits, maxbits = 2048, 8192, 8192
    s.sendall(make_packet(SSH_MSG_KEXDH_GEX_REQUEST, struct.pack(">III", minbits, nbits, maxbits)))

    # Receive group (p,g)
    mt, md, _payload_group = read_packet(s)
    if mt != SSH_MSG_KEXDH_GEX_GROUP:
        raise RuntimeError(f"expected GEX_GROUP, got {mt}")
    off = 0
    p_mp, off = parse_mpint(md, off)
    g_mp, off = parse_mpint(md, off)
    p = mpint_to_int(p_mp)
    g = mpint_to_int(g_mp)

    # DH: choose x, compute e=g^x mod p
    x = int.from_bytes(os.urandom(32), "big") % (p - 2) + 1
    e_int = pow(g, x, p)
    e_mp = mpint_from_int(e_int)
    s.sendall(make_packet(SSH_MSG_KEXDH_GEX_INIT, e_mp))

    # Receive reply: K_S(string) || f(mpint) || sig(string)
    mt, md, _payload_reply = read_packet(s)
    if mt != SSH_MSG_KEXDH_GEX_REPLY:
        raise RuntimeError(f"expected GEX_REPLY, got {mt}")
    off = 0
    k_s_blob, off2 = parse_ssh_string(md, off)
    k_s_string_onwire = md[off:off2]  # includes u32 length
    off = off2
    f_mp, off = parse_mpint(md, off)
    sig_outer, off = parse_ssh_string(md, off)
    sig_string_onwire = md[off2 + len(f_mp) : off2 + len(f_mp) + 4 + len(sig_outer)]

    f = mpint_to_int(f_mp)
    K_int = pow(f, x, p)
    K_mp = mpint_from_int(K_int)

    # Sanity-check DH math against AJOS' fixed y exponent (ssh.c hard-codes y).
    y_int = 0x3412A55A
    f_expect = pow(g, y_int, p)
    k_expect = pow(e_int, y_int, p)
    print(f"dh_check f_match={f == f_expect} k_match={K_int == k_expect}")
    if f != f_expect:
        print(f"dh_check f_expect_bits={f_expect.bit_length()} f_got_bits={f.bit_length()}")
    if K_int != k_expect:
        print(f"dh_check k_expect_bits={k_expect.bit_length()} k_got_bits={K_int.bit_length()}")

    # Parse signature: string alg, string sigblob
    alg, sig_off = parse_ssh_string(sig_outer, 0)
    sigblob, sig_off = parse_ssh_string(sig_outer, sig_off)
    if sig_off != len(sig_outer):
        raise ValueError("signature trailing bytes")
    if alg != b"rsa-sha2-512":
        raise ValueError(f"unexpected signature alg: {alg!r}")

    n_pub, e_pub = parse_hostkey_ssh_rsa(k_s_string_onwire)

    variants = ["rfc", "no_msgtype", "k_s_nolen", "mpint_nolen"]
    print(f"V_C={v_c!r}")
    print(f"V_S={v_s!r}")
    print(f"sig_alg={alg.decode()}")
    print(f"hostkey e={e_pub} (0x{e_pub:x}), n_bits={n_pub.bit_length()}, sig_len={len(sigblob)}")
    for v in variants:
        H = build_exchange_hash(
            v_c=v_c,
            v_s=v_s,
            i_c_payload=payload_client_kexinit,
            i_s_payload=payload_server_kexinit,
            k_s_string_onwire=k_s_string_onwire,
            minbits=minbits,
            nbits=nbits,
            maxbits=maxbits,
            p_mpint_onwire=p_mp,
            g_mpint_onwire=g_mp,
            e_mpint_onwire=e_mp,
            f_mpint_onwire=f_mp,
            K_mpint_onwire=K_mp,
            variant=v,
        )
        ok = rsa_verify_pkcs1_v15_sha512_over_H(n_pub, e_pub, H, sigblob)
        line = f"{v:10s} H={H.hex()} verify={ok}"
        if v == "rfc":
            k = (n_pub.bit_length() + 7) // 8
            s_int = int.from_bytes(sigblob, "big")
            m = pow(s_int, e_pub, n_pub).to_bytes(k, "big")
            # Try to identify DigestInfo algorithm.
            idx512 = m.find(SHA512_DIGESTINFO_PREFIX)
            idx256 = m.find(SHA256_DIGESTINFO_PREFIX)
            idx1 = m.find(SHA1_DIGESTINFO_PREFIX)
            line += f" dec[0:2]={m[:2].hex()} di512@{idx512} di256@{idx256} di1@{idx1}"
            if idx512 >= 0:
                dig = m[idx512 + len(SHA512_DIGESTINFO_PREFIX) : idx512 + len(SHA512_DIGESTINFO_PREFIX) + 64]
                line += f" sig_sha512={dig.hex()} calc_sha512={hashlib.sha512(H).hexdigest()}"
        print(line)

    # Try to infer which exchange-hash serialization the server used by matching
    # the SHA-512(H) embedded in the RSA signature.
    if "dig" in locals() and isinstance(dig, (bytes, bytearray)) and len(dig) == 64:
        match = find_matching_H_variant(
            v_c=v_c,
            v_s=v_s,
            i_c_payload=payload_client_kexinit,
            i_s_payload=payload_server_kexinit,
            k_s_string_onwire=k_s_string_onwire,
            minbits=minbits,
            nbits=nbits,
            maxbits=maxbits,
            p_mpint_onwire=p_mp,
            g_mpint_onwire=g_mp,
            e_mpint_onwire=e_mp,
            f_mpint_onwire=f_mp,
            K_mpint_onwire=K_mp,
            target_sha512=dig,
        )
        if match:
            print("MATCH", {k: (v.hex() if k == "H" else v) for k, v in match.items()})
        else:
            print("MATCH none (within tested serialization variants)")


if __name__ == "__main__":
    main()

