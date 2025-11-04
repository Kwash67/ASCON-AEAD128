#!/usr/bin/env python3
import binascii

from ascon128 import ascon_aead128_enc

KAT_FILE = "LWC_AEAD_KAT_128_128.txt"


def parse_kat_file(filename):
    """Parse NIST LWC AEAD KAT vectors."""
    vectors = []
    with open(filename, "r") as f:
        current = {}
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith("Count ="):
                if current:
                    vectors.append(current)
                current = {}

            key, val = [x.strip() for x in line.split("=", 1)]
            current[key] = val

        if current:
            vectors.append(current)

    return vectors


def hex_to_bytes(x):
    return b"" if x == "" else binascii.unhexlify(x)


def run_kats():
    vectors = parse_kat_file(KAT_FILE)
    total = len(vectors)
    passed = 0

    for v in vectors:
        key = hex_to_bytes(v["Key"])
        nonce = hex_to_bytes(v["Nonce"])
        ad = hex_to_bytes(v["AD"])
        pt = hex_to_bytes(v["PT"])

        # CT field = ciphertext || tag, where tag is ALWAYS 16 bytes (128 bits)
        ct_full = v["CT"].lower()

        # split into ciphertext and tag
        tag = ct_full[-32:]  # last 16 bytes (32 hex chars)
        ct = ct_full[:-32]  # everything before the tag

        K = int.from_bytes(key, "big")
        N = int.from_bytes(nonce, "big")

        C_blocks, T = ascon_aead128_enc(K, N, ad, pt)

        # join ciphertext blocks
        C = b"".join(C_blocks).hex()
        T_hex = T.hex()

        if C == ct and T_hex == tag:
            passed += 1
        else:
            print("❌ FAILED TEST:")
            print("Count =", v["Count"])
            print("expected CT:", ct)
            print("got     CT:", C)
            print("expected TAG:", tag)
            print("got     TAG:", T_hex)
            return

    print(f"✅ All {passed}/{total} Ascon-128 AEAD KATs passed!")


if __name__ == "__main__":
    run_kats()
