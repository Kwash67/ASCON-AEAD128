# ASCON-AEAD128
Python and Verilog Implementation of ASCON-AEAD-128 for RFID application.

Based on recent NIST publication NIST SP 800-232 https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf

## Generate KATs and Run Tests

This repo includes the official Python reference to generate Known Answer Tests (KATs) for Ascon-AEAD128 and a simple test harness for your implementation in `ascon128.py`.

### Generate AEAD KATs (official)

From the repo root, run:

```zsh
python3 official_ascon/genkat.py Ascon-AEAD128
```

This will produce both `LWC_AEAD_KAT_128_128.txt` and `LWC_AEAD_KAT_128_128.json` in the repo root.

### Run the KAT tests against your implementation

Ensure your implementation exposes `ascon_aead128_enc(K, N, ad, pt)` that returns `(ciphertext_blocks: List[bytes], tag: bytes)`, where tag is 16 bytes.

Then run:

```zsh
python3 test_ascon_kats.py
```

The test parses `LWC_AEAD_KAT_128_128.txt`, runs your encrypt function on each vector, and checks both ciphertext and tag.

### Notes

- The official generator uses the variant name `Ascon-AEAD128`.
- The KAT `CT` field is `ciphertext || tag` (tag is always 16 bytes).
- Keys and nonces in `test_ascon_kats.py` are interpreted as big-endian integers before being passed to your function.
