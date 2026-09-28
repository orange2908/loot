---
title: "AES-ECB - Cut-and-Paste Forgery, Block Shuffling and the ECB Penguin"
category: crypto
subcategory: aes
type: technique
tags: [aes, ecb, ecb-penguin, cut-and-paste, block-shuffling, block-reordering, cookie-forgery, profile-for, chosen-plaintext, deterministic-encryption, pkcs7, padding, cryptopals, pycryptodome, openssl, role-admin]
difficulty: easy
summary: "ECB encrypts every 16-byte block independently, so identical plaintext blocks give identical ciphertext blocks and blocks can be cut, reordered and pasted to forge a token."
when_to_use:
  - "Ciphertext length is an exact multiple of 16 and there is no IV or nonce in the blob"
  - "The same plaintext always encrypts to the same ciphertext (deterministic, no randomness)"
  - "You see repeated 16-byte blocks in a hexdump of the ciphertext"
  - "A service encrypts a structured string you partially control, like `email=...&role=user`"
  - "You need `role=admin` / `isAdmin=1` but can only influence one field"
tools: [pycryptodome, openssl, cyberchef]
source:
  name: "Cryptopals Set 2"
  url: "https://cryptopals.com/sets/2"
related: [aes-ecb-byte-at-a-time, aes-cbc-bit-flipping, aes-cbc-padding-oracle, block-cbc-mac-forgery]
---

## TL;DR

ECB is a codebook: `C[i] = E_k(P[i])`, each 16-byte block on its own, with no chaining
and no IV. That means ciphertext blocks are portable - you can delete, duplicate,
reorder and splice them between messages encrypted under the same key, and the
receiver still decrypts each one correctly. If you control enough of the plaintext to
push a value you want onto its own block boundary, you can paste that block anywhere.

## Recognise it

- `len(ciphertext) % 16 == 0` and there is no 16-byte IV glued on the front.
- Encrypting the same input twice returns the same bytes. No randomness anywhere.
- `AES.new(key, AES.MODE_ECB)` in provided source, or `openssl enc -aes-128-ecb`.
- Send `b"A" * 64`; if two consecutive ciphertext blocks are byte-identical, it is ECB.
- A bitmap or PNG "encrypted" with it still shows the picture - the ECB penguin. Every
  run of identical pixels maps to the same ciphertext block, so structure survives.
- A serialised profile / cookie / license string with `&`, `=`, `;` separators and a
  field you control (usually an email or username).

## Theory

Encryption: split `P` into blocks `P[0..n-1]` of exactly `BS = 16` bytes after PKCS#7
padding, then `C[i] = E_k(P[i])`. Decryption: `P[i] = D_k(C[i])`.

Two consequences do all the work:

1. **Determinism.** `P[i] == P[j]` implies `C[i] == C[j]`. This leaks plaintext
   structure and is what makes the penguin visible and what makes `detect_ecb` work.
2. **No position binding.** `D_k` does not know or care what index a block came from.
   A ciphertext block encrypting `"admin\x0b\x0b..."` decrypts to that string whether
   it is block 1 of one message or block 2 of a completely different message.

The only alignment you have to respect is the block grid. If the field you want to
overwrite does not start at a multiple of 16, pad the part of the plaintext you
control until it does.

## Attack

Target: `profile_for(email) = "email=" + email + "&uid=10&role=user"`, encrypted with
AES-ECB, `&` and `=` stripped from the email.

Step 1 - mint an `admin` block. `"email="` is 6 bytes, so with a 10-byte email the
second block begins exactly at offset 16. Ask for:

```
email=AAAAAAAAAA admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
^--- block 0 ---^^-------------- block 1 -----------------------^
```

The `\x0b * 11` is a valid PKCS#7 tail for a 5-byte payload, so after the splice the
unpadder will accept it. Save `C_admin = ct[16:32]`.

Step 2 - align `role=` to end a block. The fixed parts are `"email="` (6) and
`"&uid=10&role="` (13) = 19 bytes. Pick an email of length 13 so the prefix is exactly
32 bytes and `"user"` lands alone at the start of block 2.

Step 3 - splice: `forged = ct[:32] + C_admin`.

Step 4 - the server decrypts `email=foooo@bar.com&uid=10&role=admin` + valid padding.

The same primitive gives you **block reordering** (swap two ciphertext blocks to swap
two plaintext blocks), **block deletion** (drop a block to drop a field) and **block
duplication** (repeat a block to repeat a field, useful when the parser keeps the last
occurrence of a duplicated key).

## Code

```python
#!/usr/bin/env python3
"""AES-ECB cut-and-paste forgery, block shuffling and ECB detection.

Self-contained: builds the vulnerable profile service locally with a random key,
forges role=admin without knowing the key, and asserts the forgery is accepted.
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BS = 16


# ----------------------------------------------------------------- helpers
def blocks(data: bytes, bs: int = BS) -> list[bytes]:
    """Split data into bs-sized blocks (last one may be short)."""
    return [data[i:i + bs] for i in range(0, len(data), bs)]


def detect_ecb(ct: bytes, bs: int = BS) -> bool:
    """True if any two blocks repeat -- the classic ECB fingerprint."""
    bl = blocks(ct, bs)
    return len(bl) != len(set(bl))


def detect_block_size(encrypt) -> int:
    """Feed growing prefixes until the ciphertext length jumps; the jump is the block size."""
    base = len(encrypt(b""))
    for n in range(1, 65):
        size = len(encrypt(b"A" * n))
        if size != base:
            return size - base
    raise RuntimeError("no block size found")


# --------------------------------------------------------- vulnerable service
class ProfileService:
    """email=<email>&uid=10&role=user, encrypted with a fixed AES-ECB key."""

    def __init__(self) -> None:
        self.key = os.urandom(16)

    @staticmethod
    def profile_for(email: bytes) -> bytes:
        # The service "sanitises" by stripping the metacharacters. It is not enough.
        email = email.replace(b"&", b"").replace(b"=", b"")
        return b"email=" + email + b"&uid=10&role=user"

    def encrypted_profile(self, email: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(self.profile_for(email), BS))

    def parse(self, ct: bytes) -> dict[bytes, bytes]:
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), BS)
        out: dict[bytes, bytes] = {}
        for kv in pt.split(b"&"):
            k, _, v = kv.partition(b"=")
            out[k] = v
        return out


# ------------------------------------------------------------------- attack
def forge_admin(svc: ProfileService) -> bytes:
    """Cut-and-paste an `admin` block onto an aligned profile ciphertext."""
    # Step 1: a block whose plaintext is exactly b"admin" + PKCS#7 tail.
    # b"email=" is 6 bytes, so 10 filler bytes push the payload to offset 16.
    payload = b"admin" + bytes([BS - 5]) * (BS - 5)
    ct_src = svc.encrypted_profile(b"A" * 10 + payload)
    admin_block = ct_src[BS:2 * BS]

    # Step 2: choose an email length so that b"user" starts a fresh block.
    # len(b"email=") + len(email) + len(b"&uid=10&role=") == 32  ->  len(email) == 13
    fixed = len(b"email=") + len(b"&uid=10&role=")
    email_len = (-fixed) % BS
    while email_len < 13:                       # keep it a plausible address length
        email_len += BS
    email = b"foooo@bar.com"[:email_len].ljust(email_len, b"x")
    ct_tgt = svc.encrypted_profile(email)

    # Step 3: splice. Everything up to and including b"role=" is 2 blocks.
    keep = (len(b"email=") + email_len + len(b"&uid=10&role=")) // BS
    return ct_tgt[:keep * BS] + admin_block


def swap_blocks(ct: bytes, i: int, j: int, bs: int = BS) -> bytes:
    """Reorder two ciphertext blocks -> the two plaintext blocks swap."""
    bl = blocks(ct, bs)
    bl[i], bl[j] = bl[j], bl[i]
    return b"".join(bl)


def drop_block(ct: bytes, i: int, bs: int = BS) -> bytes:
    """Delete a ciphertext block -> delete 16 bytes of plaintext."""
    bl = blocks(ct, bs)
    del bl[i]
    return b"".join(bl)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    svc = ProfileService()

    # --- ECB detection -----------------------------------------------------
    probe = svc.encrypted_profile(b"A" * 64)
    assert detect_ecb(probe), "repeated blocks should be visible"
    assert detect_block_size(svc.encrypted_profile) == 16
    print("[+] mode looks like ECB, block size 16")

    # --- determinism -------------------------------------------------------
    a = svc.encrypted_profile(b"me@example.com")
    b = svc.encrypted_profile(b"me@example.com")
    assert a == b, "ECB is deterministic"
    print("[+] deterministic: same input -> same ciphertext")

    # --- the forgery -------------------------------------------------------
    forged = forge_admin(svc)
    profile = svc.parse(forged)
    print("[+] forged profile:", profile)
    assert profile[b"role"] == b"admin", profile
    print("[+] PASS cut-and-paste: role=admin")

    # --- block shuffling ---------------------------------------------------
    key = os.urandom(16)
    ecb = AES.new(key, AES.MODE_ECB)
    msg = pad(b"BLOCK-ONE-AAAAAA" b"BLOCK-TWO-BBBBBB" b"BLOCK-THREE-CCCC", BS)
    ct = ecb.encrypt(msg)

    swapped = AES.new(key, AES.MODE_ECB).decrypt(swap_blocks(ct, 0, 1))
    assert swapped[:32] == b"BLOCK-TWO-BBBBBB" b"BLOCK-ONE-AAAAAA"
    print("[+] PASS block swap:", swapped[:32])

    dropped = AES.new(key, AES.MODE_ECB).decrypt(drop_block(ct, 1))
    assert dropped[:32] == b"BLOCK-ONE-AAAAAA" b"BLOCK-THREE-CCCC"
    print("[+] PASS block delete:", dropped[:32])

    # --- ECB penguin, in miniature ----------------------------------------
    # A "bitmap" of two colours: the ciphertext still has only two distinct blocks.
    image = (b"\x00" * 16) * 8 + (b"\xff" * 16) * 8
    enc_img = AES.new(key, AES.MODE_ECB).encrypt(image)
    assert len(set(blocks(enc_img))) == 2, "structure survives ECB"
    print("[+] PASS penguin: 16 image blocks -> only 2 distinct ciphertext blocks")

    print("\nall checks passed")
```

## Variants & pitfalls

- **The padding tail matters.** If the server calls `unpad(..., 16)` your final block
  must carry a valid PKCS#7 tail. `b"admin" + b"\x0b" * 11` is the standard trick. If
  the server uses `.rstrip()` or zero padding instead, use `b"admin" + b"\x00" * 11`.
- **Metacharacter filters are irrelevant.** The filter runs on the plaintext you
  submit; the splice happens on ciphertext, after the filter.
- **Parser last-wins.** Many `k=v&k=v` parsers keep the last value. If you cannot
  align `role=` to a boundary, try appending a whole extra `&role=admin` block instead
  of replacing the original.
- **Prefix you do not control.** If the plaintext is `"user=" + name + "|role=user"`
  and the constant prefix length is unknown, recover it the same way as in
  `aes-ecb-byte-at-a-time`: send two inputs differing in one byte and find the first
  ciphertext block that changes.
- **Length is not secret.** Splicing changes the total length; if the service checks
  a length field inside the plaintext your forgery breaks. Pick block counts that keep
  the length the same, or overwrite the length field too.
- **CBC is not safe either** - see `aes-cbc-bit-flipping`. But in CBC a spliced block
  corrupts the following block, so you pay one garbage block per splice.
- **Do not confuse ECB detection with a short message.** A single-block ciphertext can
  never show a repeat. Force the repeat by submitting at least `2 * BS` identical bytes
  of your own.

## Tools

- `pycryptodome` - `from Crypto.Cipher import AES; AES.new(key, AES.MODE_ECB)`.
- `openssl enc -aes-128-ecb -K <hexkey> -nopad -in f -out f.enc` - no IV argument is
  accepted for ECB, which is itself a fingerprint.
- CyberChef - "AES Decrypt" with mode ECB, plus the "Detect ECB" style block view.
- `xxd -c 16` / `hexdump -C` - eyeball repeated lines to spot ECB instantly.

## References

- Cryptopals Set 2, challenge 12 (byte-at-a-time) and 13 (cut-and-paste):
  <https://cryptopals.com/sets/2>
- Cryptopals Set 1, challenge 8 (detect AES in ECB mode):
  <https://cryptopals.com/sets/1>
