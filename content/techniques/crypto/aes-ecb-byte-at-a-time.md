---
title: "AES-ECB - Byte-at-a-Time Decryption with a Chosen-Prefix Oracle"
category: crypto
subcategory: aes
type: technique
tags: [aes, ecb, byte-at-a-time, chosen-plaintext, adaptive-chosen-plaintext, oracle, secret-suffix, random-prefix, prefix-length, block-size-detection, ecb-detection, cryptopals, pycryptodome, dictionary-attack, padding]
difficulty: medium
summary: "An oracle that returns ECB(attacker_input || secret) leaks the secret one byte at a time: align it so only one unknown byte sits in a block, then brute-force 256 candidates."
when_to_use:
  - "A service encrypts `your_input + FLAG` (or `PREFIX + your_input + FLAG`) with AES-ECB and hands you the ciphertext"
  - "Ciphertext length is a multiple of 16, no IV, and repeated input blocks give repeated ciphertext blocks"
  - "You can query the oracle an unlimited number of times with arbitrary bytes"
  - "You know nothing about the key but want the appended secret"
  - "Cryptopals set 2 challenge 12 or 14 style challenge"
tools: [pycryptodome, openssl, cyberchef]
source:
  name: "Cryptopals Set 2"
  url: "https://cryptopals.com/sets/2"
related: [aes-ecb-cut-and-paste, aes-cbc-bit-flipping, aes-cbc-padding-oracle, aes-ctr-nonce-reuse]
---

## TL;DR

If you can get `ECB_k(controlled || secret)` for any `controlled` you like, you can read
`secret` in `16 * 256` queries per block without touching the key. Line the secret up so
exactly one unknown byte falls at the end of a block, build a dictionary of all 256
possible blocks, and match. Repeat, shifting the alignment by one byte each time.

## Recognise it

- Source contains `AES.new(key, AES.MODE_ECB).encrypt(pad(data + FLAG, 16))`.
- A remote service takes hex/base64 input and returns hex/base64 ciphertext whose
  length is always a multiple of 32 hex chars, with no random prefix on the output.
- Submitting `"A" * 32` gives two identical 16-byte ciphertext blocks.
- Submitting the same input twice gives the same ciphertext (no per-query IV/nonce).
- Length only grows in steps of 16 as you add input bytes.

## Theory

ECB encrypts each block independently, so a ciphertext block is a pure function of its
plaintext block: `C[i] = E_k(P[i])`.

Write the secret as `s[0], s[1], ...`. Send `15` filler bytes. The first plaintext
block is then `AAAAAAAAAAAAAAA | s[0]` - fifteen bytes you chose plus one unknown. Its
ciphertext block is the answer to a 256-way question. Now send
`AAAAAAAAAAAAAAA || g` for every `g in 0..255`; whichever `g` reproduces that block is
`s[0]`.

For `s[1]`, send only `14` filler bytes so the first block is
`AAAAAAAAAAAAAA | s[0] | s[1]`, and probe with `AAAAAAAAAAAAAA || s[0] || g`. In
general, for the `k`-th secret byte use `fill = (-(k+1)) mod 16` filler bytes and
compare block number `(fill + k) // 16`.

**Random prefix.** If the oracle actually computes `ECB_k(prefix || controlled || secret)`
with a fixed unknown `prefix`, you first need `len(prefix)`:

1. Encrypt `b""` and `b"X"`. The first ciphertext block that differs is the block the
   prefix ends in; call its index `idx`.
2. For `n = 0, 1, ..., 16`, encrypt `b"A"*n + b"\x00"` and `b"A"*n + b"\x01"`. When the
   first `idx+1` blocks are identical, your differing byte has been pushed out of block
   `idx`, so `len(prefix) + n == (idx + 1) * 16`, giving `len(prefix)`.

Then prepend `pad = (-len(prefix)) mod 16` junk bytes to every query and run the
ordinary attack starting at block `(len(prefix) + pad) // 16`.

**Secret length.** Let `base = len(oracle(b"A"*pad))`. Add bytes one at a time; the
first `n` where the length jumps is the PKCS#7 padding count, so
`secret_len = base - len(prefix) - pad - n`.

## Attack

1. Detect the block size: grow the input until the ciphertext length jumps; the jump
   size is the block size (16 for AES, 8 for DES/3DES/Blowfish).
2. Detect ECB: send `2 * blocksize` identical bytes, look for a repeated block.
3. Recover the prefix length (skip if there is no prefix).
4. Recover the secret length.
5. For each secret byte index `k`: choose `fill`, snapshot the target block, then try
   all 256 candidates for the final byte.
6. Stop after `secret_len` bytes. If you overrun into the PKCS#7 padding, the attack
   still "succeeds" on the first padding byte (`\x01`) and then stalls - that is the
   classic off-by-one, which is why step 4 exists.

Cost: `secret_len * 256` oracle queries in the worst case, about `128` on average per
byte if you try likely ASCII first.

## Code

```python
#!/usr/bin/env python3
"""AES-ECB byte-at-a-time secret recovery, with and without a random fixed prefix.

Builds the vulnerable oracle locally and asserts the whole secret comes back.
"""

import os
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BS = 16


# ----------------------------------------------------------------- helpers
def blocks(data: bytes, bs: int = BS) -> list[bytes]:
    return [data[i:i + bs] for i in range(0, len(data), bs)]


def detect_block_size(oracle) -> int:
    """The ciphertext length jumps by exactly one block when padding rolls over."""
    base = len(oracle(b""))
    for n in range(1, 129):
        size = len(oracle(b"A" * n))
        if size != base:
            return size - base
    raise RuntimeError("block size not found")


def detect_ecb(oracle, bs: int = BS) -> bool:
    """Two identical plaintext blocks -> two identical ciphertext blocks."""
    ct = oracle(b"A" * (bs * 4))
    bl = blocks(ct, bs)
    return len(bl) != len(set(bl))


def find_prefix_len(oracle, bs: int = BS) -> int:
    """Length of the fixed unknown prefix the oracle prepends to our input."""
    c0, c1 = oracle(b""), oracle(b"\x01")
    idx = min(len(c0), len(c1)) // bs
    for i in range(0, min(len(c0), len(c1)), bs):
        if c0[i:i + bs] != c1[i:i + bs]:
            idx = i // bs
            break
    for n in range(bs + 1):
        a = oracle(b"A" * n + b"\x00")
        b = oracle(b"A" * n + b"\x01")
        if a[:(idx + 1) * bs] == b[:(idx + 1) * bs]:
            return (idx + 1) * bs - n
    raise RuntimeError("prefix length not found")


def find_secret_len(oracle, prefix_len: int, align: int, bs: int = BS) -> int:
    """Secret length from the point at which adding one more byte grows the ciphertext."""
    base = len(oracle(b"A" * align))
    for n in range(1, bs + 1):
        if len(oracle(b"A" * (align + n))) > base:
            return base - prefix_len - align - n
    raise RuntimeError("secret length not found")


# ------------------------------------------------------------------- attack
def ecb_byte_at_a_time(oracle, bs: int = BS, verbose: bool = False) -> bytes:
    """Recover the secret appended by `oracle(data) -> ECB(prefix || data || secret)`."""
    prefix_len = find_prefix_len(oracle, bs)
    align = (-prefix_len) % bs                  # junk that fills the prefix's last block
    start = (prefix_len + align) // bs          # first fully attacker-controlled block
    secret_len = find_secret_len(oracle, prefix_len, align, bs)

    # Try printable bytes first: cuts the average query count roughly in half.
    order = [ord(c) for c in string.printable] + [b for b in range(256)]

    known = b""
    for k in range(secret_len):
        fill = (-(k + 1)) % bs
        tb = start + (fill + k) // bs
        target = oracle(b"A" * (align + fill))[tb * bs:(tb + 1) * bs]
        for guess in order:
            probe = oracle(b"A" * (align + fill) + known + bytes([guess]))
            if probe[tb * bs:(tb + 1) * bs] == target:
                known += bytes([guess])
                break
        else:
            break
        if verbose:
            print("  ", known)
    return known


# --------------------------------------------------------- vulnerable oracles
def make_simple_oracle(secret: bytes):
    """ECB(attacker || secret) -- Cryptopals 12."""
    key = os.urandom(16)

    def oracle(data: bytes) -> bytes:
        return AES.new(key, AES.MODE_ECB).encrypt(pad(data + secret, BS))

    return oracle


def make_prefixed_oracle(secret: bytes, prefix_len: int | None = None):
    """ECB(fixed_random_prefix || attacker || secret) -- Cryptopals 14."""
    key = os.urandom(16)
    n = os.urandom(1)[0] % 60 if prefix_len is None else prefix_len
    prefix = os.urandom(n)

    def oracle(data: bytes) -> bytes:
        return AES.new(key, AES.MODE_ECB).encrypt(pad(prefix + data + secret, BS))

    return oracle, len(prefix)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    SECRET = (b"flag{ecb_is_a_codebook_not_a_cipher_mode}\n"
              b"Rollin' in my 5.0 with my ragtop down so my hair can blow")

    # --- no prefix ---------------------------------------------------------
    oracle = make_simple_oracle(SECRET)
    assert detect_block_size(oracle) == 16
    assert detect_ecb(oracle)
    print("[+] block size 16, mode ECB")
    got = ecb_byte_at_a_time(oracle)
    assert got == SECRET, (got, SECRET)
    print("[+] PASS simple oracle, recovered", len(got), "bytes")
    print(got.decode())

    # --- random fixed prefix ----------------------------------------------
    for plen in (0, 1, 15, 16, 17, 31, 32, 47):
        orc, real = make_prefixed_oracle(SECRET, prefix_len=plen)
        found = find_prefix_len(orc)
        assert found == real, (found, real)
    print("[+] PASS prefix-length detection for 0,1,15,16,17,31,32,47")

    orc, real = make_prefixed_oracle(SECRET)
    assert find_prefix_len(orc) == real
    got = ecb_byte_at_a_time(orc)
    assert got == SECRET, (got, SECRET)
    print(f"[+] PASS prefixed oracle (prefix was {real} bytes), recovered {len(got)} bytes")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Random prefix of random *length per query*** breaks the alignment trick. Work
  around it by sending a long run of identical bytes (`b"A" * 3*16`) and locating the
  repeated block in the output; only keep queries where the repeat appears at the
  index you expect, or normalise by searching for your marker block every time.
- **Compression before encryption** (a CRIME-style oracle) changes the game entirely:
  length, not block content, is the signal. Different technique.
- **8-byte blocks.** DES, 3DES and Blowfish in ECB behave identically with `bs = 8`.
  `detect_block_size` finds this for you; never hardcode 16.
- **Base64-encoded secret.** Many challenges base64 the flag before appending. Recover
  the base64 text, then decode. If a byte will not resolve, you have probably run into
  the PKCS#7 padding - check `find_secret_len`.
- **Query budget.** A remote oracle may rate-limit. Restrict the candidate alphabet to
  printable ASCII (done above) and batch requests over one persistent connection.
- **Non-PKCS#7 padding.** With zero padding, `find_secret_len` misfires when the secret
  already ends on a block boundary. Fall back to "recover until a byte fails".
- **The oracle appends the secret *before* your input** (`ECB(secret || attacker)`).
  That is not solvable this way - you can only push unknown bytes to the end of a
  block if they come after your controlled bytes.

## Tools

- `pycryptodome` for local reproduction of the oracle.
- `pwntools` (`remote()`, `p.sendlineafter`) to drive a networked oracle.
- CyberChef "AES Decrypt" for one-off sanity checks once you have the key.

## References

- Cryptopals Set 2, challenge 12 ("Byte-at-a-time ECB decryption (Simple)") and
  challenge 14 ("Byte-at-a-time ECB decryption (Harder)"):
  <https://cryptopals.com/sets/2>
