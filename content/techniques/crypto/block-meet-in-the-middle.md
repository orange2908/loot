---
title: "Meet-in-the-Middle on Double Encryption (2DES-style)"
category: crypto
subcategory: block-cipher
type: technique
tags: [meet-in-the-middle, mitm, double-encryption, 2des, double-des, triple-des, 3des, time-memory-tradeoff, known-plaintext, key-recovery, false-positive, birthday, block-cipher, feistel, aes, pycryptodome, brute-force]
difficulty: medium
summary: "Encrypting twice with two k-bit keys costs an attacker ~2^(k+1) work, not 2^(2k): build a table of E_k1(P) and look up D_k2(C) in it."
when_to_use:
  - "A scheme encrypts twice with two independent keys (2DES, double-AES, double-XTEA)"
  - "Each individual key is small enough to enumerate (<= 2^32 or reduced by the challenge)"
  - "You have at least one known plaintext/ciphertext pair, ideally two"
  - "The challenge boasts about doubling the key length"
  - "A custom cipher composes two keyed permutations with no intermediate whitening"
tools: [pycryptodome, python]
related: [block-differential-linear, block-toy-spn-z3, aes-ecb-byte-at-a-time, stream-lfsr-berlekamp-massey]
---

## TL;DR

`C = E_{k2}(E_{k1}(P))` looks like a `2k`-bit key. It is not. Rearrange to

$$E_{k_1}(P) = D_{k_2}(C)$$

Both sides are computable with only *one* key each. Enumerate `k1`, store every
`E_{k1}(P)` in a hash table, then enumerate `k2` and look up `D_{k2}(C)`. Any hit is a
candidate pair. Work: `2^{k+1}` encryptions and `2^k` memory instead of `2^{2k}`. This
is exactly why 3DES exists, and why its effective strength is 112 bits, not 168.

## Recognise it

- `enc(enc(pt, k1), k2)` or `E(E(x))` anywhere in the source.
- A key that is the concatenation of two halves, each used by one cipher call.
- DES appearing twice, or a custom 32-bit-key cipher applied twice.
- A challenge that says "we doubled the key size so it is twice as strong".
- Any composition `F_b(F_a(x))` where you can invert `F_b`.

## Theory

Double encryption: `C = E_{k2}(E_{k1}(P))`, keys independent, `k` bits each.

Because the intermediate value `M = E_{k1}(P) = D_{k2}(C)` is shared, the search
factorises:

1. For each `k1`, compute `M = E_{k1}(P)`, store `table[M].append(k1)`. Cost `2^k`
   encryptions, `2^k` memory.
2. For each `k2`, compute `M' = D_{k2}(C)`. If `M'` is in the table, every `k1` in
   `table[M']` gives a candidate `(k1, k2)`.

**False positives.** With an `n`-bit block there are `2^{2k}` key pairs mapping into
`2^n` possible intermediates, so the expected number of surviving pairs after one
known plaintext is

$$\frac{2^{2k}}{2^{n}}$$

For 2DES (`k = 56`, `n = 64`) that is `2^{48}` false pairs - far too many. A second
known pair filters to `2^{2k - 2n} = 2^{-16}`, i.e. essentially just the right one.
For double-AES (`n = 128`, `k = 128`) one pair already leaves `2^{128}` candidates in
theory, but in a CTF the keyspace is always reduced, and with `2k <= n` one pair is
enough.

Rule of thumb: you need `ceil(2k / n)` known plaintext/ciphertext pairs.

**Memory.** The table is the bottleneck, not the time. Trade it back with
Hellman/rainbow-style time-memory tradeoffs, or sort both lists and merge (`2^k log`
time, `2^k` disk). In CTFs the reduced keyspace fits in RAM.

**3DES.** `E_{k1}(D_{k2}(E_{k3}(P)))`. MITM still applies across the first two stages
combined vs the last, giving `~2^{112}` - hence "112-bit security" for 3-key 3DES and
only ~`2^{80}` with certain chosen-plaintext tradeoffs. Two-key 3DES (`k3 = k1`) is
weaker still.

**Why whitening helps.** DES-X (`k2 xor E_k(k1 xor P)`) resists MITM because the xor
masks are not separable in the same way; its security is ~`2^{118}`.

## Attack

1. Get one known plaintext/ciphertext pair `(P, C)`. Get a second one if you can.
2. Decide the per-key search space. If the challenge fixed most bytes, enumerate only
   the unknown ones.
3. Build `{E_{k1}(P): [k1...]}`.
4. Sweep `k2`, look up `D_{k2}(C)`, collect candidate pairs.
5. Filter candidates with the second pair. If you have only one pair, filter with a
   plausibility check on a third ciphertext (does it decrypt to printable text?).
6. Verify the survivor against everything you have.

## Code

```python
#!/usr/bin/env python3
"""Meet-in-the-middle against double encryption.

Two demos:
  1. Double-AES with a reduced (2^16 per key) keyspace -- the realistic CTF shape.
  2. A 16-bit-block toy cipher, where false positives actually appear and a second
     known plaintext pair is genuinely required.

Self-contained; both attacks are asserted.
"""

import os
import random
import secrets
from Crypto.Cipher import AES

# --------------------------------------------------------- 1. double AES
KEY_BITS = 16                       # the challenge fixed the other 112 bits


def aes_key(x: int) -> bytes:
    """A 16-byte key whose only unknown part is the low 16 bits."""
    return b"\x00" * 14 + x.to_bytes(2, "big")


def double_aes_encrypt(k1: int, k2: int, pt: bytes) -> bytes:
    mid = AES.new(aes_key(k1), AES.MODE_ECB).encrypt(pt)
    return AES.new(aes_key(k2), AES.MODE_ECB).encrypt(mid)


def mitm_double_aes(pairs: list[tuple[bytes, bytes]], bits: int = KEY_BITS
                    ) -> list[tuple[int, int]]:
    """Recover (k1, k2) from known plaintext/ciphertext pairs."""
    pt, ct = pairs[0]
    table: dict[bytes, list[int]] = {}
    for k1 in range(1 << bits):
        table.setdefault(AES.new(aes_key(k1), AES.MODE_ECB).encrypt(pt), []).append(k1)

    candidates = []
    for k2 in range(1 << bits):
        mid = AES.new(aes_key(k2), AES.MODE_ECB).decrypt(ct)
        for k1 in table.get(mid, ()):
            candidates.append((k1, k2))

    # filter with any extra pairs
    for p, c in pairs[1:]:
        candidates = [(a, b) for a, b in candidates
                      if double_aes_encrypt(a, b, p) == c]
    return candidates


# ----------------------------------------------- 2. a 16-bit-block toy cipher
_rng = random.Random(0xC0FFEE)
SBOX = list(range(256))
_rng.shuffle(SBOX)


def _f(x: int, rk: int) -> int:
    return (SBOX[(x ^ rk) & 0xFF] + rk) & 0xFF


def _round_keys(key: int) -> list[int]:
    lo, hi = key & 0xFF, (key >> 8) & 0xFF
    return [lo, hi, lo ^ 0x5A, hi ^ 0xA5]


def tiny_encrypt(key: int, block: int) -> int:
    """4-round Feistel, 16-bit block, 16-bit key."""
    left, right = block >> 8, block & 0xFF
    for rk in _round_keys(key):
        left, right = right, left ^ _f(right, rk)
    return (left << 8) | right


def tiny_decrypt(key: int, block: int) -> int:
    left, right = block >> 8, block & 0xFF
    for rk in reversed(_round_keys(key)):
        left, right = right ^ _f(left, rk), left
    return (left << 8) | right


def double_tiny(k1: int, k2: int, block: int) -> int:
    return tiny_encrypt(k2, tiny_encrypt(k1, block))


def mitm_tiny(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    pt, ct = pairs[0]
    table: dict[int, list[int]] = {}
    for k1 in range(1 << 16):
        table.setdefault(tiny_encrypt(k1, pt), []).append(k1)

    candidates = []
    for k2 in range(1 << 16):
        for k1 in table.get(tiny_decrypt(k2, ct), ()):
            candidates.append((k1, k2))

    for p, c in pairs[1:]:
        candidates = [(a, b) for a, b in candidates if double_tiny(a, b, p) == c]
    return candidates


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    # --- toy cipher sanity --------------------------------------------------
    for _ in range(500):
        k, b = secrets.randbelow(1 << 16), secrets.randbelow(1 << 16)
        assert tiny_decrypt(k, tiny_encrypt(k, b)) == b
    print("[+] PASS toy Feistel cipher is a bijection")

    # --- 1. double AES, reduced keyspace ------------------------------------
    K1, K2 = secrets.randbelow(1 << KEY_BITS), secrets.randbelow(1 << KEY_BITS)
    P = b"attack at dawn!!"
    C = double_aes_encrypt(K1, K2, P)
    print(f"[+] true keys: k1=0x{K1:04x} k2=0x{K2:04x}  "
          f"(naive search 2^{2 * KEY_BITS}, mitm 2^{KEY_BITS + 1})")

    found = mitm_double_aes([(P, C)])
    print("[+] candidates after one pair:", found)
    assert (K1, K2) in found
    assert len(found) == 1, "128-bit block, 32-bit total keyspace -> no collisions"
    print("[+] PASS meet-in-the-middle on double AES")

    # the recovered keys really work on fresh data
    P2 = os.urandom(16)
    assert double_aes_encrypt(*found[0], P2) == double_aes_encrypt(K1, K2, P2)
    print("[+] PASS recovered keys reproduce encryption of new plaintext")

    # --- 2. toy cipher, where false positives are real ----------------------
    T1, T2 = secrets.randbelow(1 << 16), secrets.randbelow(1 << 16)
    p1, p2 = 0x1234, 0xBEEF
    c1, c2 = double_tiny(T1, T2, p1), double_tiny(T1, T2, p2)
    print(f"[+] true toy keys: k1=0x{T1:04x} k2=0x{T2:04x}")

    one_pair = mitm_tiny([(p1, c1)])
    print(f"[+] one pair  -> {len(one_pair)} candidate key pairs "
          f"(expected ~2^(2k-n) = 2^16)")
    assert (T1, T2) in one_pair
    assert len(one_pair) > 100, "a 16-bit block must produce many false positives"

    two_pairs = mitm_tiny([(p1, c1), (p2, c2)])
    print(f"[+] two pairs -> {len(two_pairs)} candidate key pairs: {two_pairs[:4]}")
    assert (T1, T2) in two_pairs
    assert len(two_pairs) <= 8, two_pairs
    print("[+] PASS a second known pair removes the false positives")

    # --- 3. the cost, stated plainly ---------------------------------------
    naive = (1 << 16) * (1 << 16)
    mitm = 2 * (1 << 16)
    print(f"[+] naive double-key search: {naive:,} encryptions")
    print(f"[+] meet in the middle     : {mitm:,} encryptions "
          f"({naive // mitm:,}x cheaper)")
    assert mitm * 32768 == naive

    print("\nall checks passed")
```

## Variants & pitfalls

- **You must be able to invert the second stage.** If the outer transform is a hash or
  a one-way function, MITM does not apply. If the outer stage is keyed *and* you can
  only evaluate it forwards, try the other direction (build the table on the decrypt
  side).
- **Two identical keys.** If `k1 == k2` (a common shortcut), the scheme is just
  `E_k(E_k(P))` and plain brute force over `2^k` is simpler than MITM.
- **Memory blowup.** `2^32` 16-byte intermediates is 64 GB. Store a *truncated*
  intermediate (say the first 4 bytes) as the dict key, accept the extra false
  positives, and re-check survivors fully.
- **Not enough known plaintext.** With one pair and `2k > n`, you will get a flood of
  candidates. Use a plausibility filter: decrypt a longer ciphertext with each
  candidate and keep the ones that give printable text or valid padding.
- **Ordering.** `E_{k2}(E_{k1}(P))` vs `E_{k1}(E_{k2}(P))` matters. If the attack
  finds nothing, swap the roles.
- **Triple encryption** needs the MITM split across `1+2` or `2+1` stages, which costs
  `2^{2k}` time or `2^{k}` time with `2^{2k}` memory. Feasible only when the challenge
  shrinks the keys.
- **Related constructions.** The same trick breaks double-hashing schemes, two-layer
  obfuscation in reversing challenges, and "encrypt then encrypt again with a second
  password" designs.
- **A sorted-merge beats a dict** when memory is tight: write both lists to disk,
  `sort`, and `comm`/merge them.

## Tools

- `pycryptodome` for the cipher primitives.
- `numpy` when the keyspace is large: vectorise the table build and use
  `np.intersect1d` for the merge.

## References

- Diffie and Hellman, "Exhaustive Cryptanalysis of the NBS Data Encryption Standard"
  (1977) - the original meet-in-the-middle argument against double DES.
- NIST SP 800-67 specifies 3DES and its 112-bit effective strength.
