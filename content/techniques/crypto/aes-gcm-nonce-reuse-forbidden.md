---
title: "AES-GCM - Nonce Reuse, Authentication Key Recovery and Tag Forgery (Forbidden Attack)"
category: crypto
subcategory: gcm
type: technique
tags: [aes, gcm, aead, forbidden-attack, nonce-reuse, iv-reuse, ghash, authentication-key, tag-forgery, galois-field, gf2-128, polynomial-root, joux, keystream-reuse, xor, nonce, pycryptodome, sagemath, cantor-zassenhaus, aes-gcm-siv]
difficulty: hard
summary: "Reuse a GCM nonce and GHASH becomes a polynomial in the authentication key H that you can solve; recover H, then forge a valid tag for any ciphertext under that nonce."
when_to_use:
  - "Two AES-GCM ciphertexts share a nonce (same key, same IV)"
  - "The nonce is a counter that resets, a timestamp, a hardcoded constant, or 12 zero bytes"
  - "You have (nonce, ciphertext, tag) for at least two messages and want to forge a third"
  - "Plain keystream reuse is not enough - you also need the tag to verify"
  - "Challenge mentions `forbidden attack`, `GHASH`, `nonce-disrespecting`, or `H recovery`"
tools: [pycryptodome, sagemath]
related: [aes-ctr-nonce-reuse, aes-cbc-padding-oracle, block-cbc-mac-forgery, xor-repeating-key]
---

## TL;DR

GCM = CTR for confidentiality + GHASH for authenticity. GHASH is a polynomial
evaluation in `GF(2^128)` at the secret point `H = E_k(0^128)`. Reusing a nonce gives
you two tags over the same `E_k(J0)` mask; subtracting them cancels the mask and leaves
a polynomial whose root is `H`. Recover `H`, recover `E_k(J0)`, and you can produce a
valid tag for any ciphertext under that nonce - total loss of authenticity, on top of
the ordinary CTR keystream reuse that loses confidentiality.

## Recognise it

- Two records with the same 12-byte IV/nonce field, or no nonce in the wire format.
- `AES.new(key, AES.MODE_GCM, nonce=NONCE)` with a module-level constant nonce.
- `nonce = os.urandom(8)` generated once at service startup and reused per request.
- TLS implementations that derived the explicit nonce from a bad PRNG (the original
  2016 "forbidden attack" scan found real HTTPS servers doing this).
- A challenge that gives you many `(ct, tag)` pairs and asks for a tag on a new message.

## Theory

Let `H = E_k(0^{128})` and, for a 96-bit nonce, `J0 = nonce || 0^{31} 1`.

- Confidentiality: `C = P xor GCTR_k(J0 + 1)`. Identical to CTR.
- Authenticity: build the GHASH input
  `X = A || pad(A) || C || pad(C) || [len(A)*8]_{64} || [len(C)*8]_{64}`,
  split into 16-byte blocks `X_1 ... X_m`, and compute

$$\mathrm{GHASH}_H(X) = \sum_{i=1}^{m} X_i \cdot H^{\,m-i+1}$$

  (all arithmetic in `GF(2^128)` with the GCM reduction polynomial
  `x^128 + x^7 + x^2 + x + 1`, bit-reflected byte order). Finally

$$T = \mathrm{GHASH}_H(X) \oplus E_k(J_0)$$

Now take two messages under the **same nonce**. `E_k(J0)` is the same for both, so

$$T_1 \oplus T_2 = \sum_{i=1}^{m} (X^{(1)}_i \oplus X^{(2)}_i)\, H^{\,m-i+1}$$

This is a known polynomial in the single unknown `H`. Its roots (found by
square-free + distinct-degree + equal-degree factorisation, i.e. Cantor-Zassenhaus,
over `GF(2^128)`) include the real `H`. A third `(ct, tag)` pair under the same nonce
prunes the candidate list to one.

**The easy CTF case.** If the two messages have the **same length** and the same AAD,
the length block and the AAD blocks cancel, leaving only the ciphertext differences.
If they additionally differ in exactly one ciphertext block `j` (out of `n`), the sum
collapses to a single term:

$$T_1 \oplus T_2 = \Delta C_j \cdot H^{\,k}, \qquad k = n - j + 2$$

so

$$H^{\,k} = \Delta T \cdot \Delta C_j^{-1}$$

The multiplicative group of `GF(2^128)` has order `N = 2^{128} - 1`, which is **odd**.
So whenever `gcd(k, N) = 1` the `k`-th root is unique and is just another exponentiation:

$$H = \left(H^{k}\right)^{k^{-1} \bmod N}$$

Picking the **last** ciphertext block as the differing one gives `k = 2`, and
`2^{-1} mod (2^{128}-1) = 2^{127}`, i.e. `H = (H^2)^{2^{127}}` - a plain square root,
127 squarings. No factorisation needed, no candidate ambiguity.

`N = 2^128 - 1 = 3 * 5 * 17 * 257 * 641 * 65537 * 274177 * 6700417 * 67280421310721`,
so any `k` avoiding those factors works too.

**After recovering H**, get the one-time mask back:

$$E_k(J_0) = T_1 \oplus \mathrm{GHASH}_H(X^{(1)})$$

and you can now compute a correct tag for *any* `(A, C)` under that nonce. Combined
with keystream reuse (`aes-ctr-nonce-reuse`) you can encrypt-and-authenticate arbitrary
plaintexts. You do **not** learn the AES key itself.

## Attack

1. Collect at least two `(nonce, aad, ct, tag)` triples sharing a nonce. Prefer two of
   the same length and same AAD.
2. If they differ in exactly one ciphertext block, compute `dT`, `dC_j`, `k`, and take
   the `k`-th root. Otherwise, build the difference polynomial and factor it in Sage:
   `F.<x> = GF(2^128, modulus=x^128+x^7+x^2+x+1)[]` then `poly.roots()`.
3. Validate each candidate `H` against a third pair; discard the ones whose recomputed
   tag does not match.
4. Recover `E_k(J0) = T xor GHASH_H(X)`.
5. Recover the keystream from a known plaintext, build the ciphertext you want, and
   compute its tag. Send `(nonce, aad', ct', tag')`.

## Code

```python
#!/usr/bin/env python3
"""AES-GCM forbidden attack: recover the GHASH authentication key H from a reused
nonce, then forge a tag that pycryptodome itself accepts.

Pure Python GF(2^128) / GHASH so the maths is visible and verifiable.
"""

import os
from math import gcd
from Crypto.Cipher import AES

BS = 16
R = 0xE1 << 120                      # GCM reduction constant, bit-reflected
ORDER = (1 << 128) - 1               # order of the multiplicative group


# ------------------------------------------------------------ GF(2^128)
def gf_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) with the GCM bit-reflected convention (SP 800-38D)."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def gf_pow(x: int, e: int) -> int:
    result, base = 1 << 127, x        # 1 is the block 0x80 00 ... 00
    while e:
        if e & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        e >>= 1
    return result


def gf_inv(x: int) -> int:
    assert x != 0
    return gf_pow(x, ORDER - 1)


def gf_kth_root(x: int, k: int) -> int:
    """Unique k-th root when gcd(k, 2^128 - 1) == 1."""
    if gcd(k, ORDER) != 1:
        raise ValueError(f"k={k} shares a factor with 2^128-1; use polynomial roots")
    return gf_pow(x, pow(k, -1, ORDER))


def b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def i2b(i: int) -> bytes:
    return i.to_bytes(16, "big")


# ---------------------------------------------------------------- GHASH
def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * ((-len(data)) % BS)


def ghash_blocks(aad: bytes, ct: bytes) -> list[int]:
    """The X_1..X_m blocks GHASH consumes, as GF(2^128) elements."""
    data = _pad16(aad) + _pad16(ct)
    data += (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    return [b2i(data[i:i + BS]) for i in range(0, len(data), BS)]


def ghash(h: int, aad: bytes, ct: bytes) -> int:
    y = 0
    for blk in ghash_blocks(aad, ct):
        y = gf_mul(y ^ blk, h)
    return y


def gcm_tag(h: int, ek_j0: int, aad: bytes, ct: bytes) -> bytes:
    """Tag = GHASH_H(A, C) xor E_k(J0). Needs no key once H and the mask are known."""
    return i2b(ghash(h, aad, ct) ^ ek_j0)


# ------------------------------------------------------------ the attack
def recover_h_single_block_diff(aad: bytes, ct1: bytes, tag1: bytes,
                                ct2: bytes, tag2: bytes) -> int:
    """H from two same-length ciphertexts (same nonce, same AAD) differing in one block.

    T1 xor T2 = dC_j * H^(n-j+2)  ->  H = (dT / dC_j)^(1/k).
    """
    assert len(ct1) == len(ct2), "this shortcut needs equal lengths"
    n = (len(ct1) + BS - 1) // BS
    b1 = ghash_blocks(aad, ct1)
    b2 = ghash_blocks(aad, ct2)
    diff = [i for i, (a, b) in enumerate(zip(b1, b2)) if a != b]
    assert len(diff) == 1, f"expected exactly one differing block, got {diff}"
    idx = diff[0]                             # 0-based index into X_1..X_m
    n_aad = len(_pad16(aad)) // BS
    j = idx - n_aad + 1                       # 1-based ciphertext block number
    k = n - j + 2
    d_ct = b1[idx] ^ b2[idx]
    d_tag = b2i(tag1) ^ b2i(tag2)
    return gf_kth_root(gf_mul(d_tag, gf_inv(d_ct)), k)


def recover_ek_j0(h: int, aad: bytes, ct: bytes, tag: bytes) -> int:
    """The one-time mask E_k(J0) for this nonce."""
    return b2i(tag) ^ ghash(h, aad, ct)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------------ vulnerable service
class GcmService:
    """Encrypts everything under one key and ONE nonce. That is the whole bug."""

    def __init__(self) -> None:
        self.key = os.urandom(16)
        self.nonce = os.urandom(12)

    def encrypt(self, pt: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        c = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        c.update(aad)
        return c.encrypt_and_digest(pt)

    def decrypt(self, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        c = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        c.update(aad)
        return c.decrypt_and_verify(ct, tag)          # raises on a bad tag


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    svc = GcmService()
    AAD = b"hdr:v1"

    # Two messages of the same length that differ only in the LAST block.
    # (Same nonce -> same keystream -> the ciphertexts differ only there too.)
    P1 = b"transfer 0000001" b"0 EUR to acct 77"
    P2 = b"transfer 0000001" b"0 EUR to acct 42"
    ct1, tag1 = svc.encrypt(P1, AAD)
    ct2, tag2 = svc.encrypt(P2, AAD)
    assert ct1[:16] == ct2[:16] and ct1[16:] != ct2[16:]
    print("[+] two ciphertexts under one nonce, differing in block 2 only")

    # --- our GHASH matches the library's -----------------------------------
    real_h = b2i(AES.new(svc.key, AES.MODE_ECB).encrypt(b"\x00" * 16))
    j0 = svc.nonce + b"\x00\x00\x00\x01"
    real_mask = b2i(AES.new(svc.key, AES.MODE_ECB).encrypt(j0))
    assert gcm_tag(real_h, real_mask, AAD, ct1) == tag1
    assert gcm_tag(real_h, real_mask, AAD, ct2) == tag2
    print("[+] pure-Python GHASH reproduces pycryptodome's tags exactly")

    # --- recover H ---------------------------------------------------------
    h = recover_h_single_block_diff(AAD, ct1, tag1, ct2, tag2)
    print("[+] recovered H   :", i2b(h).hex())
    print("[+] real      H   :", i2b(real_h).hex())
    assert h == real_h
    print("[+] PASS authentication key recovery")

    # --- recover the one-time mask ----------------------------------------
    mask = recover_ek_j0(h, AAD, ct1, tag1)
    assert mask == real_mask
    print("[+] PASS E_k(J0) recovery:", i2b(mask).hex())

    # --- forge a tag for a message the service never produced --------------
    keystream = xor(ct1, P1)                       # CTR keystream reuse
    EVIL = b"transfer 9999999" b"9 EUR to acct 13"
    evil_ct = xor(EVIL, keystream)
    evil_tag = gcm_tag(h, mask, AAD, evil_ct)
    got = svc.decrypt(evil_ct, evil_tag, AAD)      # decrypt_and_verify, real AES-GCM
    print("[+] forged message accepted:", got)
    assert got == EVIL
    print("[+] PASS tag forgery of a same-length message")

    # --- forge a DIFFERENT length, and a different AAD ---------------------
    # We have H and the mask, so any (aad, ct) under this nonce can be tagged.
    short_ct = evil_ct[:5]
    short_tag = gcm_tag(h, mask, b"other-aad", short_ct)
    got = svc.decrypt(short_ct, short_tag, b"other-aad")
    assert got == EVIL[:5]
    print("[+] PASS forgery with a different length and a different AAD:", got)

    # --- empty message, empty AAD -----------------------------------------
    empty_tag = gcm_tag(h, mask, b"", b"")
    assert svc.decrypt(b"", empty_tag, b"") == b""
    print("[+] PASS forgery of the empty message")

    # --- sanity: an arbitrary tag is rejected ------------------------------
    try:
        svc.decrypt(evil_ct, bytes(16), AAD)
        raise SystemExit("a random tag must not verify")
    except ValueError:
        print("[+] random tags are still rejected -- the forgery is real")

    # --- k-th root machinery -----------------------------------------------
    for k in (2, 3, 4, 7, 11):
        if gcd(k, ORDER) != 1:
            continue
        assert gf_kth_root(gf_pow(real_h, k), k) == real_h
    print("[+] PASS gf_kth_root for k in {2,3,4,7,11}")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Nonce not 96 bits.** If the IV is not 12 bytes, `J0 = GHASH_H(IV || pad || [0]_64
  || [len(IV)*8]_64)` instead of `IV || 0^31 1`. The attack still works - you recover
  `E_k(J0)` as an opaque mask - but you cannot compute `J0` yourself without `H`,
  which you have, so recompute it after recovering `H`.
- **General difference polynomial.** When the two messages differ in several blocks or
  have different lengths, you must factor a degree-`m` polynomial over `GF(2^128)`.
  Do it in SageMath:
  `K.<a> = GF(2^128, modulus=x^128+x^7+x^2+x+1); P.<X> = K[]; f.roots()`.
  Filter the roots with a third `(ct, tag)` pair.
- **`gcd(k, 2^128-1) != 1`.** Then the `k`-th root is not unique; there are `gcd`
  candidates. Enumerate them, or arrange for a different `k` by choosing which pair of
  messages you use.
- **Byte order.** GCM's `GF(2^128)` is bit-reflected: the first bit of the block is the
  *highest* coefficient and the shift in the multiply goes **right**, not left. A
  "normal" `GF(2^128)` multiply will silently produce garbage. Always cross-check your
  GHASH against a library tag before trusting it, as the self-test above does.
- **Truncated tags** (8 or 12 bytes) make `dT` incomplete; the polynomial approach
  needs the full 16-byte tags. With truncated tags you instead get many candidates and
  need more pairs.
- **AES-GCM-SIV** is nonce-misuse *resistant*: reusing a nonce only reveals that two
  plaintexts are equal. This attack does not apply. Neither does it to AES-SIV or
  XChaCha20-Poly1305 with a random 192-bit nonce.
- **Poly1305 nonce reuse** is the analogous ChaCha20-Poly1305 disaster: the one-time
  key `r, s` is reused and the authenticator becomes solvable. Different field
  (`2^130 - 5`), same shape of bug.
- **You never recover the AES key.** Only `H` and the per-nonce mask. Messages under a
  *different* nonce stay safe (though `H` is nonce-independent, so `H` is reusable -
  what you lack for another nonce is `E_k(J0')`).

## Tools

- `pycryptodome` - `AES.MODE_GCM`, `encrypt_and_digest`, `decrypt_and_verify`.
- SageMath - polynomial root finding over `GF(2^128)` in two lines.
- The `nonce-disrespecting-adversaries` toolkit released with the 2016 TLS research
  automates the full forbidden attack against captured TLS records.

## References

- Antoine Joux, "Authentication Failures in NIST version of GCM" (comment to NIST) -
  the original observation that nonce reuse breaks GCM authenticity.
- Boeck, Zauner, Devlin, Somorovsky, Jovanovic, "Nonce-Disrespecting Adversaries:
  Practical Forgery Attacks on GCM in TLS" (WOOT 2016).
- NIST SP 800-38D defines GCM, GHASH and the `GF(2^128)` convention used above.
