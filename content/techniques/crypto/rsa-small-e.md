---
title: "RSA - Small Public Exponent / Cube Root (No Padding)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, small-e, cube-root, nth-root, iroot, e-3, e-equals-3, textbook-rsa, no-padding, unpadded, short-message, integer-root, gmpy2, sympy, rsactftool, low-exponent]
difficulty: easy
summary: "e is tiny (3, 5, 17) and the message is short, so m^e never wraps mod n -> take a plain integer e-th root of c."
when_to_use:
  - "e is 3, 5, 7 or 17 and there is exactly one ciphertext"
  - "The plaintext is a short flag and the modulus is 1024+ bits"
  - "c is noticeably smaller than n, or c is a perfect e-th power over the integers"
  - "Source shows pow(m, e, n) with no OAEP/PKCS padding"
  - "gmpy2.iroot(c, e)[1] is True"
tools: [gmpy2, sympy, rsactftool, python3]
source:
  name: "CTF Wiki - RSA low exponent attacks"
  url: "https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/"
related: [rsa-hastad-broadcast, rsa-coppersmith, rsa-eth-root-amm]
---

## TL;DR

Textbook RSA encrypts `c = m^e mod n`. If `m^e < n` the modular reduction never happens, so
`c` *is* `m^e` over the integers and `m = iroot(c, e)`. If it wrapped only a few times,
`m^e = c + k*n` for a small `k`, so brute-force `k` and test for an exact root.
Costs nothing to try; always try it first when `e` is small.

## Recognise it

- Challenge source literally does `c = pow(bytes_to_long(flag), 3, n)`.
- `e` printed in the handout is `3`, `5`, `7`, `17`, or `0x10001` only in the decoy.
- `len(hex(c))` is much shorter than `len(hex(n))` -> no reduction happened at all.
- A single ciphertext is given (if there are three ciphertexts and three moduli, go to Hastad).
- `gmpy2.iroot(c, e)` returns `exact = True`.
- The flag is short (< 64 bytes) while `n` is 1024/2048 bits: `m^3` is only ~3x the flag's
  bit length, far below `n`.

## Theory

Let $m < 2^{L}$ (flag bit length $L$) and $n < 2^{N}$.
Encryption is $c \equiv m^e \pmod n$, i.e. $m^e = c + k n$ for some integer $k \ge 0$.

- If $eL < N$ then $m^e < n$, forcing $k = 0$, so $c = m^e$ exactly and $m = \sqrt[e]{c}$.
- If $eL$ is only slightly larger than $N$, then $k < 2^{eL-N}$, which is brute-forceable
  whenever $eL - N$ is below ~30 bits.
- If $eL \gg N$ the attack dies; you need Coppersmith (partially known plaintext) or
  Hastad (several moduli) instead.

Integer $e$-th roots must be computed exactly, never with floats: `round(c ** (1/3))`
loses precision above 2^53 and will silently give the wrong answer.

## Attack

1. Try an exact integer root of `c`. If exact, done.
2. Otherwise loop `k = 0, 1, 2, ...` and test `iroot(c + k*n, e)` for exactness.
3. If `m` is the raw flag, `long_to_bytes(m)` prints it directly.
4. If the root never comes out exact within a sane `k` bound, the plaintext is padded /
   too large: switch to `rsa-coppersmith` (stereotyped message) or `rsa-hastad-broadcast`.

## Code

```python
#!/usr/bin/env python3
"""RSA small-public-exponent (cube root) attack.

Pure stdlib. gmpy2 is used automatically if installed, but is not required.

    python3 rsa_small_e.py            # runs the self-test
"""
from __future__ import annotations

import sys


def iroot(x: int, n: int) -> tuple[int, bool]:
    """Exact integer n-th root via Newton iteration.

    Returns (r, exact) where r = floor(x ** (1/n)) and exact says whether r**n == x.
    Never use floating point here: float64 breaks above 2**53.
    """
    if x < 0:
        raise ValueError("negative radicand")
    if x == 0:
        return 0, True
    if n == 1:
        return x, True
    r = 1 << ((x.bit_length() + n - 1) // n)  # upper bound, 2**ceil(bits/n)
    while True:
        nr = ((n - 1) * r + x // r ** (n - 1)) // n
        if nr >= r:
            break
        r = nr
    return r, r ** n == x


def l2b(x: int) -> bytes:
    """long_to_bytes without pycryptodome."""
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def b2l(b: bytes) -> int:
    return int.from_bytes(b, "big")


def small_e_attack(c: int, e: int, n: int, max_k: int = 1 << 18) -> int | None:
    """Recover m from c = m^e mod n when m^e wrapped at most max_k times."""
    for k in range(max_k):
        m, exact = iroot(c + k * n, e)
        if exact:
            return m
    return None


def small_e_attack_known_suffix(c: int, e: int, n: int, suffix: bytes,
                                max_k: int = 1 << 16) -> int | None:
    """Variant: the plaintext is known to end with `suffix` (e.g. b'}').

    Useful as a sanity filter when several k give exact roots (rare but possible
    for very small n).
    """
    for k in range(max_k):
        m, exact = iroot(c + k * n, e)
        if exact and l2b(m).endswith(suffix):
            return m
    return None


def decrypt_if_e_is_small_but_m_is_not(c: int, e: int, n: int) -> None:
    """Diagnostic helper: tells you whether this attack can possibly work."""
    approx_m_bits = (c.bit_length() + e - 1) // e
    print(f"[i] n is {n.bit_length()} bits, e = {e}")
    print(f"[i] c is {c.bit_length()} bits -> m is at most ~{approx_m_bits} bits if k == 0")
    if c.bit_length() < n.bit_length() - 8:
        print("[+] c << n: almost certainly no reduction happened, iroot should be exact")
    else:
        print("[!] c is full size: either k > 0, or the message is padded (use Coppersmith)")


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random

    random.seed(0xC0FFEE)

    def gen_prime(bits: int) -> int:
        while True:
            cand = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_probable_prime(cand):
                return cand

    # --- case 1: no wraparound at all -------------------------------------- #
    p, q = gen_prime(512), gen_prime(512)
    n = p * q
    e = 3
    flag = b"CTF{no_padding_means_no_security}"
    m = b2l(flag)
    c = pow(m, e, n)
    assert m ** e < n, "test instance is wrong"
    rec = small_e_attack(c, e, n)
    assert rec == m, "plain cube root failed"
    assert l2b(rec) == flag
    print("[+] case 1 (m^e < n):", l2b(rec).decode())

    # --- case 2: wrapped a few times --------------------------------------- #
    # make m big enough that m^3 is ~12 bits wider than n
    p, q = gen_prime(256), gen_prime(256)
    n = p * q                       # ~512 bits
    e = 3
    base = b2l(b"CTF{k_is_small}")
    m = base << (175 - base.bit_length())   # exactly 175 bits -> m**3 is 525 bits
    c = pow(m, e, n)
    k_real = (m ** e - c) // n
    assert k_real > 0
    rec = small_e_attack(c, e, n, max_k=1 << 14)
    assert rec == m, f"brute-k cube root failed (real k = {k_real})"
    print(f"[+] case 2 (k = {k_real}): recovered m = {hex(rec)}")

    # --- case 3: e = 5 ------------------------------------------------------ #
    p, q = gen_prime(512), gen_prime(512)
    n = p * q
    e = 5
    m = b2l(b"CTF{five_is_no_better}")   # 21 bytes -> m**5 is ~840 bits < n
    c = pow(m, e, n)
    assert small_e_attack(c, e, n) == m
    print("[+] case 3 (e = 5): ok")

    print("[*] all self-tests passed")


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


if __name__ == "__main__":
    if len(sys.argv) == 4:
        n_, e_, c_ = (int(v, 0) for v in sys.argv[1:4])
        decrypt_if_e_is_small_but_m_is_not(c_, e_, n_)
        m_ = small_e_attack(c_, e_, n_)
        print("m =", m_)
        if m_ is not None:
            print("bytes =", l2b(m_))
    else:
        _selftest()
```

## Variants & pitfalls

- **Float roots lie.** `int(c ** (1/3))` is wrong for anything above 2^53. Use Newton /
  `gmpy2.iroot` / `sympy.integer_nthroot`.
- **`gmpy2.iroot(c, e)` returns a tuple** `(root, is_exact)`; people forget the `[1]` check
  and "decrypt" garbage.
- **k can be huge.** If `e * len(m) >> len(n)` the number of wraps is astronomic; stop and
  switch attack. A quick check: `k_max ~ 2**(e*mbits - nbits)`.
- **Partially known plaintext** (`flag{...}` prefix known, few unknown bytes) -> Coppersmith
  stereotyped message, not brute-force `k`.
- **Several ciphertexts, several moduli, same small e** -> Hastad broadcast (CRT then root).
- **Padded with random bytes each time** -> Franklin-Reiter (if related) or Coppersmith short pad.
- **`e = 1`** is a degenerate freebie: `m = c`.
- **`e` small but `gcd(e, phi) != 1`**: encryption is not injective; see `rsa-eth-root-amm`.
- If the root is exact but the bytes look like garbage, try `iroot` on `c` for e = 2..64;
  challenge authors sometimes label `e` incorrectly.

## Tools

```bash
# RsaCtfTool, dedicated attack module
python3 RsaCtfTool.py -n <N> -e 3 --uncipher <C> --attack cube_root

# one-liner with gmpy2
python3 -c 'import gmpy2;c=<C>;r,ok=gmpy2.iroot(c,3);print(ok, bytes.fromhex(hex(r)[2:]))'

# sympy, no gmpy2 needed
python3 -c 'from sympy import integer_nthroot;print(integer_nthroot(<C>,3))'
```

## References

- CTF Wiki, RSA attack collection: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
- PKCS #1 v2.2 (why padding exists): https://www.rfc-editor.org/rfc/rfc8017
