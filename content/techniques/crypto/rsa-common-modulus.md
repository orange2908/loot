---
title: "RSA - Common Modulus Attack (same n, two coprime e)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, common-modulus, same-modulus, two-exponents, gcd, bezout, extended-euclidean, extended-gcd, egcd, modular-inverse, coprime, shared-modulus, rsactftool, e1-e2]
difficulty: easy
summary: "Same plaintext encrypted twice under the same n with two coprime exponents -> Bezout gives m with no factoring."
when_to_use:
  - "Two ciphertexts c1, c2 of the SAME message under the SAME modulus n"
  - "Two different public exponents e1 != e2 with gcd(e1, e2) == 1"
  - "A service re-encrypts your message for two users that share n"
  - "Handout contains n, e1, c1, e2, c2 and nothing else"
  - "gcd(e1, e2) = g > 1: still works, you recover m^g then take a g-th root"
tools: [python3, gmpy2, rsactftool]
source:
  name: "CTF Wiki - RSA common modulus attack"
  url: "https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/"
related: [rsa-small-e, rsa-eth-root-amm, rsa-common-factor-batch-gcd]
---

## TL;DR

If `c1 = m^e1 mod n` and `c2 = m^e2 mod n` with `gcd(e1, e2) = 1`, extended Euclid gives
`a*e1 + b*e2 = 1`, hence `c1^a * c2^b = m^(a*e1 + b*e2) = m mod n`.
One of `a`, `b` is negative, so invert the corresponding ciphertext.
No factoring, no `d`, works for any modulus size. Runs in milliseconds.

## Recognise it

- The handout lists **one** `n` and **two** `(e, c)` pairs.
- A server encrypts the flag "for Alice" and "for Bob" but the key generation reuses `n`.
- Two users of the same system were given different exponents but the same modulus
  (this is the real-world "common modulus failure" of RSA).
- `gcd(e1, e2) == 1` (very often `e1 = 65537`, `e2 = 3` or two random primes).
- A padding-free `pow(m, e, n)` in the source.

## Theory

Bezout: for coprime $e_1, e_2$ there exist integers $a, b$ (one of them negative) with

$$a e_1 + b e_2 = \gcd(e_1,e_2) = 1$$

Then

$$c_1^{a} c_2^{b} \equiv m^{a e_1} m^{b e_2} \equiv m^{a e_1 + b e_2} \equiv m \pmod n$$

A negative exponent means a modular inverse: $c^{-k} = (c^{-1})^{k} \bmod n$, which exists
because $\gcd(c, n) = 1$ (if it is not 1, you just factored `n` - even better).

If $g = \gcd(e_1,e_2) > 1$ the same computation yields $m^{g} \bmod n$, and you finish with
an integer $g$-th root (if $m^g < n$) or an AMM $g$-th root modulo the factors.

**Bonus:** knowing two exponents with the same `n` and one private key also lets you factor
`n` (see `rsa-known-phi-known-d`), because any valid `d` reveals a multiple of `lambda(n)`.

## Attack

1. `g, a, b = egcd(e1, e2)`.
2. If `g != 1`, remember you will only get `m^g`.
3. Normalise negative exponents: if `a < 0`, replace `c1` by `inverse(c1, n)` and `a` by `-a`.
4. `m = pow(c1, a, n) * pow(c2, b, n) % n`.
5. `long_to_bytes(m)`.

## Code

```python
#!/usr/bin/env python3
"""RSA common-modulus attack: same n, two coprime exponents.

    python3 rsa_common_modulus.py                 # self-test
    python3 rsa_common_modulus.py N E1 C1 E2 C2   # solve a real instance
"""
from __future__ import annotations

import sys

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:  # pure-python fallback, pycryptodome not required
    import random as _r

    def bytes_to_long(b: bytes) -> int:
        return int.from_bytes(b, "big")

    def long_to_bytes(x: int) -> bytes:
        return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")

    def _is_prime(n: int) -> bool:
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def getPrime(bits: int) -> int:
        while True:
            c = _r.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_prime(c):
                return c


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: returns (g, x, y) with a*x + b*y == g == gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def iroot(x: int, n: int) -> tuple[int, bool]:
    """Exact integer n-th root (Newton)."""
    if x < 0:
        raise ValueError("negative radicand")
    if x == 0:
        return 0, True
    r = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        nr = ((n - 1) * r + x // r ** (n - 1)) // n
        if nr >= r:
            break
        r = nr
    return r, r ** n == x


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> tuple[int, int]:
    """Return (value, g) where value == m**g mod n and g == gcd(e1, e2).

    When g == 1 the value IS the plaintext.
    Raises a helpful error if a ciphertext shares a factor with n (jackpot: factored n).
    """
    g, a, b = egcd(e1, e2)
    x1, x2 = c1 % n, c2 % n
    if a < 0:
        try:
            x1 = pow(x1, -1, n)
        except ValueError:
            raise ValueError(f"c1 not invertible, gcd = {__import__('math').gcd(x1, n)} -> n is factored")
        a = -a
    if b < 0:
        try:
            x2 = pow(x2, -1, n)
        except ValueError:
            raise ValueError(f"c2 not invertible, gcd = {__import__('math').gcd(x2, n)} -> n is factored")
        b = -b
    return pow(x1, a, n) * pow(x2, b, n) % n, g


def solve(n: int, e1: int, c1: int, e2: int, c2: int) -> bytes | None:
    """Full solver: handles gcd(e1, e2) > 1 by taking an integer g-th root."""
    val, g = common_modulus(n, e1, c1, e2, c2)
    if g == 1:
        return long_to_bytes(val)
    print(f"[!] gcd(e1, e2) = {g}; recovered m^{g} mod n, trying integer {g}-th root")
    for k in range(1 << 14):
        r, exact = iroot(val + k * n, g)
        if exact:
            return long_to_bytes(r)
    print("[-] g-th root not exact: see rsa-eth-root-amm for roots modulo p and q")
    return None


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    random.seed(1337)

    # --- classic coprime case ---------------------------------------------- #
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e1, e2 = 65537, 3
    flag = b"CTF{one_modulus_two_exponents_zero_security}"
    m = bytes_to_long(flag)
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    assert solve(n, e1, c1, e2, c2) == flag
    print("[+] coprime case ok")

    # --- both exponents large and random ----------------------------------- #
    e1, e2 = 0xdeadbeef, 0x1000003
    assert egcd(e1, e2)[0] == 1
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    val, g = common_modulus(n, e1, c1, e2, c2)
    assert g == 1 and val == m
    print("[+] large random exponents ok")

    # --- gcd(e1, e2) = 3 --------------------------------------------------- #
    e1, e2 = 3 * 5, 3 * 7
    short = bytes_to_long(b"CTF{gcd_is_three}")     # short enough that m^3 < n
    c1, c2 = pow(short, e1, n), pow(short, e2, n)
    val, g = common_modulus(n, e1, c1, e2, c2)
    assert g == 3 and val == pow(short, 3, n)
    assert solve(n, e1, c1, e2, c2) == b"CTF{gcd_is_three}"
    print("[+] gcd(e1, e2) = 3 case ok")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 6:
        N, E1, C1, E2, C2 = (int(v, 0) for v in sys.argv[1:6])
        print(solve(N, E1, C1, E2, C2))
    else:
        _selftest()
```

## Variants & pitfalls

- **Wrong pairing.** Make sure `c1` really is the encryption under `e1`. Swapping them gives
  garbage; if the output is junk, try the other assignment.
- **`gcd(e1, e2) = g > 1`**: you get `m^g`. Take an integer `g`-th root if the message is
  short, else use AMM (`rsa-eth-root-amm`) after factoring, or find a third exponent.
- **Non-invertible ciphertext**: `pow(c, -1, n)` raising `ValueError` means `gcd(c, n) > 1`,
  which hands you a factor of `n`. Take the win.
- **Same e, different n** is a different attack: `rsa-hastad-broadcast` (if e is small) or
  `rsa-common-factor-batch-gcd` (if the moduli share a prime).
- **Padded messages**: if each encryption used *fresh random* padding, the plaintexts differ
  and this attack fails - look at `rsa-franklin-reiter` instead.
- Negative exponents in Python: `pow(c, -a, n)` works natively in 3.8+ and is the cleanest
  way to write the whole attack:
  `m = pow(c1, a, n) * pow(c2, b, n) % n` with raw signed `a, b`.

## Tools

```bash
# RsaCtfTool has a dedicated mode
python3 RsaCtfTool.py -n <N> -e <E1> --uncipher <C1> --attack common_modulus \
    --e2 <E2> --c2 <C2>

# three-line manual version
python3 - <<'PY'
n,e1,c1,e2,c2 = 0,0,0,0,0   # fill in
from math import gcd
g = gcd(e1, e2); assert g == 1
a = pow(e1, -1, e2); b = (g - a*e1)//e2
print(pow(c1, a, n) * pow(c2, b, n) % n)
PY
```

## References

- CTF Wiki, common modulus attack: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
