---
title: "RSA - Hastad Broadcast Attack (same m, e moduli, small e)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, hastad, hastad-broadcast, broadcast, crt, chinese-remainder-theorem, small-e, e-3, cube-root, nth-root, same-message, multiple-moduli, coppersmith, linear-padding, rsactftool, sympy, gmpy2]
difficulty: easy
summary: "Same message sent to e recipients with the same small e -> CRT the ciphertexts into m^e mod prod(n_i), then take an exact e-th root."
when_to_use:
  - "The same plaintext is encrypted under e (or more) different moduli with the same small e"
  - "Handout is a list of (n_i, c_i) pairs with e = 3 and at least 3 entries"
  - "A service broadcasts the flag to several 'users', each with their own key"
  - "e = 5 and you have 5 ciphertexts, e = 17 and you have 17, etc."
  - "Messages are padded linearly (m_i = a_i*m + b_i) -> Hastad + Coppersmith variant"
tools: [python3, gmpy2, sympy, sage, rsactftool]
source:
  name: "CTF Wiki - RSA broadcast attack"
  url: "https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/"
related: [rsa-small-e, rsa-coppersmith, rsa-common-factor-batch-gcd, rsa-franklin-reiter]
---

## TL;DR

With `e` ciphertexts of the *same* `m` under `e` pairwise-coprime moduli, CRT gives
`M = m^e mod (n_1 * ... * n_e)`. Because `m < min(n_i)`, `m^e < prod(n_i)`, so `M` is
exactly `m^e` over the integers and `m = iroot(M, e)`. No factoring, no oracle.

## Recognise it

- The handout is `[(n1, c1), (n2, c2), (n3, c3)]` with `e = 3` printed once.
- A netcat service says "sending the flag to 3 users" and prints 3 moduli.
- All moduli are different, all `e` are equal and small.
- You have *at least* `e` ciphertexts (fewer is not enough unless the padding is known
  and you can use Coppersmith).
- If two moduli share a factor, `gcd` beats Hastad - always check first.

## Theory

Let $c_i \equiv m^e \pmod{n_i}$ for $i = 1..e$ with the $n_i$ pairwise coprime.
CRT yields a unique $M < \prod n_i$ with $M \equiv m^e \pmod{\prod n_i}$.
Since $m < n_i$ for all $i$,

$$m^e < \prod_{i=1}^{e} n_i \quad\Longrightarrow\quad M = m^e \text{ over } \mathbb{Z}$$

so an exact integer $e$-th root recovers $m$.

**Padded variant.** If each recipient got $m_i = a_i m + b_i$ (fixed, *known* linear
padding), you cannot root directly. Instead build
$g_i(x) = (a_i x + b_i)^e - c_i \bmod n_i$, CRT the coefficients into one polynomial modulo
$\prod n_i$, make it monic, and run Coppersmith's univariate `small_roots`: the root $m$ is
smaller than $(\prod n_i)^{1/e}$, which is inside the bound. That is Hastad's theorem in
its general form (it needs $k > e$ ciphertexts for a comfortable margin).

## Attack

1. Check `gcd(n_i, n_j) == 1` for all pairs (if not: you just factored two keys, done).
2. CRT the `(c_i, n_i)` pairs -> `M`.
3. `m, exact = iroot(M, e)`; `exact` must be True.
4. If not exact: you have fewer than `e` ciphertexts, or there is padding. Add more
   ciphertexts, or go to the Coppersmith variant.

## Code

```python
#!/usr/bin/env python3
"""Hastad broadcast attack (plain and linear-padding variants).

    python3 rsa_hastad.py            # self-test
    python3 rsa_hastad.py pairs.txt  # lines of "n c", e taken from argv[2] (default 3)
"""
from __future__ import annotations

import sys
from math import gcd

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:
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


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """Garner-free CRT. Returns (x, M) with x = residue mod M = prod(moduli)."""
    x, M = 0, 1
    for r, m in zip(residues, moduli):
        g = gcd(M, m)
        if g != 1:
            raise ValueError(f"moduli not coprime, gcd = {g} (that is a factor!)")
        # solve x + M*t = r (mod m)
        t = (r - x) * pow(M, -1, m) % m
        x += M * t
        M *= m
    return x % M, M


def iroot(x: int, n: int) -> tuple[int, bool]:
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


def check_pairwise_coprime(moduli: list[int]) -> None:
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if g != 1:
                raise SystemExit(f"[!] n[{i}] and n[{j}] share the factor {g} - "
                                 f"factor them instead of running Hastad")


def hastad(ciphertexts: list[int], moduli: list[int], e: int) -> int | None:
    """Plain Hastad: needs at least e ciphertexts of the same unpadded message."""
    check_pairwise_coprime(moduli)
    if len(moduli) < e:
        print(f"[!] only {len(moduli)} ciphertexts for e = {e}; "
              f"the root will not be exact unless m is small")
    M, _ = crt(ciphertexts[:max(e, len(ciphertexts))], moduli[:max(e, len(moduli))])
    m, exact = iroot(M, e)
    if exact:
        return m
    # the message might still be recoverable if it wrapped a little
    for k in range(1, 1 << 12):
        m, exact = iroot(M + k * _prod(moduli), e)
        if exact:
            return m
    return None


def _prod(xs: list[int]) -> int:
    out = 1
    for x in xs:
        out *= x
    return out


# --------------------------------------------------------------------------- #
# linear-padding variant:  m_i = a_i * m + b_i
# --------------------------------------------------------------------------- #
def poly_mul(a: list[int], b: list[int], mod: int) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] = (out[i + j] + x * y) % mod
    return out


def hastad_linear_padding_poly(pairs, e: int):
    """Build the CRT'd polynomial g(x) = sum_i T_i * ((a_i x + b_i)^e - c_i) mod prod(n_i).

    `pairs` is a list of (n_i, c_i, a_i, b_i). Returns (coeffs, N) where a root of
    coeffs modulo N smaller than N^(1/e) is the message. Feed that to Coppersmith
    (see rsa-coppersmith for a pure-python small_roots, or use Sage's small_roots).
    """
    moduli = [p[0] for p in pairs]
    check_pairwise_coprime(moduli)
    N = _prod(moduli)
    total = [0] * (e + 1)
    for n_i, c_i, a_i, b_i in pairs:
        # (a x + b)^e - c   over Z_{n_i}
        g = [1]
        for _ in range(e):
            g = poly_mul(g, [b_i % n_i, a_i % n_i], n_i)
        g[0] = (g[0] - c_i) % n_i
        # CRT coefficient-wise: T_i = (N/n_i) * inv(N/n_i, n_i)
        Ni = N // n_i
        T = Ni * pow(Ni, -1, n_i)
        for k, coef in enumerate(g):
            total[k] = (total[k] + T * coef) % N
    # make monic
    inv = pow(total[e], -1, N)
    return [(x * inv) % N for x in total], N


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    random.seed(20260101)

    # --- plain broadcast, e = 3, three moduli ------------------------------ #
    e = 3
    flag = b"CTF{broadcast_the_same_plaintext_and_lose}"
    m = bytes_to_long(flag)
    ns, cs = [], []
    for _ in range(e):
        n = getPrime(512) * getPrime(512)
        ns.append(n)
        cs.append(pow(m, e, n))
    assert all(m < n for n in ns)
    rec = hastad(cs, ns, e)
    assert rec == m, "hastad failed"
    assert long_to_bytes(rec) == flag
    print("[+] e = 3 broadcast:", long_to_bytes(rec).decode())

    # --- e = 5 with exactly 5 ciphertexts ---------------------------------- #
    e = 5
    m = bytes_to_long(b"CTF{five_recipients}")
    ns, cs = [], []
    for _ in range(e):
        n = getPrime(256) * getPrime(256)
        ns.append(n)
        cs.append(pow(m, e, n))
    assert hastad(cs, ns, e) == m
    print("[+] e = 5 broadcast ok")

    # --- CRT sanity + non-coprime detection -------------------------------- #
    x, M = crt([2, 3, 2], [3, 5, 7])
    assert x % 3 == 2 and x % 5 == 3 and x % 7 == 2 and M == 105
    try:
        crt([1, 1], [6, 15])
        raise AssertionError("should have refused non-coprime moduli")
    except ValueError as exc:
        assert "not coprime" in str(exc)
    print("[+] crt helper ok")

    # --- linear padding: the polynomial really vanishes at m --------------- #
    e = 3
    m = bytes_to_long(b"CTF{linear_padding}")
    pairs = []
    for i in range(e + 1):                       # e+1 pairs for margin
        n = getPrime(512) * getPrime(512)
        a, b = random.randrange(2, 1 << 64), random.randrange(2, 1 << 64)
        pairs.append((n, pow((a * m + b) % n, e, n), a, b))
    coeffs, N = hastad_linear_padding_poly(pairs, e)
    val = 0
    for k in reversed(range(len(coeffs))):
        val = (val * m + coeffs[k]) % N
    assert val == 0, "CRT'd padded polynomial does not vanish at m"
    print("[+] linear-padding polynomial built (feed to Coppersmith small_roots)")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        E = int(sys.argv[2]) if len(sys.argv) > 2 else 3
        ns, cs = [], []
        for line in open(sys.argv[1]):
            line = line.split("#")[0].strip()
            if not line:
                continue
            a, b = line.split()
            ns.append(int(a, 0))
            cs.append(int(b, 0))
        res = hastad(cs, ns, E)
        print("m =", res)
        if res:
            print("bytes =", long_to_bytes(res))
    else:
        _selftest()
```

## Variants & pitfalls

- **Fewer than e ciphertexts**: the CRT modulus is smaller than `m^e`, so the root is not
  exact. Either find more ciphertexts or exploit known padding with Coppersmith.
- **More than e ciphertexts**: use them all, it only helps (and gives margin for padding).
- **Random padding per recipient** kills plain Hastad. If the padding is *linear and known*
  (`m_i = a_i*m + b_i`, e.g. `m_i = i * 2^k + m`), use the polynomial variant above plus
  Coppersmith. If it is random and unknown, you need Franklin-Reiter style relations.
- **Moduli not coprime** -> `gcd` factors two of them instantly; do that instead.
- **`e` not given**: try 3, 5, 7, 11, 17, 65537 - the root either comes out exact or not.
- **Beware of `m` bigger than some `n_i`**: if the flag is longer than the smallest modulus,
  the CRT bound argument breaks.
- Same message but same modulus with different `e` -> `rsa-common-modulus`, not this.

## Tools

```bash
# RsaCtfTool broadcast mode (pass several public keys and ciphertexts)
python3 RsaCtfTool.py --publickey "keys/*.pub" --uncipherfile ciphertexts.txt \
    --attack hastads

# sympy CRT in one line
python3 -c 'from sympy.ntheory.modular import crt;print(crt([<N1>,<N2>,<N3>],[<C1>,<C2>,<C3>]))'

# integer cube root check
python3 -c 'import gmpy2;print(gmpy2.iroot(<M>,3))'
```

## References

- J. Hastad, "Solving Simultaneous Modular Equations of Low Degree" (SIAM J. Comput. 1988)
- CTF Wiki: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
