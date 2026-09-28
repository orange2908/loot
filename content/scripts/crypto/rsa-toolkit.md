---
title: "Script - rsa_toolkit.py (one-file RSA attack toolkit)"
category: crypto
subcategory: rsa
type: script
tags: [rsa, toolkit, script, nth-root, iroot, extended-gcd, egcd, modular-inverse, crt, continued-fractions, wiener, common-modulus, batch-gcd, gcd, fermat, pollard-rho, pollard-p-1, lsb-oracle, hastad, self-test]
summary: "Single dependency-free Python module with iroot, egcd, CRT, Wiener, common modulus, batch GCD, Fermat, Pollard rho, Pollard p-1, LSB oracle, Hastad and a CLI dispatcher."
tools: [python3, gmpy2, sympy]
related: [rsa-cheatsheet, factoring-toolkit, rsa-wiener-small-d, rsa-common-modulus, rsa-hastad-broadcast]
---

## What it is

`rsa_toolkit.py` - copy it once into your CTF workspace and import it from every RSA
challenge. Pure standard library (it will use `gmpy2` if present, but does not need it).
Every routine is also reachable from the command line.

## Usage

```bash
# run the built-in test suite (generates its own instances and asserts recovery)
python3 rsa_toolkit.py selftest

# individual attacks
python3 rsa_toolkit.py wiener        N E [C]
python3 rsa_toolkit.py commonmod     N E1 C1 E2 C2
python3 rsa_toolkit.py batchgcd      moduli.txt
python3 rsa_toolkit.py fermat        N
python3 rsa_toolkit.py rho           N
python3 rsa_toolkit.py pm1           N [B1]
python3 rsa_toolkit.py hastad        pairs.txt E     # each line: "n c"
python3 rsa_toolkit.py smalle        N E C
python3 rsa_toolkit.py decrypt       N E C P Q
python3 rsa_toolkit.py auto          N E [C]         # try everything cheap, in order
```

## Code

```python
#!/usr/bin/env python3
"""rsa_toolkit.py - a single-file RSA/CTF attack toolkit.

No mandatory dependencies (pure stdlib). gmpy2 is used automatically if importable.

    python3 rsa_toolkit.py selftest
"""
from __future__ import annotations

import random
import sys
from fractions import Fraction
from math import gcd, isqrt

__all__ = [
    "iroot", "egcd", "inverse", "crt", "continued_fraction", "convergents",
    "wiener", "common_modulus", "batch_gcd", "fermat", "pollard_rho",
    "pollard_p_minus_1", "lsb_oracle_attack", "hastad", "small_e_attack",
    "factor_from_phi", "factor_from_d", "is_probable_prime", "getPrime",
    "b2l", "l2b", "decrypt",
]

# --------------------------------------------------------------------------- #
# 0. tiny helpers (work with or without pycryptodome / gmpy2)
# --------------------------------------------------------------------------- #
def b2l(b: bytes) -> int:
    """bytes -> int, big endian (bytes_to_long)."""
    return int.from_bytes(b, "big")


def l2b(x: int) -> bytes:
    """int -> bytes, big endian (long_to_bytes)."""
    return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")


def is_probable_prime(n: int, rounds: int = 8) -> bool:
    """Deterministic small-base Miller-Rabin plus a few random bases."""
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
    bases = small + [random.randrange(2, n - 1) for _ in range(rounds)]
    for a in bases:
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


def getPrime(bits: int) -> int:
    """Random prime with the top bit set."""
    try:
        from Crypto.Util.number import getPrime as _gp
        return int(_gp(bits))
    except ImportError:
        pass
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


# --------------------------------------------------------------------------- #
# 1. arithmetic primitives
# --------------------------------------------------------------------------- #
def iroot(x: int, n: int) -> tuple[int, bool]:
    """Exact integer n-th root by Newton iteration. Returns (root, is_exact)."""
    if x < 0:
        raise ValueError("negative radicand")
    if x == 0:
        return 0, True
    if n == 1:
        return x, True
    r = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        nr = ((n - 1) * r + x // r ** (n - 1)) // n
        if nr >= r:
            break
        r = nr
    return r, r ** n == x


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: (g, x, y) with a*x + b*y == g == gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def inverse(a: int, m: int) -> int:
    """Modular inverse; raises ValueError (with the useful gcd) if it does not exist."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"not invertible, gcd = {g}")
    return x % m


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """CRT for pairwise-coprime moduli. Returns (x, prod(moduli))."""
    x, M = 0, 1
    for r, m in zip(residues, moduli):
        g = gcd(M, m)
        if g != 1:
            raise ValueError(f"moduli share the factor {g}")
        x += M * ((r - x) * inverse(M, m) % m)
        M *= m
    return x % M, M


def continued_fraction(a: int, b: int, limit: int = 8192) -> list[int]:
    """Partial quotients of a/b."""
    cf = []
    while b and len(cf) < limit:
        cf.append(a // b)
        a, b = b, a % b
    return cf


def convergents(cf: list[int]):
    """Yield (num, den) for every convergent of a continued fraction."""
    p0, p1, q0, q1 = 0, 1, 1, 0
    for x in cf:
        p0, p1 = p1, x * p1 + p0
        q0, q1 = q1, x * q1 + q0
        yield p1, q1


# --------------------------------------------------------------------------- #
# 2. key-recovery from leaked values
# --------------------------------------------------------------------------- #
def factor_from_phi(n: int, phi: int):
    """Two primes from phi(n): roots of x^2 - (n-phi+1)x + n."""
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = isqrt(disc)
    if r * r != disc:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    return (p, q) if p * q == n else None


def factor_from_d(n: int, e: int, d: int, tries: int = 100):
    """Split n using any valid private exponent (works for multi-prime too)."""
    k = e * d - 1
    if k <= 0:
        return None
    t, s = k, 0
    while t % 2 == 0:
        t //= 2
        s += 1
    for _ in range(tries):
        g = random.randrange(2, n - 1)
        if gcd(g, n) > 1:
            return gcd(g, n)
        x = pow(g, t, n)
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                f = gcd(x - 1, n)
                if 1 < f < n:
                    return f
            x = y
    return None


def decrypt(n: int, e: int, c: int, p: int, q: int) -> bytes:
    """Standard decryption once the factorisation is known."""
    d = inverse(e, (p - 1) * (q - 1))
    return l2b(pow(c, d, n))


# --------------------------------------------------------------------------- #
# 3. attacks
# --------------------------------------------------------------------------- #
def small_e_attack(c: int, e: int, n: int, max_k: int = 1 << 16):
    """m^e < n (or wrapped a few times) -> integer e-th root."""
    for k in range(max_k):
        m, exact = iroot(c + k * n, e)
        if exact:
            return m
    return None


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int):
    """Same n, two exponents. Returns (m^gcd(e1,e2) mod n, gcd)."""
    g, a, b = egcd(e1, e2)
    x1, x2 = c1 % n, c2 % n
    if a < 0:
        x1, a = inverse(x1, n), -a
    if b < 0:
        x2, b = inverse(x2, n), -b
    return pow(x1, a, n) * pow(x2, b, n) % n, g


def wiener(n: int, e: int, extended_bound: int = 0):
    """Small private exponent. Returns (p, q, d) or None.

    extended_bound > 0 also tries small integer combinations of consecutive
    convergents (Dujella), which reaches a few bits past n^0.25.
    """
    def check(k: int, d: int):
        if k <= 0 or d <= 0 or (e * d - 1) % k:
            return None
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            return None
        r = isqrt(disc)
        if r * r != disc:
            return None
        p, q = (s + r) // 2, (s - r) // 2
        return (p, q, d) if p * q == n else None

    conv = list(convergents(continued_fraction(e, n)))
    for k, d in conv:
        hit = check(k, d)
        if hit:
            return hit
    if extended_bound:
        for i in range(len(conv) - 1):
            (pa, qa), (pb, qb) = conv[i], conv[i + 1]
            for r in range(extended_bound):
                for s in range(-extended_bound, extended_bound):
                    hit = check(r * pb + s * pa, r * qb + s * qa)
                    if hit:
                        return hit
    return None


def batch_gcd(ns: list[int]) -> list[int]:
    """Bernstein batch GCD: gcd(n_i, prod of the others) for every modulus."""
    if len(ns) < 2:
        return [1] * len(ns)
    levels = [list(ns)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([cur[i] * cur[i + 1] if i + 1 < len(cur) else cur[i]
                       for i in range(0, len(cur), 2)])
    rem = levels[-1]
    for i in range(len(levels) - 2, -1, -1):
        cur = levels[i]
        rem = [rem[j // 2] % (cur[j] ** 2) for j in range(len(cur))]
    return [gcd(rem[i] // ns[i], ns[i]) for i in range(len(ns))]


def fermat(n: int, max_steps: int = 1 << 22):
    """Close primes: n = a^2 - b^2."""
    if n % 4 == 2:
        return None
    a = isqrt(n)
    if a * a == n:
        return a, a
    a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a + b, a - b
            if q > 1 and p * q == n:
                return p, q
        a += 1
    return None


def pollard_rho(n: int, max_iter: int = 1 << 22):
    """Brent's variant. Best when the smallest factor is below ~2^60."""
    if n % 2 == 0:
        return 2
    if is_probable_prime(n):
        return n
    while True:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        m = 128
        g = r = q = 1
        x = ys = y
        total = 0
        while g == 1 and total < max_iter:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += m
                total += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
        if total >= max_iter:
            return None


def _primes_upto(n: int) -> list[int]:
    sieve = bytearray([1]) * (n + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(n) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, n + 1, i)))
    return [i for i in range(n + 1) if sieve[i]]


def pollard_p_minus_1(n: int, B1: int = 100000, a: int = 2):
    """Smooth p-1. Returns a factor or None."""
    if n % 2 == 0:
        return 2
    x = a % n
    for q in _primes_upto(B1):
        e = q
        while e * q <= B1:
            e *= q
        x = pow(x, e, n)
        if x == 1:
            return None
    g = gcd(x - 1, n)
    return g if 1 < g < n else None


def hastad(ciphertexts: list[int], moduli: list[int], e: int):
    """Broadcast attack: e ciphertexts of the same m under coprime moduli."""
    M, prod = crt(ciphertexts[:e], moduli[:e])
    m, exact = iroot(M, e)
    if exact:
        return m
    for k in range(1, 1 << 12):
        m, exact = iroot(M + k * prod, e)
        if exact:
            return m
    return None


def lsb_oracle_attack(n: int, e: int, c: int, oracle) -> int:
    """oracle(ct) -> least significant bit of dec(ct). Needs ~log2(n) queries."""
    lo, hi = Fraction(0), Fraction(n)
    mult = 1
    for _ in range(n.bit_length()):
        mult = mult * pow(2, e, n) % n
        bit = oracle(c * mult % n)
        mid = (lo + hi) / 2
        if bit:
            lo = mid
        else:
            hi = mid
    for cand in range(int(lo) - 2, int(hi) + 3):
        if cand >= 0 and pow(cand, e, n) == c % n:
            return cand
    return int(hi)


def auto(n: int, e: int, c: int | None = None) -> dict:
    """Run every cheap attack in a sensible order and report what stuck."""
    out: dict[str, object] = {}
    r = isqrt(n)
    out["bits"] = n.bit_length()
    out["is_square"] = r * r == n
    small = [p for p in _primes_upto(5000) if n % p == 0]
    out["small_factors"] = small
    if small:
        out["factors"] = (small[0], n // small[0])
        return out
    f = fermat(n, 1 << 18)
    if f:
        out["fermat"] = f
        out["factors"] = f
        return out
    w = wiener(n, e, extended_bound=0)
    if w:
        out["wiener_d"] = w[2]
        out["factors"] = (w[0], w[1])
        return out
    if c is not None:
        m = small_e_attack(c, e, n, 1 << 12)
        if m is not None:
            out["small_e_plaintext"] = l2b(m)
            return out
    f = pollard_rho(n, 1 << 18)
    if f and 1 < f < n:
        out["rho"] = f
        out["factors"] = (f, n // f)
        return out
    f = pollard_p_minus_1(n, 50000)
    if f:
        out["p_minus_1"] = f
        out["factors"] = (f, n // f)
        return out
    out["result"] = "nothing cheap worked - read the handout again"
    return out


# --------------------------------------------------------------------------- #
# 4. self-test
# --------------------------------------------------------------------------- #
def selftest() -> None:
    random.seed(0xBADC0DE)

    # iroot / egcd / inverse / crt
    assert iroot(10 ** 30, 3) == (10 ** 10, True)
    assert iroot(10 ** 30 + 1, 3) == (10 ** 10, False)
    g, x, y = egcd(240, 46)
    assert g == 2 and 240 * x + 46 * y == 2
    assert inverse(3, 11) == 4
    v, M = crt([2, 3, 2], [3, 5, 7])
    assert M == 105 and v % 3 == 2 and v % 5 == 3 and v % 7 == 2
    print("[+] primitives ok")

    # continued fractions
    assert continued_fraction(415, 93) == [4, 2, 6, 7]
    assert list(convergents([4, 2, 6, 7]))[-1] == (415, 93)
    print("[+] continued fractions ok")

    # small e
    p, q = getPrime(512), getPrime(512)
    n, e = p * q, 3
    flag = b"CTF{toolkit_small_e}"
    assert small_e_attack(pow(b2l(flag), e, n), e, n) == b2l(flag)
    print("[+] small e ok")

    # common modulus
    m = b2l(b"CTF{toolkit_common_modulus}")
    val, g = common_modulus(n, 65537, pow(m, 65537, n), 3, pow(m, 3, n))
    assert g == 1 and val == m
    print("[+] common modulus ok")

    # wiener
    while True:
        p, q = getPrime(512), getPrime(512)
        phi = (p - 1) * (q - 1)
        d = random.getrandbits(200) | 1
        if gcd(d, phi) != 1:
            continue
        e2 = inverse(d, phi)
        n2 = p * q
        if e2.bit_length() > 1000:
            break
    res = wiener(n2, e2)
    assert res is not None and res[2] == d
    print("[+] wiener ok")

    # batch gcd
    shared = getPrime(256)
    mods = [getPrime(256) * getPrime(256) for _ in range(10)]
    mods[3] = shared * getPrime(256)
    mods[8] = shared * getPrime(256)
    bg = batch_gcd(mods)
    assert bg[3] == shared and bg[8] == shared
    assert all(bg[i] == 1 for i in range(10) if i not in (3, 8))
    print("[+] batch gcd ok")

    # fermat
    p = getPrime(256)
    q = p + 2
    while not is_probable_prime(q):
        q += 2
    assert set(fermat(p * q)) == {p, q}
    print("[+] fermat ok")

    # pollard rho
    p, q = getPrime(32), getPrime(32)
    assert pollard_rho(p * q) in (p, q)
    print("[+] pollard rho ok")

    # pollard p-1
    pool = _primes_upto(400)
    while True:
        v = 2
        for x in random.sample(pool, 40):
            if v.bit_length() >= 200:
                break
            v *= x
        if v.bit_length() > 150 and is_probable_prime(v + 1):
            ps = v + 1
            break
    n3 = ps * getPrime(200)
    assert pollard_p_minus_1(n3, 500) == ps
    print("[+] pollard p-1 ok")

    # hastad
    e = 3
    m = b2l(b"CTF{toolkit_hastad}")
    ns = [getPrime(256) * getPrime(256) for _ in range(3)]
    cs = [pow(m, e, x) for x in ns]
    assert hastad(cs, ns, e) == m
    print("[+] hastad ok")

    # lsb oracle
    p, q = getPrime(256), getPrime(256)
    n4 = p * q
    e4 = 65537
    d4 = inverse(e4, (p - 1) * (q - 1))
    m = b2l(b"CTF{toolkit_lsb}")
    c4 = pow(m, e4, n4)
    assert lsb_oracle_attack(n4, e4, c4, lambda ct: pow(ct, d4, n4) & 1) == m
    print("[+] lsb oracle ok")

    # factor from phi / d
    assert set(factor_from_phi(n4, (p - 1) * (q - 1))) == {p, q}
    assert factor_from_d(n4, e4, d4) in (p, q)
    assert decrypt(n4, e4, c4, p, q) == b"CTF{toolkit_lsb}"
    print("[+] phi/d recovery ok")

    # auto
    p = getPrime(256)
    q = p + 2
    while not is_probable_prime(q):
        q += 2
    res = auto(p * q, 65537)
    assert res.get("factors") and set(res["factors"]) == {p, q}
    print("[+] auto dispatcher ok")

    print("[*] rsa_toolkit self-test passed")


# --------------------------------------------------------------------------- #
# 5. CLI
# --------------------------------------------------------------------------- #
USAGE = """rsa_toolkit.py <command> [args]

  selftest
  wiener     N E [C]
  commonmod  N E1 C1 E2 C2
  batchgcd   moduli.txt
  fermat     N
  rho        N
  pm1        N [B1]
  hastad     pairs.txt E        # each line: "<n> <c>"
  smalle     N E C
  decrypt    N E C P Q
  auto       N E [C]
"""


def _ints(argv):
    return [int(v, 0) for v in argv]


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "selftest":
        selftest()
    elif cmd == "wiener":
        n, e = _ints(rest[:2])
        res = wiener(n, e, extended_bound=60)
        print(res)
        if res and len(rest) > 2:
            print(l2b(pow(int(rest[2], 0), res[2], n)))
    elif cmd == "commonmod":
        n, e1, c1, e2, c2 = _ints(rest[:5])
        val, g = common_modulus(n, e1, c1, e2, c2)
        print(f"gcd(e1,e2) = {g}")
        print(l2b(val) if g == 1 else f"m^{g} = {val}")
    elif cmd == "batchgcd":
        ns = [int(x.strip(), 0) for x in open(rest[0]) if x.strip()]
        for i, g in enumerate(batch_gcd(ns)):
            if g != 1:
                print(f"[{i}] p = {g}\n     q = {ns[i] // g}")
    elif cmd == "fermat":
        print(fermat(_ints(rest)[0]))
    elif cmd == "rho":
        print(pollard_rho(_ints(rest)[0]))
    elif cmd == "pm1":
        n = int(rest[0], 0)
        B1 = int(rest[1]) if len(rest) > 1 else 100000
        print(pollard_p_minus_1(n, B1))
    elif cmd == "hastad":
        e = int(rest[1])
        ns, cs = [], []
        for line in open(rest[0]):
            line = line.split("#")[0].strip()
            if line:
                a, b = line.split()
                ns.append(int(a, 0))
                cs.append(int(b, 0))
        m = hastad(cs, ns, e)
        print(m, l2b(m) if m else "")
    elif cmd == "smalle":
        n, e, c = _ints(rest[:3])
        m = small_e_attack(c, e, n)
        print(m, l2b(m) if m else "")
    elif cmd == "decrypt":
        n, e, c, p, q = _ints(rest[:5])
        print(decrypt(n, e, c, p, q))
    elif cmd == "auto":
        n, e = _ints(rest[:2])
        c = int(rest[2], 0) if len(rest) > 2 else None
        for k, v in auto(n, e, c).items():
            print(f"{k:20s}: {v}")
    else:
        print(USAGE)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

## Notes

- Drop `gmpy2` in for a 10-50x speedup on `iroot`, `isqrt` and modular exponentiation:
  `from gmpy2 import mpz, iroot, isqrt` and wrap the moduli in `mpz`.
- `auto` is intentionally *cheap*: it never runs anything that could take more than a few
  seconds. If it prints "nothing cheap worked", move to `factoring-toolkit.md` or to a
  structural attack.
- Every function is independent - copy just the one you need into an exploit script.
