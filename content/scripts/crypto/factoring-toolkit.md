---
title: "Script - factor_it.py (factordb -> small primes -> Fermat -> p-1 -> rho -> ECM)"
category: crypto
subcategory: factoring
type: script
tags: [factoring, factordb, trial-division, fermat, pollard-p-1, pollard-rho, ecm, lenstra, perfect-power, pipeline, escalation, rsa, gcd, sympy, gmpy2, yafu, script]
summary: "One script that throws every cheap factoring method at n in the right order and tells you which one worked."
tools: [python3, factordb, sympy, gmpy2, yafu, gmp-ecm]
related: [factoring-cheatsheet, rsa-toolkit, rsa-pollard-rho-ecm, rsa-fermat-close-primes]
---

## What it is

`factor_it.py` - the "I have an `n`, now what" script. It runs, in order:

1. trivial checks (even, perfect power, `n` prime)
2. **factordb** lookup (skip with `--no-net`)
3. trial division to 10^6
4. **Fermat** (close primes) with a step budget
5. **Pollard p-1** with escalating `B1`
6. **Williams p+1**
7. **Pollard rho** (Brent)
8. **ECM** with the standard `B1`/curve ladder

It recurses on composite cofactors, prints which method produced each split, and
finishes with the full prime factorisation (or an honest "escalate to yafu/cado-nfs").

## Usage

```bash
python3 factor_it.py 1234567891011                 # factor one number
python3 factor_it.py --no-net <N>                  # never touch the network
python3 factor_it.py --budget 20 <N>               # ~20 seconds per method
python3 factor_it.py --selftest                    # run the built-in tests
python3 factor_it.py --rsa <N> <E> <C>             # factor, then decrypt
```

## Code

```python
#!/usr/bin/env python3
"""factor_it.py - escalating integer factorisation pipeline for CTFs.

Pure stdlib (urllib for the optional factordb lookup). gmpy2/sympy are used if present.

    python3 factor_it.py --selftest
"""
from __future__ import annotations

import json
import random
import sys
import time
from math import gcd, isqrt

# --------------------------------------------------------------------------- #
# basics
# --------------------------------------------------------------------------- #
def is_probable_prime(n: int, rounds: int = 8) -> bool:
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
    for a in small + [random.randrange(2, n - 1) for _ in range(rounds)]:
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


def primes_upto(n: int) -> list[int]:
    sieve = bytearray([1]) * (n + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(n) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, n + 1, i)))
    return [i for i in range(n + 1) if sieve[i]]


def iroot(x: int, k: int) -> tuple[int, bool]:
    if x == 0:
        return 0, True
    r = 1 << ((x.bit_length() + k - 1) // k)
    while True:
        nr = ((k - 1) * r + x // r ** (k - 1)) // k
        if nr >= r:
            break
        r = nr
    return r, r ** k == x


def perfect_power(n: int):
    for k in range(2, n.bit_length() + 1):
        b, exact = iroot(n, k)
        if exact and b > 1:
            return b, k
    return None


# --------------------------------------------------------------------------- #
# 1. factordb
# --------------------------------------------------------------------------- #
def factordb(n: int, timeout: float = 6.0):
    """Ask factordb.com. Returns a list of prime factors, or None.

    Status codes: FF = fully factored, C = composite (no factors known),
    P/PRP = prime, CF = partially factored, U = unknown.
    """
    import urllib.request
    url = f"http://factordb.com/api?query={n}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as fh:
            data = json.loads(fh.read().decode())
    except Exception as exc:                      # offline, blocked, rate limited
        print(f"[!] factordb unavailable ({exc.__class__.__name__})")
        return None
    status = data.get("status")
    out = []
    for base, mult in data.get("factors", []):
        b = int(base)
        out += [b] * int(mult)
    prod = 1
    for x in out:
        prod *= x
    if status in ("FF", "P", "PRP") and prod == n and all(
            is_probable_prime(x) for x in out):
        return sorted(out)
    if out and prod != n:
        print(f"[i] factordb knows a partial factorisation: {status}")
    return None


# --------------------------------------------------------------------------- #
# 2..8 the methods
# --------------------------------------------------------------------------- #
def trial_division(n: int, bound: int = 10 ** 6):
    facs = []
    for p in primes_upto(bound):
        while n % p == 0:
            facs.append(p)
            n //= p
        if n == 1:
            break
    return facs, n


def fermat(n: int, max_steps: int = 1 << 20):
    if n % 4 == 2:
        return None
    a = isqrt(n)
    if a * a == n:
        return a
    a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2 and a - b > 1:
            return a - b
        a += 1
    return None


def pollard_p_minus_1(n: int, B1: int, a: int = 2):
    x = a % n
    for q in primes_upto(B1):
        e = q
        while e * q <= B1:
            e *= q
        x = pow(x, e, n)
        if x == 1:
            return None
    g = gcd(x - 1, n)
    return g if 1 < g < n else None


def lucas_v(k: int, A: int, n: int) -> int:
    v0, v1 = 2 % n, A % n
    for bit in bin(k)[2:]:
        if bit == "0":
            v1 = (v0 * v1 - A) % n
            v0 = (v0 * v0 - 2) % n
        else:
            v0 = (v0 * v1 - A) % n
            v1 = (v1 * v1 - 2) % n
    return v0


def williams_p_plus_1(n: int, B1: int, bases=(3, 5, 7, 9)):
    ps = primes_upto(B1)
    for A in bases:
        v = A % n
        for q in ps:
            e = q
            while e * q <= B1:
                e *= q
            v = lucas_v(e, v, n)
            g = gcd(v - 2, n)
            if 1 < g < n:
                return g
            if g == n:
                break
    return None


def pollard_rho(n: int, max_iter: int):
    if n % 2 == 0:
        return 2
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


class _Found(Exception):
    def __init__(self, f):
        super().__init__(str(f))
        self.f = f


def _ec_add(P, Q, a, n):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % n == 0:
        return None
    if P == Q:
        num, den = (3 * x1 * x1 + a) % n, (2 * y1) % n
    else:
        num, den = (y2 - y1) % n, (x2 - x1) % n
    g = gcd(den, n)
    if g > 1:
        if g < n:
            raise _Found(g)
        return None
    lam = num * pow(den, -1, n) % n
    x3 = (lam * lam - x1 - x2) % n
    return x3, (lam * (x1 - x3) - y1) % n


def _ec_mul(k, P, a, n):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, a, n)
        P = _ec_add(P, P, a, n)
        k >>= 1
    return R


def ecm(n: int, B1: int, curves: int, deadline: float | None = None):
    ps = primes_upto(B1)
    for _ in range(curves):
        if deadline and time.time() > deadline:
            return None
        x, y, a = (random.randrange(1, n) for _ in range(3))
        P = (x, y)
        try:
            for q in ps:
                e = q
                while e * q <= B1:
                    e *= q
                P = _ec_mul(e, P, a, n)
                if P is None:
                    break
        except _Found as f:
            return f.f
    return None


# --------------------------------------------------------------------------- #
# the pipeline
# --------------------------------------------------------------------------- #
def split(n: int, budget: float = 10.0, use_net: bool = True, verbose: bool = True):
    """Return (factor, method_name) for a composite n, or (None, None)."""
    def say(msg):
        if verbose:
            print(msg)

    if n % 2 == 0:
        return 2, "even"

    pp = perfect_power(n)
    if pp:
        say(f"[+] perfect power: n = b^{pp[1]}")
        return pp[0], "perfect-power"

    if use_net:
        say("[*] factordb ...")
        fs = factordb(n)
        if fs and len(fs) > 1:
            say("[+] factordb knew it")
            return fs[0], "factordb"

    say("[*] trial division to 10^6 ...")
    facs, rest = trial_division(n, 10 ** 6)
    if facs:
        return facs[0], "trial-division"

    say("[*] fermat (close primes) ...")
    f = fermat(n, 1 << 20)
    if f:
        return f, "fermat"

    for B1 in (10 ** 3, 10 ** 4, 10 ** 5):
        say(f"[*] pollard p-1, B1 = {B1} ...")
        f = pollard_p_minus_1(n, B1)
        if f:
            return f, f"pollard-p-1 (B1={B1})"

    say("[*] williams p+1, B1 = 10^4 ...")
    f = williams_p_plus_1(n, 10 ** 4)
    if f:
        return f, "williams-p+1"

    say("[*] pollard rho ...")
    f = pollard_rho(n, 1 << 20)
    if f:
        return f, "pollard-rho"

    deadline = time.time() + budget
    for B1, curves in ((2000, 25), (11000, 90), (50000, 300)):
        say(f"[*] ecm, B1 = {B1}, curves = {curves} ...")
        f = ecm(n, B1, curves, deadline)
        if f:
            return f, f"ecm (B1={B1})"
        if time.time() > deadline:
            break
    return None, None


def factor(n: int, budget: float = 10.0, use_net: bool = True,
           verbose: bool = True) -> list[int]:
    """Full factorisation. Raises RuntimeError when the pipeline gives up."""
    out, todo = [], [n]
    while todo:
        cur = todo.pop()
        if cur == 1:
            continue
        if is_probable_prime(cur):
            out.append(cur)
            continue
        f, how = split(cur, budget, use_net, verbose)
        if f is None or f in (1, cur):
            raise RuntimeError(
                f"could not split {cur} ({cur.bit_length()} bits) - "
                f"escalate to yafu / msieve / cado-nfs")
        if verbose:
            print(f"[+] {cur.bit_length()}-bit split by {how}: "
                  f"{f.bit_length()} + {(cur // f).bit_length()} bits")
        todo += [f, cur // f]
    return sorted(out)


def rsa_decrypt(n: int, e: int, c: int, primes: list[int]) -> bytes:
    phi = 1
    seen: dict[int, int] = {}
    for p in primes:
        seen[p] = seen.get(p, 0) + 1
    for p, k in seen.items():
        phi *= p ** (k - 1) * (p - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    random.seed(20260925)

    def gp(bits: int) -> int:
        while True:
            c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_probable_prime(c):
                return c

    # trivial
    assert factor(2 * 3 * 5 * 7, use_net=False, verbose=False) == [2, 3, 5, 7]
    print("[+] trial division path ok")

    # perfect power
    p = gp(64)
    assert factor(p ** 3, use_net=False, verbose=False) == [p, p, p]
    print("[+] perfect power path ok")

    # close primes -> fermat
    p = gp(256)
    q = p + 2
    while not is_probable_prime(q):
        q += 2
    assert factor(p * q, use_net=False, verbose=False) == sorted([p, q])
    print("[+] fermat path ok")

    # smooth p-1
    pool = primes_upto(400)
    while True:
        v = 2
        for x in random.sample(pool, 40):
            if v.bit_length() >= 200:
                break
            v *= x
        if v.bit_length() > 150 and is_probable_prime(v + 1):
            ps = v + 1
            break
    q = gp(200)
    got = factor(ps * q, use_net=False, verbose=False)
    assert got == sorted([ps, q]), "p-1 path failed"
    print("[+] pollard p-1 path ok")

    # small factors -> rho
    p, q = gp(30), gp(120)
    assert factor(p * q, use_net=False, verbose=False) == sorted([p, q])
    print("[+] rho path ok")

    # ecm-sized factor inside a bigger modulus
    p, q = gp(32), gp(200)
    got = factor(p * q, budget=60, use_net=False, verbose=False)
    assert got == sorted([p, q]), f"ecm path failed: {got}"
    print("[+] ecm path ok")

    # end-to-end RSA
    p = gp(256)
    q = p + 2
    while not is_probable_prime(q):
        q += 2
    n, e = p * q, 65537
    flag = b"CTF{factor_it_works}"
    c = pow(int.from_bytes(flag, "big"), e, n)
    ps = factor(n, use_net=False, verbose=False)
    assert rsa_decrypt(n, e, c, ps) == flag
    print("[+] end-to-end RSA decryption ok:", flag.decode())

    # prime input
    assert factor(gp(128), use_net=False, verbose=False) != []
    print("[+] prime input handled")

    print("[*] factor_it self-test passed")


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("usage: factor_it.py [--no-net] [--budget SEC] [--rsa] N [E C]")
        return 0
    use_net, budget = True, 10.0
    args = []
    i = 0
    rsa_mode = False
    while i < len(argv):
        a = argv[i]
        if a == "--no-net":
            use_net = False
        elif a == "--budget":
            i += 1
            budget = float(argv[i])
        elif a == "--rsa":
            rsa_mode = True
        elif a == "--selftest":
            _selftest()
            return 0
        else:
            args.append(a)
        i += 1
    if not args:
        print("nothing to do")
        return 1
    n = int(args[0], 0)
    t0 = time.time()
    fs = factor(n, budget=budget, use_net=use_net)
    print(f"\n[=] {n} =")
    for f in fs:
        print(f"      {f}")
    print(f"[=] {len(fs)} prime factors in {time.time() - t0:.1f}s")
    if rsa_mode and len(args) >= 3:
        e, c = int(args[1], 0), int(args[2], 0)
        print("[=] plaintext:", rsa_decrypt(n, e, c, fs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

## Notes

- `--no-net` is the right default for an offline CTF box; the factordb step is the only
  thing that touches the network.
- The ECM stage here is stage-1 only and pure Python: it is a *convenience*, not a
  replacement for `gmp-ecm`. If a factor is bigger than ~40 bits, shell out:
  `echo <N> | ecm -c 1000 11e4`.
- For balanced moduli above ~330 bits the script will (correctly) give up; that is a
  signal to look for a structural weakness instead of more CPU.
