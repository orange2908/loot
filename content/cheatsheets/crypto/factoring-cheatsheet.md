---
title: "Factoring - Cheatsheet (factordb, yafu, cado-nfs, msieve, ECM, sympy, gmpy2)"
category: crypto
subcategory: factoring
type: cheatsheet
tags: [factoring, factordb, yafu, cado-nfs, msieve, gmp-ecm, ecm, siqs, gnfs, pollard-rho, pollard-p-1, williams-p-plus-1, fermat, trial-division, sympy, gmpy2, alpertron, semiprime, size-table, rsa]
summary: "Which factoring tool for which size, factordb API recipes, yafu/cado-nfs/msieve/gmp-ecm invocations, and python snippets for quick splits."
tools: [factordb, yafu, cado-nfs, msieve, gmp-ecm, sympy, gmpy2, python3, curl]
related: [rsa-cheatsheet, factoring-toolkit, rsa-pollard-rho-ecm, rsa-fermat-close-primes]
---

## Size vs method

| `n` size | digits | Method | Realistic time |
|---|---|---|---|
| < 64 bit | < 20 | `sympy.factorint`, rho | instant |
| 64-128 bit | 20-39 | rho / SQUFOF / yafu | seconds |
| 128-220 bit | 39-66 | SIQS (yafu, msieve) | seconds-minutes |
| 220-330 bit | 66-100 | SIQS | minutes-hours |
| 330-390 bit | 100-118 | SIQS / small GNFS | hours |
| 390-768 bit | 118-232 | GNFS (cado-nfs) | days-months |
| > 768 bit | > 232 | not in a CTF | - |

**Independent of `n`'s size**, ECM finds a *small* factor:

| smallest factor | ECM `B1` | curves | time (gmp-ecm) |
|---|---|---|---|
| 15 digits (~50 bit) | 2e3 | 25 | < 1 s |
| 20 digits (~66 bit) | 11e3 | 90 | seconds |
| 25 digits (~83 bit) | 5e4 | 300 | ~1 min |
| 30 digits (~100 bit) | 25e4 | 700 | ~10 min |
| 35 digits (~116 bit) | 1e6 | 1800 | ~1 h |
| 40 digits (~133 bit) | 3e6 | 5100 | hours |
| 45 digits | 11e6 | 10600 | ~a day |
| 50 digits | 43e6 | 19300 | days |

Rule of thumb: try ECM up to 35 digits before committing to SIQS/GNFS.

## The order to try things

```
1. is it even / a perfect power / prime?
2. factordb
3. trial division to 10^6
4. Fermat (close primes)       - 1 second, huge payoff
5. gcd against every other modulus in the challenge
6. Pollard p-1, Williams p+1   - B1 = 1e4 .. 1e7
7. Pollard rho                 - only if a factor may be < 2^60
8. ECM ladder                  - 2e3, 11e3, 5e4, 25e4, 1e6
9. SIQS (yafu / msieve)        - if n < ~110 digits
10. GNFS (cado-nfs)            - if you really must
```

## factordb

```bash
# JSON API (the only stable interface)
curl -s "http://factordb.com/api?query=1234567891011" | python3 -m json.tool

# status codes:
#   FF  fully factored        C   composite, no factors known
#   CF  partially factored    P   definitely prime
#   PRP probably prime        U   unknown / not yet processed
#   Unit / Zero for 1 and 0

# pull just the factors
curl -s "http://factordb.com/api?query=<N>" | \
  python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["status"],d["factors"])'

# submit a number for factoring (it will queue it)
curl -s "http://factordb.com/index.php?query=<N>" > /dev/null

# expression queries work too
curl -s "http://factordb.com/api?query=2%5E67-1"      # 2^67-1
```

```python
# python helper with a graceful offline fallback
import json
import urllib.request


def factordb(n: int, timeout: float = 6.0):
    """Return a list of prime factors from factordb, or None."""
    try:
        with urllib.request.urlopen(
                f"http://factordb.com/api?query={n}", timeout=timeout) as fh:
            data = json.loads(fh.read().decode())
    except Exception:
        return None
    out = []
    for base, mult in data.get("factors", []):
        out += [int(base)] * int(mult)
    prod = 1
    for x in out:
        prod *= x
    return sorted(out) if out and prod == n else None


if __name__ == "__main__":
    print(factordb(9))
```

Gotchas: rate limited (roughly one request per second); returns `["<id>", 1]` style
placeholders for very large unfactored numbers; always verify `prod(factors) == n`.

## yafu - the default choice

```bash
# one number
echo 'factor(123456789012345678901234567890)' | yafu

# from the command line, 8 threads
yafu "factor(<N>)" -threads 8

# force a specific algorithm
yafu "siqs(<N>)" -threads 8
yafu "nfs(<N>)" -threads 8
yafu "ecm(<N>,1000)"          # 1000 curves
yafu "rho(<N>)"
yafu "pm1(<N>)"
yafu "pp1(<N>)"
yafu "fermat(<N>,1000000)"    # 10^6 iterations
yafu "trial(<N>,100000)"
yafu "squfof(<N>)"

# batch: one number per line
yafu "factor(@)" -batchfile numbers.txt

# useful flags
#   -v            more verbose (repeat for more)
#   -threads N    parallelism
#   -plan none    do not run the default pretesting plan
#   -one          stop after the first factor
#   -pfile        write factors to factor.log
```

## GMP-ECM

```bash
# the standard escalating ladder (stop as soon as one hits)
echo <N> | ecm -c 25   2e3
echo <N> | ecm -c 90   11e3
echo <N> | ecm -c 300  5e4
echo <N> | ecm -c 700  25e4
echo <N> | ecm -c 1800 1e6
echo <N> | ecm -c 5100 3e6

# p-1 and p+1 (each is one "curve")
echo <N> | ecm -pm1 1e7
echo <N> | ecm -pp1 1e7

# useful flags
#   -q           quiet, print only factors
#   -one         stop at the first factor
#   -save f.txt  checkpoint residues so you can resume with -resume
#   -maxmem 4096 cap memory for stage 2
#   -k 4         more stage-2 blocks (less memory)
echo <N> | ecm -q -one -c 500 11e4
```

## msieve (SIQS, and NFS post-processing)

```bash
# quadratic sieve, verbose, multi-thread
msieve -v -t 8 <N>

# use a work file so you can stop and resume
msieve -v -t 8 -s work.dat <N>

# NFS via msieve (needs a poly + relations from ggnfs/cado)
msieve -v -nc -s work.dat <N>
```

## cado-nfs (GNFS)

```bash
git clone https://gitlab.inria.fr/cado-nfs/cado-nfs && cd cado-nfs && make -j8

# fully automatic, single machine
./cado-nfs.py <N>

# with an explicit work directory (resumable)
./cado-nfs.py <N> --workdir /tmp/cado-work

# distribute over several machines
./cado-nfs.py <N> server.threads=8 slaves.hostnames=host1,host2 slaves.nrclients=4
```

Expect: 100 digits in ~an hour on a laptop, 130 digits in a day, 155+ digits needs a cluster.

## sympy / gmpy2 quick shots

```python
# sympy: complete factorisation (rho + p-1 + ECM + SIQS internally)
from sympy import factorint, isprime, primefactors, divisors
print(factorint(2 ** 67 - 1))
print(factorint(N, limit=10 ** 6))          # give up past small primes
print(primefactors(N))
print(isprime(N))

# sympy: individual algorithms
from sympy.ntheory import pollard_rho, pollard_pm1
print(pollard_rho(N))
print(pollard_pm1(N, B=10 ** 5))

# gmpy2: fast primitives
import gmpy2
print(gmpy2.is_prime(N))
print(gmpy2.next_prime(N))
print(gmpy2.isqrt(N))
print(gmpy2.iroot(N, 3))                    # (root, is_exact)
print(gmpy2.gcd(N1, N2))
print(gmpy2.invert(e, phi))
```

```bash
# one-liners
python3 -c 'from sympy import factorint;print(factorint(<N>))'
python3 -c 'from sympy import factorint;print(factorint(<N>, limit=10**6))'
python3 -c 'import gmpy2;print(gmpy2.iroot(<N>,2))'
python3 -c 'from math import isqrt;n=<N>;r=isqrt(n);print("square" if r*r==n else (n-r*r).bit_length())'
python3 -c 'from math import gcd;print(gcd(<N1>,<N2>))'
```

## Pure-python splits worth pasting

```python
"""Small self-contained splitters: Fermat, rho (Brent), p-1. All runnable."""
import random
from math import gcd, isqrt


def fermat(n: int, steps: int = 1 << 20):
    """Close primes: n = a^2 - b^2."""
    if n % 4 == 2:
        return None
    a = isqrt(n)
    if a * a == n:
        return a
    a += 1
    for _ in range(steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2 and a - b > 1:
            return a - b
        a += 1
    return None


def rho(n: int, iters: int = 1 << 20):
    """Brent's rho; returns a factor or None."""
    if n % 2 == 0:
        return 2
    y, c, m = random.randrange(1, n), random.randrange(1, n), 128
    g = r = q = 1
    x = ys = y
    total = 0
    while g == 1 and total < iters:
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
    return g if 1 < g < n else None


def pm1(n: int, B1: int = 100000):
    """Pollard p-1 stage 1."""
    sieve = bytearray([1]) * (B1 + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(B1) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, B1 + 1, i)))
    x = 2
    for q in (i for i in range(B1 + 1) if sieve[i]):
        e = q
        while e * q <= B1:
            e *= q
        x = pow(x, e, n)
    g = gcd(x - 1, n)
    return g if 1 < g < n else None


if __name__ == "__main__":
    random.seed(0)
    # two primes 6 apart -> Fermat hits immediately
    p, q = 1000000000000000003, 1000000000000000009
    assert fermat(p * q) in (p, q)
    # two 30-bit primes -> rho
    assert rho(982451653 * 961748941) in (982451653, 961748941)
    # p - 1 is 113-smooth -> Pollard p-1 with B1 = 200
    smooth_p = 274657193071          # 274657193070 = 2*3*5*7*11*23*29*31*37*113
    assert pm1(smooth_p * 982451653, 200) == smooth_p
    print("[*] all three splitters work")
```

## Reading the output

```
- "n is prime" from any tool: stop, the challenge lies elsewhere.
- yafu printing "PRP47 = ..." means a 47-digit probable prime factor.
- ECM finding a factor on curve 3 of 500: you were lucky, note the B1 for next time.
- A factor equal to n: the algorithm collapsed (bad base / both factors smooth). Retry.
- Partial factorisation (CF on factordb): use the cofactor as the new target.
```

## Online helpers (when you are allowed network)

```
factordb          http://factordb.com/           lookup + submit
alpertron ECM     https://www.alpertron.com.ar/ECM.HTM   in-browser ECM/SIQS
```

## References

- factordb: http://factordb.com/
- yafu: https://github.com/bbuhrow/yafu
- GMP-ECM: https://gitlab.inria.fr/zimmerma/ecm
- cado-nfs: https://gitlab.inria.fr/cado-nfs/cado-nfs
- msieve: https://sourceforge.net/projects/msieve/
- Alpertron ECM applet: https://www.alpertron.com.ar/ECM.HTM
