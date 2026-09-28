---
title: "DLP - Index Calculus and When a Discrete Log Is Actually Easy"
category: crypto
subcategory: dlp
type: technique
tags: [dlp, discrete-log, discrete-logarithm, index-calculus, factor-base, smooth, linear-algebra, gaussian-elimination, number-field-sieve, nfs, function-field-sieve, gf2n, coppersmith, logjam, sage, pari, python]
difficulty: hard
summary: "Index calculus turns a DLP into linear algebra over smooth relations. Plus the triage list: the ten reasons a CTF discrete log is not actually hard."
when_to_use:
  - "You have a DLP in GF(p)^* or GF(2^n)^* and generic square-root methods are too slow"
  - "You need to decide quickly whether a discrete log is worth attacking at all"
  - "The modulus is small enough (< 2^60) that a hand-rolled index calculus finishes"
  - "The challenge is in GF(2^n) -- that field is far weaker than its size suggests"
tools: [sage, pari, cado-nfs, python]
related: [dlp-pohlig-hellman, dlp-bsgs-pollard-rho, dlp-diffie-hellman-attacks, ecc-mov-pairing, ecc-smart-anomalous]
---

## TL;DR

Index calculus exploits structure that elliptic curves do not have: integers factor. Build a
factor base of small primes, collect relations `g^k = prod q_i^{e_i}`, solve the resulting
linear system for `log_g q_i`, then express the target as a smooth product. Subexponential
`L_p[1/2]` by hand, `L_p[1/3]` with the number field sieve. In `GF(2^n)` it is
quasi-polynomial, which is why binary fields are dead.

## Recognise it

- A DLP in `Z_p^*` with `p` of 60-512 bits and `p - 1` *not* smooth.
- `GF(2^n)` arithmetic anywhere in the source -- polynomials mod an irreducible.
- A 512-bit or 768-bit DH prime (Logjam territory).
- The challenge insists the group order is a big prime, so Pohlig-Hellman is out.

## The triage list: when a DLP is easy

Run through this before writing any code.

| condition | attack | cost |
| --- | --- | --- |
| `p` small (`< 2^50`) | BSGS / rho | `sqrt(p)` |
| `ord(g)` smooth | Pohlig-Hellman | `sum e_i sqrt(q_i)` |
| `p - 1` smooth | Pohlig-Hellman | same |
| `x` known to be small or in an interval | kangaroo / brute force | `sqrt(w)` |
| `g` not a generator | you only need `x mod ord(g)` | often tiny |
| the group is `(Z_n, +)` in disguise | one modular inverse | `O(1)` |
| elliptic curve with `#E == p` | Smart's attack | `O(log p)` |
| elliptic curve with small embedding degree | MOV / Frey-Ruck, then field DLP | `L[1/3]` |
| singular curve | map to `(GF(p),+)` or `GF(p)^*` | trivial / Pohlig-Hellman |
| `GF(2^n)` or `GF(p^k)` with small `p` | function field sieve / quasi-polynomial | very fast |
| `p` up to ~600 bits, generic | CADO-NFS | hours on a workstation |
| repeated structure (same `g^x` reused) | look for a protocol bug, not a DLP | free |

If none of these apply and the prime is 1024 bits or more with a large prime-order subgroup,
the DLP is not the intended solution. Re-read the challenge.

## Theory

**Factor base.** Fix `B` and let `FB = {q : q prime, q <= B}`, `m = |FB|`.

**Relation collection.** For random (or sequential) `k`, test whether `g^k mod p` is
`B`-smooth. If it factors as `prod q_i^{e_i}` then taking logs base `g`:

$$k \equiv \sum_i e_i \, \log_g q_i \pmod{p-1}$$

Collect slightly more than `m` such relations.

**Linear algebra.** Solve the system for the `m` unknowns `log_g q_i`. Modulo a composite
`p - 1` this is awkward, so solve modulo each prime power dividing `p - 1` and CRT. For a
safe prime `p = 2q + 1` you solve modulo `q` by ordinary Gaussian elimination over `GF(q)`
and get the parity for free: `log_g a` is even exactly when `a` is a quadratic residue.

**Individual logarithm.** Find `s` with `h g^s` smooth over `FB`. Then

$$\log_g h \equiv \sum_i e_i \log_g q_i - s \pmod{p-1}$$

**Cost.** Smoothness probability for a random `y < p` over primes `<= B` is `u^{-u}` with
`u = log p / log B`; balancing gives
`L_p[1/2, sqrt(2)] = exp((sqrt 2 + o(1)) sqrt(ln p ln ln p))`. The number field sieve
improves the constant to `L_p[1/3]`, which is what makes 1024-bit DH uncomfortable and
512-bit DH (Logjam) breakable in minutes with precomputation.

**Binary fields.** In `GF(2^n)` the "primes" are irreducible polynomials, smoothness is far
more common, and the Barbulescu-Gaudry-Joux-Thome quasi-polynomial algorithm solves records
of thousands of bits. Treat any `GF(2^n)` DLP as broken.

## Attack

1. Triage with the table above.
2. Pick `B` around `exp(0.5 sqrt(ln p ln ln p))` -- in practice tune it: too small and
   relations never appear, too large and the linear algebra dominates.
3. Collect `m + 10` relations by walking `g, g^2, g^3, ...` and trial-dividing.
4. Solve mod the large prime factor of `p - 1`, fix parity with Legendre symbols, CRT.
5. Find one smooth `h g^s` and read off the answer.
6. Verify `g^x == h`.

## Code

```python
#!/usr/bin/env python3
"""A complete (small-scale) index calculus for a safe prime p = 2q + 1."""
import random
from math import gcd

def is_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for q in small:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in small:
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

def primes_up_to(b):
    sieve = bytearray([1]) * (b + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(b ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(2, b + 1) if sieve[i]]

def safe_prime(bits, rng):
    """p = 2q + 1 with both p and q prime."""
    while True:
        q = rng.randrange(1 << (bits - 2), 1 << (bits - 1)) | 1
        if is_prime(q) and is_prime(2 * q + 1):
            return 2 * q + 1, q

def smooth_vector(y, fb):
    """Exponent vector of y over the factor base, or None if not smooth."""
    e = [0] * len(fb)
    for i, q in enumerate(fb):
        while y % q == 0:
            y //= q
            e[i] += 1
    return e if y == 1 else None

def solve_mod_prime(rows, rhs, ncols, q):
    """Gaussian elimination over GF(q). Returns the solution or None if rank-deficient."""
    A = [r[:] + [v] for r, v in zip(rows, rhs)]
    piv_of_col = {}
    r = 0
    for c in range(ncols):
        pr = next((i for i in range(r, len(A)) if A[i][c] % q), None)
        if pr is None:
            continue
        A[r], A[pr] = A[pr], A[r]
        inv = pow(A[r][c], -1, q)
        A[r] = [v * inv % q for v in A[r]]
        for i in range(len(A)):
            if i != r and A[i][c] % q:
                f = A[i][c]
                A[i] = [(v - f * w) % q for v, w in zip(A[i], A[r])]
        piv_of_col[c] = r
        r += 1
        if r == len(A):
            break
    if len(piv_of_col) != ncols:
        return None
    return [A[piv_of_col[c]][ncols] % q for c in range(ncols)]

def index_calculus(g, h, p, q, bound, rng, max_trials=400000, batch=4000):
    """log_g(h) mod p-1 for a safe prime p = 2q + 1."""
    fb_all = primes_up_to(bound)
    rows, rhs, cur, k = [], [], 1, 0
    fb, logs_q = None, None
    while k < max_trials and logs_q is None:
        for _ in range(batch):                    # collect a batch of relations
            k += 1
            cur = cur * g % p
            e = smooth_vector(cur, fb_all)
            if e is not None:
                rows.append(e)
                rhs.append(k % q)
        # drop factor-base primes that never showed up, then try to solve
        cols = [i for i in range(len(fb_all)) if any(r[i] for r in rows)]
        if len(rows) < len(cols) + 5:
            continue
        sub = [[r[i] for i in cols] for r in rows]
        sol = solve_mod_prime(sub, rhs, len(cols), q)
        if sol is not None:
            fb, logs_q = [fb_all[i] for i in cols], sol
    if logs_q is None:
        raise RuntimeError("no full-rank relation set; raise the bound or the trial budget")

    # parity: log_g(a) is even exactly when a is a quadratic residue mod p
    logs = []
    for qi, lq in zip(fb, logs_q):
        parity = 0 if pow(qi, (p - 1) // 2, p) == 1 else 1
        # CRT of (lq mod q) and (parity mod 2) into mod 2q = p-1
        x = lq if lq % 2 == parity else lq + q
        logs.append(x % (p - 1))
        assert pow(g, logs[-1], p) == qi % p, "factor-base log is wrong"

    # individual logarithm: find s with h * g^s smooth
    for _ in range(max_trials):
        s = rng.randrange(1, p - 1)
        e = smooth_vector(h * pow(g, s, p) % p, fb)
        if e is None:
            continue
        x = (sum(ei * li for ei, li in zip(e, logs)) - s) % (p - 1)
        if pow(g, x, p) == h % p:
            return x, len(rows), len(fb)
    raise RuntimeError("no smooth h*g^s found")

if __name__ == "__main__":
    rng = random.Random(5)

    p, q = safe_prime(34, rng)
    # a generator of the full group Z_p^* (order p-1 = 2q)
    g = 2
    while pow(g, q, p) == 1 or pow(g, 2, p) == 1:
        g += 1
    assert pow(g, p - 1, p) == 1 and pow(g, q, p) != 1
    print(f"[ok] safe prime p = {p} ({p.bit_length()} bits), q = {q}")
    print(f"     p-1 = 2*q is NOT smooth, so Pohlig-Hellman is useless here")

    x = rng.randrange(2, p - 1)
    h = pow(g, x, p)
    rec, nrel, msize = index_calculus(g, h, p, q, 200, rng)
    assert rec == x, (rec, x)
    print(f"[ok] index calculus: {nrel} relations over a factor base of {msize} primes")
    print(f"[ok] log_g(h) = {rec} (correct)")

    # compare with what a generic method would have cost
    import math
    print(f"    generic sqrt(q) would need about {int(math.isqrt(q)):,} group operations")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Choosing `B`.** Too small: you never find `m + 10` relations. Too large: the Gaussian
  elimination is `O(m^3)` and dominates. Start at a few hundred for 32-bit primes, a few
  thousand for 64-bit.
- **Composite `p - 1`.** Solve the relation system modulo each prime power of `p - 1`
  separately, then CRT the factor-base logs. The safe-prime shortcut above (mod `q` plus
  Legendre parity) is the special case everyone uses in CTFs.
- **Rank deficiency.** Collect more relations than unknowns; duplicates and dependent rows
  are normal. Deleting a column for a prime that never appears also works.
- **Large-prime variation.** Accept relations with one factor slightly above `B` and combine
  two such relations sharing that prime. Roughly doubles the relation yield.
- **Sieving instead of trial division.** Real implementations sieve; trial division is fine
  up to ~50-bit primes.
- **Do not hand-roll for big primes.** For 300+ bits use CADO-NFS. For 512-bit DH primes,
  Logjam showed a week of precomputation per prime, then individual logs in minutes.
- **`GF(2^n)`.** Do not implement index calculus there by hand; Sage's `discrete_log` in
  `GF(2^n)` already uses good algorithms, and the field is weak anyway. A CTF using `GF(2^n)`
  for DH is handing you the solve.
- **The answer is only defined mod `ord(g)`.** Verify with `pow(g, x, p) == h`.

## Tools

```python
# SageMath: let the library pick the right algorithm
p = ...; F = GF(p)
print(discrete_log(F(h), F(g)))              # Pohlig-Hellman + BSGS/rho
K.<a> = GF(2^127)                            # binary field: quasi-polynomial under the hood
print(discrete_log(K(h), K(g)))
```

```sh
# PARI/GP: znlog handles moderate sizes and uses index calculus internally
gp -q -c 'print(znlog(Mod(h,p), Mod(g,p)))'
# CADO-NFS for the serious sizes (512-bit primes and beyond)
./cado-nfs.py -dlp -ell <subgroup-order> target=<h> <p>
```

## References

- https://en.wikipedia.org/wiki/Index_calculus_algorithm
- Adrian et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice" (Logjam, CCS 2015), https://weakdh.org/
- Barbulescu, Gaudry, Joux, Thome, "A heuristic quasi-polynomial algorithm for discrete logarithm in finite fields of small characteristic" (EUROCRYPT 2014)
- https://gitlab.inria.fr/cado-nfs/cado-nfs
