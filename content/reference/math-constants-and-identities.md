---
title: "Reference - Number Theory Facts for CTF Crypto"
category: crypto
subcategory: number-theory
type: reference
tags: [number-theory, euler, fermat, crt, chinese-remainder-theorem, quadratic-residue, tonelli-shanks, legendre, jacobi, order, generator, primitive-root, continued-fractions, birthday-bound, gcd, phi, lcm, complexity, sagemath, sympy]
summary: "The theorems, identities and algorithm complexities that CTF crypto actually uses, each with a runnable Python implementation."
related: [rsa-decision-tree, crypto-triage, sagemath]
---

## 1. Modular arithmetic basics

| Fact | Statement |
|---|---|
| Modular inverse exists | `a^-1 mod n` exists iff `gcd(a, n) == 1` |
| Computing it | extended Euclidean algorithm, or `pow(a, -1, n)` in Python 3.8+ |
| Fermat's little theorem | `p` prime, `gcd(a,p)=1` -> `a^(p-1) = 1 mod p`, so `a^-1 = a^(p-2) mod p` |
| Euler's theorem | `gcd(a,n)=1` -> `a^phi(n) = 1 mod n` |
| Exponent reduction | `a^e mod n = a^(e mod phi(n)) mod n` **only when** `gcd(a,n)=1` |
| Carmichael | `lambda(n)` is the smallest such exponent; `lambda(pq) = lcm(p-1, q-1)` divides `phi(pq)` |
| phi is multiplicative | `phi(mn) = phi(m)phi(n)` when `gcd(m,n)=1` |
| phi of a prime power | `phi(p^k) = p^k - p^(k-1) = p^(k-1)(p-1)` |
| phi of a semiprime | `phi(pq) = (p-1)(q-1) = n - p - q + 1` |
| Recovering p,q from n and phi | `s = n - phi + 1`; `p,q` are the roots of `x^2 - sx + n = 0` |
| gcd/lcm identity | `gcd(a,b) * lcm(a,b) = a*b` |
| Bezout | there exist `x,y` with `ax + by = gcd(a,b)` |
| Wilson | `p` prime iff `(p-1)! = -1 mod p` |
| Square roots mod p | exist for exactly `(p-1)/2` nonzero residues |
| Number of solutions of `x^e = c mod p` | `gcd(e, p-1)` (when a solution exists) |

```python
from math import gcd, isqrt

def egcd(a: int, b: int):
    """Return (g, x, y) with a*x + b*y = g = gcd(a,b)."""
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def inv(a: int, n: int) -> int:
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError(f"no inverse: gcd={g}")
    return x % n

def factor_from_phi(n: int, phi: int):
    """Recover (p, q) from n = p*q and phi = (p-1)(q-1)."""
    s = n - phi + 1
    disc = s * s - 4 * n
    r = isqrt(disc)
    if r * r != disc:
        raise ValueError("not a valid (n, phi) pair")
    return (s - r) // 2, (s + r) // 2
```

---

## 2. Chinese Remainder Theorem

Given pairwise-coprime moduli `n_i` and residues `a_i`, there is a unique `x mod N` (with `N = prod n_i`) such that `x = a_i mod n_i`.

Construction: `x = sum(a_i * N_i * inv(N_i, n_i)) mod N` where `N_i = N / n_i`.

**Where it shows up in CTF**
- Hastad broadcast: the same message under `e` different moduli -> CRT -> integer `e`-th root.
- CRT-RSA: `dp = d mod (p-1)`, `dq = d mod (q-1)`; decryption is 4x faster; a fault in one branch leaks a factor.
- Pohlig-Hellman: solve the DLOG in each prime-power subgroup, CRT the answers.
- Small-subgroup / invalid-curve attacks: recover the key mod many small primes, CRT.
- When moduli are **not** coprime you can still combine, if the residues agree on the common part.

```python
def crt(residues, moduli):
    """Solve x = residues[i] mod moduli[i] for pairwise-coprime moduli."""
    from math import prod
    N = prod(moduli)
    x = 0
    for a, n in zip(residues, moduli):
        Ni = N // n
        x += a * Ni * inv(Ni, n)
    return x % N, N

def crt_general(residues, moduli):
    """CRT that also works for non-coprime moduli. Returns (x, lcm) or None."""
    from math import gcd
    x, m = residues[0] % moduli[0], moduli[0]
    for a, n in zip(residues[1:], moduli[1:]):
        g = gcd(m, n)
        if (a - x) % g:
            return None
        lcm = m // g * n
        t = ((a - x) // g * inv(m // g, n // g)) % (n // g)
        x = (x + m * t) % lcm
        m = lcm
    return x, m
```

---

## 3. Quadratic residues

`a` is a **quadratic residue** mod `p` (odd prime) if `x^2 = a mod p` has a solution.

| Fact | Statement |
|---|---|
| Euler's criterion | `a^((p-1)/2) = 1 mod p` if QR, `= -1` if non-residue (`a` not divisible by `p`) |
| Count | exactly `(p-1)/2` nonzero QRs mod `p` |
| Product rule | QR * QR = QR, QR * NQR = NQR, NQR * NQR = QR |
| `-1` is a QR mod p | iff `p = 1 mod 4` |
| `2` is a QR mod p | iff `p` is congruent to 1 or 7 mod 8 |
| Square root when `p = 3 mod 4` | `x = a^((p+1)/4) mod p` - one line, no Tonelli-Shanks needed |
| Square root when `p = 5 mod 8` | `x = a^((p+3)/8)`, times `2^((p-1)/4)` if that fails |
| General case | Tonelli-Shanks |
| Square root mod `n = pq` | take roots mod `p` and `q`, CRT the 4 sign combinations -> 4 roots |
| Knowing two distinct roots mod n | `gcd(x - y, n)` factors `n` - this is the Rabin attack |

### Legendre and Jacobi symbols

- **Legendre** `(a/p)` for odd prime `p`: `0` if `p | a`, `1` if `a` is a QR, `-1` otherwise. Equals `a^((p-1)/2) mod p`.
- **Jacobi** `(a/n)` for odd `n = prod p_i^e_i`: the product of Legendre symbols. **Computable without factoring `n`**, in `O(log^2 n)`.
- Key subtlety: Jacobi `= 1` does **not** imply `a` is a QR mod composite `n`. This gap is the basis of the Goldwasser-Micali cryptosystem and of several CTF oracles.
- Quadratic reciprocity: for distinct odd primes, `(p/q)(q/p) = (-1)^((p-1)/2 * (q-1)/2)`.
- Supplements: `(-1/p) = (-1)^((p-1)/2)`, `(2/p) = (-1)^((p^2-1)/8)`.

```python
def legendre(a: int, p: int) -> int:
    """Legendre symbol (a/p) for odd prime p, returned as -1, 0 or 1."""
    a %= p
    if a == 0:
        return 0
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else 1


def jacobi(a: int, n: int) -> int:
    """Jacobi symbol (a/n) for odd n > 0. Works without factoring n."""
    assert n > 0 and n % 2 == 1
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def tonelli_shanks(a: int, p: int) -> int:
    """Return x with x*x = a (mod p), for odd prime p. Raises if a is not a QR."""
    a %= p
    if a == 0:
        return 0
    if legendre(a, p) != 1:
        raise ValueError("not a quadratic residue")
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    # factor p-1 as q * 2^s with q odd
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # find a quadratic non-residue z
    z = 2
    while legendre(z, p) != -1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p
    return r


def sqrt_mod_n(a: int, p: int, q: int):
    """All four square roots of a modulo n = p*q."""
    rp, rq = tonelli_shanks(a, p), tonelli_shanks(a, q)
    n = p * q
    roots = set()
    for sp in (rp, p - rp):
        for sq in (rq, q - rq):
            roots.add(crt([sp, sq], [p, q])[0])
    return sorted(roots)
```

---

## 4. Orders, generators, primitive roots

| Term | Definition |
|---|---|
| `ord_n(a)` | the smallest `k > 0` with `a^k = 1 mod n`. Divides `lambda(n)` (and `phi(n)`) |
| generator / primitive root | an element of order exactly `phi(n)` |
| existence of a primitive root mod n | only for `n = 1, 2, 4, p^k, 2p^k` with `p` an odd prime |
| number of primitive roots mod p | `phi(p-1)` |
| test for a generator mod p | `g^((p-1)/q) != 1 mod p` for every prime `q` dividing `p-1` (requires factoring `p-1`) |
| subgroup of order d | exists for each divisor `d` of `p-1`, and is cyclic |
| Lagrange | the order of any element divides the group order |
| safe prime | `p = 2q+1` with `q` prime; `p-1` has only the factors 2 and q, so Pohlig-Hellman fails |
| smooth order | `p-1` factors into small primes -> Pohlig-Hellman succeeds -> the DLOG is easy |

```python
from math import gcd
from sympy import factorint, totient

def order(a: int, n: int) -> int:
    """Multiplicative order of a modulo n. Requires gcd(a,n) == 1."""
    if gcd(a, n) != 1:
        raise ValueError("a and n must be coprime")
    t = int(totient(n))
    o = t
    for p, e in factorint(t).items():
        for _ in range(e):
            if pow(a, o // p, n) == 1:
                o //= p
            else:
                break
    return o


def is_primitive_root(g: int, p: int) -> bool:
    """True if g generates the full multiplicative group mod prime p."""
    for q in factorint(p - 1):
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True


def find_primitive_root(p: int) -> int:
    g = 2
    while not is_primitive_root(g, p):
        g += 1
    return g
```

---

## 5. Continued fractions

Every rational `a/b` has a finite continued fraction `[a0; a1, a2, ...]`. Its **convergents** `h_k/k_k` are the best rational approximations with denominators of their size.

**Why it matters**: Wiener's attack. If `d < n^0.25 / 3`, then `k/d` is a convergent of `e/n`, so enumerating the convergents of `e/n` recovers `d` in `O(log n)` steps.

Also used for: solving Pell's equation, recovering a rational from a truncated decimal, and the lattice-free version of some small-root problems.

```python
def cont_frac(x: int, y: int):
    """Continued-fraction expansion of x/y."""
    while y:
        a = x // y
        yield a
        x, y = y, x - a * y


def convergents(cf):
    """Yield (numerator, denominator) for each convergent."""
    n0, d0, n1, d1 = 0, 1, 1, 0
    for a in cf:
        n0, d0, n1, d1 = n1, d1, a * n1 + n0, a * d1 + d0
        yield n1, d1


def wiener(n: int, e: int):  # requires: from math import isqrt
    """Recover d when d is small. Returns d or None."""
    for k, d in convergents(cont_frac(e, n)):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            return d
    return None
```

---

## 6. Birthday bound and collision complexity

| Quantity | Value |
|---|---|
| Expected samples for a collision in a space of size `N` | `sqrt(pi*N/2)` ~ `1.253*sqrt(N)` |
| 50% collision probability | at about `1.177*sqrt(N)` samples |
| Generic collision on an `n`-bit hash | `2^(n/2)` work |
| Generic preimage on an `n`-bit hash | `2^n` work |
| Multi-target preimage, `t` targets | `2^n / t` |
| Meet-in-the-middle on double encryption (2 x k-bit keys) | `2^(k+1)` time, `2^k` memory |
| Collision with memory constraint | Pollard rho / distinguished points: `sqrt(N)` time, `O(1)` memory |
| Nonce collision for a 64-bit nonce | ~`2^32` messages |
| Birthday attack on a 128-bit block cipher's mode | ~`2^64` blocks (the "Sweet32" style bound) |

```python
import math

def birthday_samples(space_bits: int, prob: float = 0.5) -> float:
    """Expected number of samples for a collision with the given probability."""
    n = 2 ** space_bits
    return math.sqrt(2 * n * math.log(1 / (1 - prob)))

if __name__ == "__main__":
    for bits in (32, 48, 64, 128, 160, 256):
        print(f"{bits:3d}-bit space: ~2^{math.log2(birthday_samples(bits)):.1f} samples for 50%")
```

---

## 7. Algorithm complexity table

| Problem | Algorithm | Complexity |
|---|---|---|
| gcd | Euclid | `O(log^2 n)` bit ops |
| modular exponentiation | square-and-multiply | `O(log e * M(n))` |
| primality test | Miller-Rabin (probabilistic) | `O(k log^3 n)` |
| primality proof | AKS | polynomial but impractical; use ECPP in practice |
| integer factorisation | trial division | `O(sqrt(n))` |
| | Pollard rho | `O(n^(1/4))` = `O(sqrt(p))` for the smallest factor `p` |
| | Pollard p-1 | `O(B log B log^2 n)`; only if `p-1` is `B`-smooth |
| | Williams p+1 | analogous, needs `p+1` smooth |
| | Fermat | fast iff `\|p-q\|` is small (`O((p-q)^2/n)` steps) |
| | ECM (Lenstra) | `exp(sqrt(2 ln p ln ln p))` - best for factors up to ~60 digits |
| | Quadratic sieve | `exp(sqrt(ln n ln ln n))` - best for `n` up to ~100 digits |
| | GNFS | `exp(((64/9)^(1/3) + o(1)) (ln n)^(1/3) (ln ln n)^(2/3))` - best above that |
| discrete log (generic group, order `n`) | baby-step giant-step | `O(sqrt(n))` time and memory |
| | Pollard rho for DLOG | `O(sqrt(n))` time, `O(1)` memory |
| | Pohlig-Hellman | `O(sum e_i (log n + sqrt(p_i)))` over the factorisation of the order |
| discrete log in `GF(p)*` | index calculus / NFS-DL | subexponential, like factoring |
| discrete log on an elliptic curve | generic only (rho) | `O(sqrt(n))` - this is why ECC keys are short |
| ECDLP, anomalous curve (`#E = p`) | Smart's attack | `O(log p)` - instant |
| ECDLP, small embedding degree `k` | MOV / Frey-Ruck to `GF(p^k)` | index calculus in the target field |
| square root mod p | Tonelli-Shanks | `O(log^2 p)` average; `O(s^2)` where `2^s \|\| p-1` |
| lattice reduction | LLL | `O(d^5 log^3 B)` for dimension `d`, entries `< B` |
| | BKZ with block size `b` | exponential in `b`, much better bases |
| shortest vector (exact) | enumeration / sieving | `2^O(d)` |
| linear algebra over GF(2) | Gaussian elimination | `O(n^3)`, `O(n^2.37)` with fast methods |
| Berlekamp-Massey (LFSR recovery) | - | `O(n^2)` from `2n` output bits |
| Mersenne Twister state recovery | untempering | `O(624)` outputs, linear |
| Coppersmith small roots | LLL on a lattice of dimension ~`m*d` | polynomial; bound `X < n^(1/d)` for degree `d` |
| hash collision (generic) | birthday | `2^(n/2)` |
| MD5 collision | Wang / fastcoll / UniColl | seconds on a laptop |
| SHA-1 collision | SHAttered / chosen-prefix | ~`2^63` (done, expensive) |

---

## 8. Sizes worth memorising

| Value | Bits | Note |
|---|---|---|
| `2^10` | 10 | ~1e3 |
| `2^20` | 20 | ~1e6 - brute-forceable instantly |
| `2^32` | 32 | ~4.3e9 - brute-forceable in seconds to minutes |
| `2^40` | 40 | ~1e12 - minutes to hours |
| `2^56` | 56 | DES key - hours on a GPU cluster |
| `2^64` | 64 | ~1.8e19 - infeasible by brute force, feasible by birthday |
| `2^80` | 80 | the old "80-bit security" floor |
| `2^128` | 128 | AES-128, the modern floor |
| 512-bit RSA | 512 | factorable in hours with CADO-NFS |
| 768-bit RSA | 768 | factored in 2009 (academic effort) |
| 1024-bit RSA | 1024 | not factorable in a CTF; look for a different bug |
| 2048-bit RSA | 2048 | standard |
| 256-bit ECC | 256 | ~128-bit security |

If a CTF hands you a 256-bit or 512-bit modulus, factoring **is** the intended path. If it hands you 2048 bits, it never is.

---

## 9. Tool one-liners

```sh
# Sage: factorisation, discrete log, orders, primality
sage -c "print(factor(1234567891011))"
sage -c "p=10007; print(discrete_log(Mod(3,p), Mod(5,p)))"
sage -c "print(Mod(2,101).multiplicative_order())"
sage -c "print(primitive_root(10007))"
sage -c "n=..; print(Integer(n).is_prime())"
# Sage: quadratic residues and roots
sage -c "print(Mod(3,11).is_square(), Mod(5,11).sqrt())"
sage -c "print(kronecker_symbol(3, 11))"
# Sage: CRT
sage -c "print(CRT_list([2,3,2],[3,5,7]))"
# Sage: continued fractions
sage -c "print(continued_fraction(17/12).convergents())"
```
```python
# sympy equivalents (no Sage needed)
from sympy import factorint, isprime, totient, primitive_root, discrete_log, sqrt_mod, jacobi_symbol, nextprime
print(factorint(1234567891011))
print(primitive_root(10007))
print(discrete_log(10007, 5, 3))
print(sqrt_mod(3, 11, all_roots=True))
print(jacobi_symbol(3, 11))
```
`ctfbrain search sagemath`
