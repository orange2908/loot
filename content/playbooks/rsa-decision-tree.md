---
title: "Playbook - RSA Decision Tree by Known Parameters"
category: crypto
subcategory: rsa
type: playbook
tags: [rsa, rsa-decision-tree, what-attack, stuck, wiener, boneh-durfee, coppersmith, hastad, common-modulus, fermat, pollard-p-1, factordb, rsactftool, franklin-reiter, lsb-oracle, blinding, multiprime, phi, dp, sagemath]
summary: "Lookup table: given exactly which RSA values you know, which attack applies and the exact command to run."
when_to_use:
  - "You have an RSA challenge and a partial set of parameters"
  - "You need to know whether n is factorable before spending time"
  - "You have unusual extras: dp, dq, a hint about p, two moduli, two exponents"
related: [crypto-triage, rsactftool, factordb, sagemath, math-constants-and-identities]
---

## TL;DR

```sh
# run this before thinking. it covers ~20 classic cases.
RsaCtfTool -n <n> -e <e> --uncipher <c> --attack all
# and this. if n is in factordb you are done in 3 seconds.
curl -s "http://factordb.com/api?query=<n>" | python3 -m json.tool
```
If both fail, use the table.

---

## Section A - The master lookup table

`m` = message, `c = m^e mod n`, `n = p*q`, `phi = (p-1)(q-1)`, `d = e^-1 mod phi`.

| # | You know | Extra condition | Attack | Command / search |
|---|---|---|---|---|
| 1 | n, e, c | nothing | try the whole ladder below | `RsaCtfTool --attack all` |
| 2 | n, e, c | n < ~2^400 or n in factordb | just factor it | `ctfbrain search factordb yafu` |
| 3 | n, e, c | `e` = 1 | `m = c` | `long_to_bytes(c)` |
| 4 | n, e, c | small `e` (3,5,17) and `m^e < n` | integer e-th root | `gmpy2.iroot(c, e)` |
| 5 | n, e, c | small `e`, `m^e` slightly > n | root of `c + k*n` for k=0..N | `ctfbrain search small-exponent-root` |
| 6 | e ciphertexts of same m under e different n | `e` small, moduli coprime | Hastad broadcast (CRT + e-th root) | `ctfbrain search hastad-broadcast` |
| 7 | n, e1, e2, c1, c2 | same n, `gcd(e1,e2)=1` | common modulus: Bezout `a*e1+b*e2=1`, `m = c1^a * c2^b` | `ctfbrain search rsa-common-modulus` |
| 8 | n1, n2 (two moduli) | they share a prime | `p = gcd(n1,n2)` | `ctfbrain search rsa-common-factor batch-gcd` |
| 9 | many moduli | any two share a prime | batch GCD | `ctfbrain search batch-gcd` |
| 10 | n, e, d | - | factor n from (e,d) via the standard randomized algorithm | `ctfbrain search factor-n-from-d` |
| 11 | n, e, c | `d < n^0.292` (i.e. `e` is huge, near n) | Wiener (continued fractions) / Boneh-Durfee (lattice) | `ctfbrain search rsa-wiener boneh-durfee` |
| 12 | n, e, c | `p` and `q` close (`\|p-q\|` small) | Fermat factorisation | `ctfbrain search fermat-factorisation` |
| 13 | n, e, c | `p-1` smooth | Pollard p-1 | `ctfbrain search pollard-p-minus-1` |
| 14 | n, e, c | `p+1` smooth | Williams p+1 | `ctfbrain search williams-p-plus-1` |
| 15 | n, e, c | `n` has many small factors | Lenstra ECM | `ecm -c 1000 <B1> < n.txt` |
| 16 | n, e, c | `n = p^k` or `p == q` | `iroot(n,k)`; phi = `p^(k-1)*(p-1)` | `ctfbrain search rsa-perfect-power` |
| 17 | n, e, c | `n = p*q*r...` (multi-prime) | factor all, `phi = prod(p_i - 1)` | `ctfbrain search multiprime-rsa` |
| 18 | n, e, c, high/low bits of p | >= ~50% of p known | Coppersmith / `small_roots` | `ctfbrain search coppersmith-partial-p` |
| 19 | n, e, c, most bits of d | ~25% of d low bits | Coppersmith on d / Boneh-Durfee-Frankel | `ctfbrain search partial-key-exposure` |
| 20 | n, e, c, most bits of m | remaining unknown < `n^(1/e)` | Coppersmith stereotyped message | `ctfbrain search stereotyped-message` |
| 21 | n, e, c1, c2 | `m2 = f(m1)` for known low-degree `f` | Franklin-Reiter related message + GCD of polynomials | `ctfbrain search franklin-reiter` |
| 22 | n, e, c | `e=3` and PKCS#1 v1.5 signature | Bleichenbacher '06 signature forgery | `ctfbrain search bleichenbacher-signature-forgery` |
| 23 | n, e, oracle for parity/LSB of decryption | - | LSB oracle: binary search, ~log2(n) queries | `ctfbrain search rsa-lsb-oracle` |
| 24 | n, e, oracle "is padding valid" | PKCS#1 v1.5 | Bleichenbacher '98 (Million Message) | `ctfbrain search bleichenbacher-padding-oracle` |
| 25 | n, e, a decrypt oracle that refuses only `c` | - | blinding: send `c * r^e mod n`, divide result by `r` | `ctfbrain search rsa-blinding` |
| 26 | n, e, a sign oracle | - | multiplicative forgery: `sig(m1)*sig(m2) = sig(m1*m2)` | `ctfbrain search rsa-signature-forgery` |
| 27 | n, dp (= d mod p-1), e | - | `p = gcd(pow(2,e*dp,n) - 2, n)` | see code below |
| 28 | dp, dq, p, q, c | CRT private key | CRT decrypt directly | see code below |
| 29 | dp, dq, p, q + a fault in one half | one signature is faulty | Bellcore fault attack: `p = gcd(sig^e - m, n)` | `ctfbrain search bellcore-fault-attack` |
| 30 | n, e, c | `e` shares a factor with phi (`gcd(e,phi) = g > 1`) | e-th root in the ring: AMM / Adleman-Manders-Miller | `ctfbrain search amm-root e-gcd-phi` |
| 31 | n, e, c | `gcd(e, phi)` = 2 and n prime power | Rabin-style: 4 roots, CRT them | `ctfbrain search rabin-cryptosystem` |
| 32 | p, q, e, c | - | just decrypt | `d = pow(e,-1,(p-1)*(q-1))` |
| 33 | n, phi, e, c | - | `d = pow(e,-1,phi)` | direct |
| 34 | n, e, c, and n generated by a bad RNG | keys from an embedded device | look for shared primes across a key corpus | `ctfbrain search batch-gcd` |
| 35 | n, e, c | modulus reused across challenges in the same CTF | try gcd with every other n you have | `ctfbrain search batch-gcd` |
| 36 | n, e, c | plaintext is small AND padded with a known constant | Coppersmith with the known part | `ctfbrain search coppersmith` |
| 37 | n, e, c | `m` is a flag of known length L, `e*L*8 < n.bit_length()` | plain e-th root works | `gmpy2.iroot` |
| 38 | n, e, c | "textbook RSA" + short message space | brute force: encrypt every candidate and compare | dictionary attack |
| 39 | n, e, c1..ck for the same m with different padding you control | - | Coppersmith short-pad / related message | `ctfbrain search coppersmith-short-pad` |
| 40 | signature s and message m, n unknown | several (m,s) pairs | `n = gcd(s1^e - m1, s2^e - m2, ...)` | see code below |

---

## Section B - The decision flow (run top to bottom)

```
START: you have n, e, c
 |
 |-- e == 1?                      -> m = c
 |-- n.bit_length() <= 400?       -> factordb / yafu / cado-nfs  -> you have p,q -> DONE
 |-- n in factordb?               -> DONE
 |-- e <= 11?
 |     |-- iroot(c, e) exact?     -> DONE
 |     |-- iroot(c + k*n, e) for k in 0..1e6 exact? -> DONE
 |     |-- do you have e ciphertexts of the same m? -> Hastad
 |     |-- do you know part of m?  -> Coppersmith stereotyped
 |-- e.bit_length() ~ n.bit_length()?  -> Wiener, then Boneh-Durfee
 |-- isqrt(n)^2 close to n, Fermat converges in < 1e7 steps? -> DONE
 |-- Pollard p-1 with B1=1e6 finds a factor?  -> DONE
 |-- Williams p+1?                -> DONE
 |-- ECM with B1=1e6, 1000 curves? -> DONE (works for factors up to ~35 digits)
 |-- do you have a second modulus anywhere in this CTF? -> gcd
 |-- do you have an oracle (a service)? -> LSB / padding / blinding
 |-- is there anything else in the handout (dp? a hint? a seed? a timestamp?)
 |      -> that IS the intended attack; the standard attacks are decoys
 |-- else: the bug is in HOW the primes were generated. Read the generator source.
```

---

## Section C - Runnable code for the awkward cases

```python
#!/usr/bin/env python3
"""RSA helper set for the cases the generic tools miss."""
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes, inverse
import random


def fermat_factor(n: int, max_steps: int = 10_000_000):
    """Works when |p-q| is small. Returns (p, q) or None."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def pollard_p_minus_1(n: int, bound: int = 200_000):
    """Works when p-1 is bound-smooth."""
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None


def factor_from_dp(n: int, e: int, dp: int):
    """Given dp = d mod (p-1), recover p. Classic 'CRT leak' challenge."""
    p = gcd(pow(2, e * dp, n) - 2, n)
    if 1 < p < n:
        return p, n // p
    return None


def factor_from_d(n: int, e: int, d: int):
    """Standard probabilistic factorisation of n given (e, d)."""
    k = e * d - 1
    while True:
        g = random.randrange(2, n - 1)
        t = k
        while t % 2 == 0:
            t //= 2
            x = pow(g, t, n)
            y = gcd(x - 1, n)
            if x > 1 and y > 1:
                return y, n // y


def crt_decrypt(c: int, dp: int, dq: int, p: int, q: int) -> int:
    """Decrypt using CRT components only."""
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    qinv = inverse(q, p)
    h = (qinv * (m1 - m2)) % p
    return m2 + h * q


def recover_n_from_signatures(pairs, e: int):
    """pairs = [(m1, s1), (m2, s2), ...]; n = gcd(s_i^e - m_i)."""
    g = 0
    for m, s in pairs:
        g = gcd(g, pow(s, e) - m)
    # strip small factors that sneak in
    for small in (2, 3, 5, 7, 11, 13):
        while g % small == 0:
            g //= small
    return g


def common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    """gcd(e1,e2) must be 1."""
    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y
    g, a, b = egcd(e1, e2)
    assert g == 1, "exponents are not coprime"
    if a < 0:
        c1, a = inverse(c1, n), -a
    if b < 0:
        c2, b = inverse(c2, n), -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def wiener(n: int, e: int):
    """Continued-fraction attack. Returns d or None."""
    def cf(x, y):
        while y:
            a = x // y
            yield a
            x, y = y, x - a * y

    def convergents(seq):
        n0, d0, n1, d1 = 0, 1, 1, 0
        for a in seq:
            n0, d0, n1, d1 = n1, d1, a * n1 + n0, a * d1 + d0
            yield n1, d1

    for k, d in convergents(cf(e, n)):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            return d
    return None


if __name__ == "__main__":
    # self-test: Fermat
    p = 1000003
    q = 1000033
    n = p * q
    assert set(fermat_factor(n)) == {p, q}

    # self-test: common modulus
    from Crypto.Util.number import getPrime, bytes_to_long
    p, q = getPrime(256), getPrime(256)
    n = p * q
    m = bytes_to_long(b"flag{common_modulus}")
    e1, e2 = 17, 65537
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    assert common_modulus(n, e1, e2, c1, c2) == m

    # self-test: factor from d
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    assert set(factor_from_d(n, e, d)) == {p, q}

    # self-test: Wiener
    while True:
        p, q = getPrime(512), getPrime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = getPrime(100)
        if gcd(d, phi) == 1:
            break
    e = inverse(d, phi)
    assert wiener(n, e) == d
    print("all self-tests passed")
```

---

## Section D - Coppersmith (needs SageMath)

Use when you know a large chunk of an unknown and the unknown is small relative to `n`.

```sage
# sage script: partial_p.sage  -- run: sage partial_p.sage
n = 0x00           # <- paste the modulus here
p_high = 0x00      # <- known high bits of p, with the unknown low bits zeroed
unknown_bits = 128 # how many low bits of p you do NOT know

P.<x> = PolynomialRing(Zmod(n))
f = (p_high + x).monic()
roots = f.small_roots(X=2**unknown_bits, beta=0.4, epsilon=0.02)
print(roots)
# then p = p_high + roots[0]
```

| Coppersmith variant | Bound | Use |
|---|---|---|
| Known high bits of p | need >= half of p | factor n |
| Stereotyped message | unknown part < `n^(1/e)` | recover m |
| Short pad | pad length < `n^(1/e^2)` | recover m from two ciphertexts |
| Partial d (low bits) | `n^(1/4)` of d | recover d |
| Hastad with padding | k >= e^2 ciphertexts | recover m |

Rules of thumb for `small_roots`: `beta` = (size of the factor you target)/(size of n); increase `epsilon` to go faster and lose bound; raise the lattice dimension (`m`, `t`) to go slower and gain bound.

---

## Section E - Sanity checks that save you an hour

```python
# is c actually a valid ciphertext, or is it already the plaintext?
print(long_to_bytes(c)[:40])
# do the parameters even make a valid key?
assert pow(pow(2, e, n), d, n) == 2, "e and d do not match n"
# is the recovered m sensible?
print(long_to_bytes(m))
# did the flag get padded? check for leading nulls / PKCS markers
print(long_to_bytes(m).hex()[:64])
```

- If `long_to_bytes(m)` is garbage but ends in readable text, you are missing leading zero bytes: `long_to_bytes(m).rjust(k, b'\x00')`.
- If `n.bit_length()` is not a round number (1024/2048), primes were generated oddly -> read the generator.
- If `e` is even, `gcd(e, phi) != 1`: this is Rabin/AMM territory, not textbook RSA.
- Check `is_prime(n)`: some challenges hand you a prime "modulus", making phi = n-1.

## References
- RsaCtfTool: `ctfbrain search rsactftool`
- factordb: `ctfbrain search factordb`
- SageMath: `ctfbrain search sagemath`
