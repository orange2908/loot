---
title: "DLP - Diffie-Hellman Attacks: Small Subgroups, Bad Generators, Parameter Injection"
category: crypto
subcategory: dlp
type: technique
tags: [diffie-hellman, dh, dlp, discrete-log, small-subgroup, subgroup-confinement, parameter-injection, mitm, key-validation, static-key, generator, order, crt, chinese-remainder-theorem, pohlig-hellman, logjam, safe-prime, python, sage]
difficulty: medium
summary: "Send g=1, y=0, y=p-1 or a small-order element and the shared secret stops being secret. With a static key, small subgroups leak the exponent by CRT."
when_to_use:
  - "A DH implementation accepts p, g or the peer public key from the wire without checks"
  - "The prime is not a safe prime and the cofactor has small factors"
  - "One side reuses a static secret exponent across sessions"
  - "You can act as a man in the middle on the parameter exchange"
tools: [python, sage, pari]
related: [dlp-pohlig-hellman, dlp-bsgs-pollard-rho, ecc-invalid-curve, ecc-twist-attack, dlp-index-calculus]
---

## TL;DR

Textbook DH assumes `p` is a safe prime, `g` generates a large prime-order subgroup, and both
sides validate the received public value. Drop any one of those and the shared secret becomes
predictable or leaky. The three families: **degenerate parameters** (`g` or `y` in `{0, 1, p-1}`),
**small-subgroup confinement** (force the secret into a tiny group and read the exponent
modulo small primes), and **parameter injection** (a MITM rewrites `p`, `g` or `y`).

## Recognise it

- The protocol sends `p` and `g` on the wire and the client just uses them.
- `shared = pow(peer, secret, p)` with no `if not 1 < peer < p-1: abort`.
- `p` generated as `product_of_primes + 1` or simply "a random prime" (not `2q+1`).
- The same `secret` is loaded from a file or generated once at startup.
- A "key confirmation" step that reveals a hash/MAC of the shared secret -- that is the oracle.

## Theory

**Degenerate values.**

| injected | resulting shared secret | note |
| --- | --- | --- |
| `g = 1` | `1` | both sides compute `1^x = 1` |
| `g = 0` | `0` | and `0^x = 0` |
| `g = p` | `0` | `p = 0` |
| `g = p - 1` | `1` or `p - 1` | order 2: one bit of the exponent |
| peer `y = 1` | `1` | victim computes `1^b` |
| peer `y = 0` | `0` | |
| peer `y = p - 1` | `+/-1` | leaks `b mod 2` |

Each of these fixes the session key to a value the attacker knows, without any discrete log.

**Small-subgroup confinement.** Let `p - 1 = 2 q_1 q_2 ... Q` with `Q` a large prime (the
intended subgroup) and `q_i` small. For each small `q_i`, `h_i = x^{(p-1)/q_i} mod p` has
order `q_i`. Send `h_i` as your public value. The victim replies with (a function of)
`h_i^b = h_i^{b mod q_i}`, which takes only `q_i` values: brute force to learn `b mod q_i`.
Collect enough `q_i` and CRT:

$$b \bmod \prod_i q_i$$

If `prod q_i > b`, that *is* `b`. Otherwise finish with a kangaroo over the residual range.
This needs a **static** `b`; one query per ephemeral key is worthless.

**Why safe primes fix it.** With `p = 2q + 1`, the only subgroups have order `1, 2, q, 2q`.
The only small one is `{1, p-1}`, which leaks one bit -- and that is why implementations
should also send `g` of order `q` and check `y^q == 1`.

**Validation that actually works.**

1. `1 < y < p - 1`.
2. `y^q mod p == 1` where `q` is the intended subgroup order.
3. Never accept `p`, `g` from an untrusted peer; use a named group (RFC 3526 / RFC 7919).

**Parameter injection MITM.** If the attacker sits between the parties and rewrites `g` to
`1`, both derive the key `1` and the MITM decrypts everything while both sides believe the
handshake succeeded. Rewriting `y_A` and `y_B` to `1` achieves the same without touching `g`.
This is the classic "DH has no authentication" lesson: the fix is signing the parameters.

## Attack

1. Probe the degenerate values first: `y in {0, 1, p-1, p}`. They cost nothing.
2. Factor `p - 1`. Anything small in there is a subgroup to confine into.
3. If `b` is static: for each small `q`, build an order-`q` element, query, brute force
   `b mod q`.
4. CRT. Verify against the victim's real public key `g^b`.
5. If the modulus is still short of `b`, kangaroo the remainder.

## Code

```python
#!/usr/bin/env python3
"""Diffie-Hellman: degenerate parameters and small-subgroup confinement, simulated offline."""
import hashlib
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

def crt(rs, ms):
    x, m = 0, 1
    for r, n in zip(rs, ms):
        g = gcd(m, n)
        assert (r - x) % g == 0, "inconsistent residues"
        t = ((r - x) // g * pow(m // g, -1, n // g)) % (n // g)
        x, m = x + m * t, m // g * n
    return x % m

class DHPeer:
    """A peer with a STATIC secret exponent that validates nothing."""

    def __init__(self, p, g, secret):
        self.p, self.g, self.secret = p, g, secret
        self.public = pow(g, secret, p)
        self.queries = 0

    def key_confirmation(self, peer_public):
        """Returns a hash of the shared secret -- the usual CTF oracle."""
        self.queries += 1
        shared = pow(peer_public, self.secret, self.p)
        return hashlib.sha256(str(shared).encode()).digest()

def kc(shared):
    return hashlib.sha256(str(shared).encode()).digest()

def order_q_element(p, q, rng):
    """An element of exact order q, for q | p-1."""
    while True:
        h = pow(rng.randrange(2, p - 1), (p - 1) // q, p)
        if h != 1:
            return h

def small_subgroup_attack(peer, p, small_primes, rng):
    """Recover the peer's static exponent modulo the product of small_primes."""
    rs, ms = [], []
    for q in small_primes:
        h = order_q_element(p, q, rng)
        target = peer.key_confirmation(h)
        cur = 1
        for j in range(q):
            if kc(cur) == target:
                rs.append(j)
                ms.append(q)
                break
            cur = cur * h % p
    return crt(rs, ms), ms

def build_weak_prime(rng, big_bits=64, smooth_bound=101):
    """p - 1 = 2 * Q * (product of small primes): a big subgroup plus a smooth cofactor."""
    smalls = [q for q in primes_up_to(smooth_bound) if q > 2]
    M = 1
    for q in smalls:
        M *= q
    while True:
        Q = rng.randrange(1 << (big_bits - 1), 1 << big_bits) | 1
        if not is_prime(Q):
            continue
        p = 2 * Q * M + 1
        if is_prime(p):
            return p, Q, M, smalls

if __name__ == "__main__":
    rng = random.Random(42)

    # ---- 1. degenerate parameters on a perfectly good safe prime ----
    while True:
        q0 = rng.randrange(1 << 63, 1 << 64) | 1
        if is_prime(q0) and is_prime(2 * q0 + 1):
            ps = 2 * q0 + 1
            break
    gs = 4                                   # a generator of the order-q subgroup
    bob = DHPeer(ps, gs, rng.randrange(2, q0))
    for injected, expected in [(1, 1), (0, 0), (ps, 0)]:
        assert bob.key_confirmation(injected) == kc(expected)
    assert bob.key_confirmation(ps - 1) in (kc(1), kc(ps - 1))
    parity = 0 if bob.key_confirmation(ps - 1) == kc(1) else 1
    assert parity == bob.secret % 2
    print("[ok] injected y in {0, 1, p, p-1}: shared secret forced, and p-1 leaks b mod 2")

    # ---- 2. small-subgroup confinement on a non-safe prime ----
    p, Q, M, smalls = build_weak_prime(rng)
    print(f"[ok] p is {p.bit_length()} bits; p-1 = 2 * Q({Q.bit_length()} bits) * "
          f"{len(smalls)} small primes")
    g = pow(rng.randrange(2, p - 1), (p - 1) // Q, p)
    while g == 1:
        g = pow(rng.randrange(2, p - 1), (p - 1) // Q, p)
    assert pow(g, Q, p) == 1

    victim = DHPeer(p, g, rng.randrange(2, Q))
    usable = [q for q in smalls if q <= 200]
    rec, mods = small_subgroup_attack(victim, p, usable, rng)
    modulus = 1
    for m in mods:
        modulus *= m
    print(f"[ok] {victim.queries} queries -> b known modulo a {modulus.bit_length()}-bit number")
    assert modulus > Q, "the smooth cofactor must exceed the subgroup order for a full break"
    assert rec == victim.secret
    assert pow(g, rec, p) == victim.public
    print(f"[ok] static exponent fully recovered: b = {rec}")

    # ---- 3. the fix: validate the peer public value ----
    def validated_exchange(p, q, secret, peer_public):
        if not 1 < peer_public < p - 1:
            raise ValueError("peer public value out of range")
        if pow(peer_public, q, p) != 1:
            raise ValueError("peer public value is not in the order-q subgroup")
        return pow(peer_public, secret, p)

    bad = order_q_element(p, usable[0], rng)
    for probe in (0, 1, p - 1, p, bad):
        try:
            validated_exchange(p, Q, victim.secret, probe)
            raise AssertionError(f"probe {probe} should have been rejected")
        except ValueError:
            pass
    good = pow(g, rng.randrange(2, Q), p)
    assert validated_exchange(p, Q, victim.secret, good) == pow(good, victim.secret, p)
    print("[ok] range + subgroup validation rejects every probe and accepts honest keys")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Ephemeral keys defeat the subgroup attack.** You get one residue per key, and each key is
  different. Look for a static/semi-static key, a long-lived session, or a server that
  re-derives from the same secret.
- **The oracle need not be a hash.** A ciphertext, a MAC, an "invalid padding" message, or
  even a timing difference works: you only need to distinguish `q` possibilities.
- **Order-`q` element construction.** `x^{(p-1)/q}` has order dividing `q`; it equals `1` with
  probability `1/q`, so retry. For `q = 2` you get exactly `p - 1`.
- **CRT modulus too small.** With a safe prime you can only ever get `b mod 2`. With a random
  prime, the smooth part of `p - 1` bounds what you can learn. Combine with a kangaroo over
  the remaining range.
- **`g` of composite order.** If `ord(g)` is not prime, the honest protocol itself leaks
  `b mod (small factors)` to a passive observer who can compute `y_B^{ord/q}`.
- **Logjam / downgrade.** Injecting *weaker parameters* (512-bit export-grade `p`) is the
  same family: you do not break DH, you make it small enough to break.
- **Elliptic-curve analogue.** Exactly the same attack with points instead of residues:
  see `ecc-invalid-curve` and `ecc-twist-attack`.
- **Check `p` too.** If the attacker supplies `p`, they can supply a composite or a prime with
  fully smooth `p - 1`, which makes the DLP itself trivial.

## Tools

```python
# SageMath: audit a set of DH parameters in five lines
p = ...; g = ...
print(is_prime(p), is_prime((p - 1) // 2))            # safe prime?
print(factor(p - 1))                                   # smooth cofactor?
print(Mod(g, p).multiplicative_order().factor())       # what does g generate?
```

```sh
# inspect the DH parameters an OpenSSL file or server offers
openssl dhparam -in dhparams.pem -text -noout
openssl s_client -connect host:443 -cipher 'EDH' 2>/dev/null | grep -i 'temp key'
```

## References

- https://weakdh.org/ (Logjam, and why 512/1024-bit groups matter)
- https://datatracker.ietf.org/doc/html/rfc7919 (named finite-field DH groups)
- Lim, Lee, "A key recovery attack on discrete log-based schemes using a prime order subgroup" (CRYPTO 1997)
- van Oorschot, Wiener, "On Diffie-Hellman key agreement with short exponents" (EUROCRYPT 1996)
