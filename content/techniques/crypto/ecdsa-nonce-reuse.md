---
title: "ECDSA - Nonce Reuse to Private Key Recovery"
category: crypto
subcategory: ecdsa
type: technique
tags: [ecdsa, dsa, nonce-reuse, repeated-r, private-key-recovery, modular-inverse, secp256k1, signature, ps3, sony, blockchain, k-reuse, linear-nonce-relation, python, sage]
difficulty: easy
summary: "Two signatures with the same r share the nonce k. One subtraction and two inversions give k, then the private key d = (s*k - h)/r mod n."
when_to_use:
  - "Two signatures from the same key share the same r value"
  - "A signing oracle returns deterministic-looking signatures for different messages"
  - "The source calls random.seed() before signing, or uses a fixed k"
  - "You scraped a blockchain / log and want to scan for duplicate r"
tools: [python, sage, ecdsa]
related: [ecdsa-biased-nonce-lll, ecdsa-weak-k-derivation, ecdsa-malleability, ecc-toolkit, dlp-diffie-hellman-attacks]
---

## TL;DR

ECDSA signs with `s = k^{-1}(h + r d) mod n`, where `r = x(kG) mod n`. The nonce `k` must be
fresh and secret. Reuse it once and two signatures give a 2x2 linear system in `(k, d)`:

$$k = \frac{h_1 - h_2}{s_1 - s_2}, \qquad d = \frac{s_1 k - h_1}{r} \pmod n$$

Same `r` in two signatures is the tell, and it is visible without any secret.

## Recognise it

- Two signatures `(r, s1)` and `(r, s2)` with the **same `r`** and `s1 != s2`.
- The source has `k = 1337`, `k = int(time.time())`, `random.seed(0)` before signing, or
  `k = sha256(privkey)` with no message input.
- A service signs any message you submit and you notice a repeated `r` across messages.
- A blockchain address whose transactions repeat an `r`.
- Two *different keys* signing with the same `k` (the Sony PS3 / "fail0verflow" shape).

## Theory

ECDSA signing, group order `n`, private key `d`, public key `Q = dG`, message hash `h`
(truncated to `n.bit_length()` bits):

$$r = x(kG) \bmod n, \qquad s = k^{-1}(h + r d) \bmod n$$

**Same `k`, same `d`.** Both signatures have the same `r` because `r` depends only on `k`.

$$s_1 k = h_1 + r d, \qquad s_2 k = h_2 + r d$$

Subtract: `(s1 - s2) k = h1 - h2`, so `k = (h1 - h2)(s1 - s2)^{-1} mod n`. Then
`d = (s1 k - h1) r^{-1} mod n`. Two inversions, no search.

**Same `k`, different `d`.** Two users share a broken RNG. From
`s_1 k = h_1 + r d_1` and `s_2 k = h_2 + r d_2` you have two equations and three unknowns --
under-determined *unless* you know one of `d_1, d_2` (then you get `k` and hence the other),
or unless one party's `d` is also guessable. In practice the CTF gives you one key.

**Known linear relation between nonces.** If `k_2 = a k_1 + b` with `a, b` known (a LCG step,
a counter, `k, k+1`, `k, 2k`), then

$$s_1 k_1 = h_1 + r_1 d, \qquad s_2 (a k_1 + b) = h_2 + r_2 d$$

is again two equations in `(k_1, d)`. Eliminate `k_1`:

$$d = \frac{a s_2 h_1 - s_1 h_2 + s_1 s_2 b}{s_1 r_2 - a s_2 r_1} \bmod n$$

This is the generalisation worth memorising, since `a = 1, b = 0` recovers the classic case
only when `r_1 = r_2`.

**Sign/negation.** Because `(r, s)` and `(r, -s)` are both valid, a naive collector may show
`s_2 = -s_1`; then `s_1 - s_2 = 2 s_1` and the same formula still works -- the recovered `k`
is just the negated nonce. Verify `d G == Q` at the end, and if it fails try `-k`.

## Attack

1. Collect signatures with their message hashes.
2. Group by `r`. Any group of size >= 2 with distinct `s` is exploitable.
3. Compute `k` and `d` with the formulas above.
4. Verify `d*G == Q`. If not, retry with `k -> n - k` (or swap the two signatures).
5. Forge at will: sign any message with the recovered `d`.

## Code

```python
#!/usr/bin/env python3
"""ECDSA nonce reuse: detection, key recovery, and the linear-relation generalisation."""
import hashlib
import random

# ---- secp256k1 in ~30 lines ---------------------------------------------

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def ec_add(A, B):
    if A is None:
        return B
    if B is None:
        return A
    (x1, y1), (x2, y2) = A, B
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    lam = ((3 * x1 * x1) * pow(2 * y1 % P, -1, P) if A == B
           else (y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def ec_mul(k, A):
    R, S = None, A
    k %= N
    while k:
        if k & 1:
            R = ec_add(R, S)
        S, k = ec_add(S, S), k >> 1
    return R

def h_of(msg):
    """Message hash truncated to the bit length of n, as ECDSA requires."""
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

def sign(d, msg, k):
    r = ec_mul(k, G)[0] % N
    s = pow(k, -1, N) * (h_of(msg) + r * d) % N
    assert r and s, "degenerate signature, pick another k"
    return r, s

def verify(Q, msg, sig):
    r, s = sig
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    h = h_of(msg)
    X = ec_add(ec_mul(h * w % N, G), ec_mul(r * w % N, Q))
    return X is not None and X[0] % N == r

# ---- the attacks --------------------------------------------------------

def find_repeated_r(sigs):
    """sigs = [(msg, r, s), ...] -> list of index pairs sharing r."""
    seen, pairs = {}, []
    for i, (_, r, s) in enumerate(sigs):
        for j in seen.get(r, []):
            if sigs[j][2] != s:
                pairs.append((j, i))
        seen.setdefault(r, []).append(i)
    return pairs

def recover_from_reuse(r, s1, h1, s2, h2, n=N):
    """Same nonce, same key. Returns (k, d)."""
    assert (s1 - s2) % n, "identical s values carry no information"
    k = (h1 - h2) * pow(s1 - s2, -1, n) % n
    d = (s1 * k - h1) * pow(r, -1, n) % n
    return k, d

def recover_linear_nonces(sig1, h1, sig2, h2, a, b, n=N):
    """k2 = a*k1 + b with a, b known. Returns (k1, d) or None."""
    (r1, s1), (r2, s2) = sig1, sig2
    num = (a * s2 * h1 - s1 * h2 + s1 * s2 * b) % n
    den = (s1 * r2 - a * s2 * r1) % n
    if den == 0:
        return None
    d = num * pow(den, -1, n) % n
    k1 = pow(s1, -1, n) * (h1 + r1 * d) % n
    return k1, d

if __name__ == "__main__":
    rng = random.Random(1234)
    d = rng.randrange(1, N)
    Q = ec_mul(d, G)

    # --- 1. the classic: one nonce, two messages ---
    k = rng.randrange(1, N)
    m1, m2 = b"transfer 1 btc to alice", b"transfer 1000 btc to mallory"
    sig1, sig2 = sign(d, m1, k), sign(d, m2, k)
    assert verify(Q, m1, sig1) and verify(Q, m2, sig2)
    assert sig1[0] == sig2[0], "same k means same r"

    pairs = find_repeated_r([(m1,) + sig1, (m2,) + sig2])
    assert pairs == [(0, 1)]
    k_rec, d_rec = recover_from_reuse(sig1[0], sig1[1], h_of(m1), sig2[1], h_of(m2))
    assert (k_rec, d_rec) == (k, d)
    assert ec_mul(d_rec, G) == Q
    print("[ok] nonce reuse: private key recovered from 2 signatures")

    # forge a signature for a message that was never signed
    forged = sign(d_rec, b"give mallory everything", rng.randrange(1, N))
    assert verify(Q, b"give mallory everything", forged)
    print("[ok] forged a valid signature with the recovered key")

    # --- 2. the collector sees (r, -s) instead of (r, s) ---
    sig2_neg = (sig2[0], (-sig2[1]) % N)
    k2, d2 = recover_from_reuse(sig1[0], sig1[1], h_of(m1), sig2_neg[1], h_of(m2))
    if ec_mul(d2, G) != Q:
        k2, d2 = recover_from_reuse(sig1[0], sig1[1], h_of(m1), sig2[1], h_of(m2))
    assert ec_mul(d2, G) == Q
    print("[ok] handled the malleated (r, -s) form")

    # --- 3. related nonces: k2 = a*k1 + b, r values differ ---
    a_rel, b_rel = 3, 7
    k1 = rng.randrange(1, N)
    k2v = (a_rel * k1 + b_rel) % N
    m3, m4 = b"first", b"second"
    s3, s4 = sign(d, m3, k1), sign(d, m4, k2v)
    assert s3[0] != s4[0], "different nonces, different r"
    got = recover_linear_nonces(s3, h_of(m3), s4, h_of(m4), a_rel, b_rel)
    assert got is not None and got == (k1, d)
    print("[ok] related nonces k2 = 3*k1 + 7: key recovered although r differs")

    # --- 4. counter nonces k, k+1, k+2, ... found by search over the offset ---
    kbase = rng.randrange(1, N)
    sa, sb = sign(d, b"msg a", kbase), sign(d, b"msg b", kbase + 5)
    offset = next(o for o in range(1, 16)
                  if (recover_linear_nonces(sa, h_of(b"msg a"), sb, h_of(b"msg b"), 1, o)
                      or (None, None))[1] == d)
    assert offset == 5
    print(f"[ok] brute-forced the nonce offset: k2 = k1 + {offset}")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Hash truncation.** `h` must be the hash truncated to `n.bit_length()` bits *before*
  reduction, and for secp256k1 that is the full 256 bits. Get this wrong and every formula
  produces a plausible but wrong `d`. If recovery fails, print `h` and compare with the
  challenge's own hashing.
- **DSA is identical.** Replace `r = x(kG) mod n` with `r = (g^k mod p) mod q`; the algebra
  is unchanged.
- **Same `k`, two different keys.** Under-determined on its own. You need one of the keys, or
  a third signature that ties them (e.g. both keys signing a shared message with the same `k`).
- **Bitcoin / Ethereum.** Historical Android `SecureRandom` failures produced real repeated
  `r` on-chain. To scan a dump: group by `r`, then filter for distinct `(s, h)`.
- **`s1 == s2` as well.** Then the two "signatures" are the same signature of the same hash;
  no information. Check `h1 != h2`.
- **Deterministic ECDSA (RFC 6979) is not vulnerable** to this, because `k = HMAC(d, h)`
  depends on the message. But a *broken* RFC 6979 that forgets the message is maximally
  vulnerable: every signature shares one `k`.
- **Recovery gives `k` too.** That is often the actual flag material in challenges that print
  `flag = long_to_bytes(k)`.

## Tools

```sh
# scan a JSON list of {"h":..,"r":..,"s":..} for duplicate r
python3 -c '
import json,sys,collections
sigs=json.load(open(sys.argv[1]))
g=collections.defaultdict(list)
for x in sigs: g[x["r"]].append(x)
print([r for r,v in g.items() if len(v)>1])' sigs.json
```

```python
# SageMath: the same recovery, two lines
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
k = (h1 - h2) * inverse_mod(s1 - s2, n) % n
d = (s1 * k - h1) * inverse_mod(r, n) % n
```

## References

- https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security
- https://datatracker.ietf.org/doc/html/rfc6979 (deterministic nonces)
- fail0verflow, "Console Hacking 2010" (27C3) -- the PS3 static-`k` break
- https://en.bitcoin.it/wiki/BIP_0062 (signature malleability context)
