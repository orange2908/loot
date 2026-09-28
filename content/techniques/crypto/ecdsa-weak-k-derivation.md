---
title: "ECDSA - Weak Nonce Derivation, Broken RFC 6979 and Signing Faults"
category: crypto
subcategory: ecdsa
type: technique
tags: [ecdsa, weak-prng, lcg, mersenne-twister, mt19937, seeded-random, rfc6979, deterministic-nonce, hmac, fault-attack, differential-fault, invalid-curve, key-recovery, brute-force, nonce, python, sage]
difficulty: medium
summary: "Where k comes from is the whole game: a small range, a seeded PRNG, an LCG recurrence, a message-less RFC 6979, or one faulted signature all give up the key."
when_to_use:
  - "The signer calls random.seed(), time(), or getrandbits with too few bits"
  - "Nonces follow a recurrence (LCG, counter, hash chain) with known constants"
  - "Deterministic signatures repeat r across different messages"
  - "You can glitch, replay or re-request a signature and get a second, inconsistent one"
tools: [python, sage, randcrack]
related: [ecdsa-nonce-reuse, ecdsa-biased-nonce-lll, lattice-linear-relations, dlp-bsgs-pollard-rho, ecc-toolkit]
---

## TL;DR

Recovering `d` needs `k`. Every shortcut a lazy signer takes to produce `k` is an attack:
a small range (brute force it), a seeded PRNG (brute force the seed), a recurrence
`k_{i+1} = a k_i + c` (solve the 2x2 system), an RFC 6979 implementation that forgets the
message (constant `k` -> nonce reuse), or a fault that makes the device sign the same `k`
twice with different data.

## Recognise it

- `random.seed(int(time.time()))`, `random.seed(0)`, `random.seed(len(msg))`.
- `k = getrandbits(32)`, `k = int(time.time())`, `k = os.getpid()`.
- A `LCG`/`next_state` class in the source that also feeds the signer.
- `k = hmac_sha256(privkey, b"")` -- RFC 6979 minus the message.
- Two signatures of *different* messages sharing `r` (that is nonce reuse, see the sibling file).
- A hardware/oracle challenge that lets you ask for the same signature twice and returns
  different `s` for the same `r`.

## Theory

**Small range.** If `k < B` you can search: for each candidate compute `R = kG` incrementally
(one point addition per step) and compare `x(R) mod n` with `r`. `B = 2^24` is a couple of
minutes in Python, `2^32` needs C or a baby-step/giant-step over `kG`.

**Seeded PRNG.** `random.seed(s)` makes `k` a deterministic function of `s`. If `s` is a
timestamp, a PID, or a small integer, enumerate it. Python's Mersenne Twister also allows
*state recovery* from 624 consecutive 32-bit outputs -- if the same generator produced other
values you can observe, recover the state and predict `k` directly.

**Recurrence.** Suppose `k_2 = a k_1 + c (mod n)` with known `a, c` (an LCG whose modulus is
`n`, or a counter with `a = 1`). From the two signing equations

$$s_1 k_1 = h_1 + r_1 d, \qquad s_2 (a k_1 + c) = h_2 + r_2 d$$

eliminate `k_1`:

$$d = \frac{a s_2 h_1 - s_1 h_2 + s_1 s_2 c}{s_1 r_2 - a s_2 r_1} \pmod n$$

If the LCG modulus `m` differs from `n`, the relation holds only modulo `m`; either brute
force the wrap-around term `t` in `k_2 = a k_1 + c - t m` (feasible when `a` is small) or
treat the short nonces as an HNP instance and use a lattice.

**RFC 6979 done wrong.** The specification derives `k = HMAC_DRBG(d, h(m))`: it depends on
both the key and the message. Implementations that hash only the key produce one `k` for
every message -- maximal nonce reuse. Implementations that forget to reduce the hash, or that
seed the DRBG with a truncated key, produce biased `k` -- feed it to the lattice attack.

**Signing faults.** The classical differential fault attack: obtain `(r, s)` correctly, then
induce a fault so the device signs the *same* `k` against a corrupted hash `h'`, giving
`(r, s')`. Same `r`, two equations, key recovered -- exactly the nonce-reuse formula. Faults
in the scalar multiplication itself push `kG` onto a different curve; then `r` is the
x-coordinate of a point of an invalid curve, and if that curve has smooth order you recover
`k mod small primes` (see `ecc-invalid-curve`).

## Attack

1. Read the source and find where `k` comes from. That is 90% of the work.
2. Small range -> incremental search over `kG`.
3. Seeded PRNG -> enumerate seeds in a plausible window, derive `k`, test `d G == Q`.
4. Recurrence -> two signatures and the closed form above.
5. Constant `k` -> nonce reuse.
6. Biased `k` -> lattice/HNP (`ecdsa-biased-nonce-lll`).
7. Always finish with `d*G == Q`.

## Code

```python
#!/usr/bin/env python3
"""Five ways a weak nonce gives up an ECDSA private key."""
import hashlib
import hmac
import random

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
    R, S, k = None, A, k % N
    while k:
        if k & 1:
            R = ec_add(R, S)
        S, k = ec_add(S, S), k >> 1
    return R

def h_of(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

def sign_with(d, h, k):
    r = ec_mul(k, G)[0] % N
    return r, pow(k, -1, N) * (h + r * d) % N

def d_from_k(r, s, h, k):
    return (s * k - h) * pow(r, -1, N) % N

# ---- 1. k drawn from a small range --------------------------------------

def attack_small_k(r, s, h, limit):
    """Walk k = 1, 2, 3, ... with one point addition per step."""
    R = None
    for k in range(1, limit + 1):
        R = ec_add(R, G)
        if R[0] % N == r:
            return k, d_from_k(r, s, h, k)
    return None

# ---- 2. k from a seeded Mersenne Twister --------------------------------

def attack_seed(r, s, h, pub, seeds):
    """Enumerate plausible seeds; each one determines k completely."""
    for seed in seeds:
        rng = random.Random(seed)
        k = rng.randrange(1, N)
        d = d_from_k(r, s, h, k)
        if ec_mul(d, G) == pub:
            return seed, k, d
    return None

# ---- 3. k from a recurrence k2 = a*k1 + c (mod n) -----------------------

def attack_recurrence(sig1, h1, sig2, h2, a, c):
    (r1, s1), (r2, s2) = sig1, sig2
    den = (s1 * r2 - a * s2 * r1) % N
    if den == 0:
        return None
    num = (a * s2 * h1 - s1 * h2 + s1 * s2 * c) % N
    d = num * pow(den, -1, N) % N
    k1 = pow(s1, -1, N) * (h1 + r1 * d) % N
    return k1, d

# ---- 4. RFC 6979 with and without the message ---------------------------

def rfc6979_k(d, h, extra=b"", with_message=True):
    """HMAC-DRBG nonce. with_message=False models the classic broken port."""
    x = d.to_bytes(32, "big")
    m = h.to_bytes(32, "big") if with_message else b"\x00" * 32
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + m + extra, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + m + extra, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 0 < k < N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()

def attack_nonce_reuse(r, s1, h1, s2, h2):
    k = (h1 - h2) * pow(s1 - s2, -1, N) % N
    return k, d_from_k(r, s1, h1, k)

if __name__ == "__main__":
    rng = random.Random(77)
    d = rng.randrange(1, N)
    Q = ec_mul(d, G)

    # --- 1. small-range nonce ---
    k_small = rng.randrange(2, 1 << 16)
    h1 = h_of(b"small nonce")
    sig = sign_with(d, h1, k_small)
    got = attack_small_k(sig[0], sig[1], h1, 1 << 16)
    assert got is not None and got == (k_small, d)
    print(f"[ok] k < 2^16 brute-forced in {k_small} point additions")

    # --- 2. seeded PRNG: seed is a timestamp inside a known window ---
    base = 1700000000
    seed = base + rng.randrange(0, 1500)
    k_seeded = random.Random(seed).randrange(1, N)
    h2 = h_of(b"seeded prng")
    sig2 = sign_with(d, h2, k_seeded)
    found = attack_seed(sig2[0], sig2[1], h2, Q, range(base, base + 1500))
    assert found is not None and found[0] == seed and found[2] == d
    print(f"[ok] random.seed(timestamp) recovered: seed = {seed}")

    # --- 3. LCG recurrence modulo n ---
    a_l, c_l = 6364136223846793005, 1442695040888963407
    k_a = rng.randrange(1, N)
    k_b = (a_l * k_a + c_l) % N
    ha, hb = h_of(b"lcg first"), h_of(b"lcg second")
    sa, sb = sign_with(d, ha, k_a), sign_with(d, hb, k_b)
    assert sa[0] != sb[0], "different nonces, so r differs and reuse detection fails"
    res = attack_recurrence(sa, ha, sb, hb, a_l, c_l)
    assert res is not None and res == (k_a, d)
    print("[ok] LCG-derived nonces: key recovered from 2 signatures, no repeated r")

    # --- 4. RFC 6979: correct vs message-less ---
    hx, hy = h_of(b"alpha"), h_of(b"beta")
    good = (sign_with(d, hx, rfc6979_k(d, hx)), sign_with(d, hy, rfc6979_k(d, hy)))
    assert good[0][0] != good[1][0], "proper RFC 6979 gives distinct r per message"
    bad_k = rfc6979_k(d, hx, with_message=False)
    assert bad_k == rfc6979_k(d, hy, with_message=False), "message-less: one k forever"
    b1, b2 = sign_with(d, hx, bad_k), sign_with(d, hy, bad_k)
    assert b1[0] == b2[0]
    k_rec, d_rec = attack_nonce_reuse(b1[0], b1[1], hx, b2[1], hy)
    assert (k_rec, d_rec) == (bad_k, d)
    print("[ok] RFC 6979 without the message collapses to nonce reuse")

    # --- 5. signing fault: same k, corrupted hash ---
    k_f = rng.randrange(1, N)
    h_ok = h_of(b"transfer 1 coin")
    h_fault = h_ok ^ (1 << 17)                    # one flipped bit in the hash register
    f1, f2 = sign_with(d, h_ok, k_f), sign_with(d, h_fault, k_f)
    assert f1[0] == f2[0], "the fault did not touch k, so r is unchanged"
    k_rec, d_rec = attack_nonce_reuse(f1[0], f1[1], h_ok, f2[1], h_fault)
    assert (k_rec, d_rec) == (k_f, d)
    print("[ok] single-bit hash fault during signing leaks the key")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Mersenne Twister state recovery.** If the same `random.Random` also produced values you
  can see (tokens, IDs, "random" padding), collect 624 consecutive 32-bit outputs and use
  `randcrack` to clone the generator, then predict `k` exactly. Note `randrange(1, N)`
  consumes several 32-bit words, so account for the consumption pattern.
- **`getrandbits(t)` with `t < log2(n)`.** That is a bias, not a brute force: go to the
  lattice attack, it needs only `log2(n)/(log2(n)-t) + 2` signatures.
- **LCG modulus != group order.** The closed form above assumes the recurrence holds mod `n`.
  If the LCG is mod `2^64` and `k = state`, the nonces are 64-bit: treat it as HNP.
  If the LCG is mod `2^64` and `k = state * something mod n`, expand the wrap term.
- **Counters.** `k = base + i` is `a = 1, c = i2 - i1`; try small offsets exhaustively.
- **Hash-chain nonces.** `k_{i+1} = H(k_i)` gives no algebraic relation. You need the first
  `k` (brute force the seed) or a bias.
- **Two signatures are not always enough.** If `a` and `c` are unknown too, you have four
  unknowns; use three or four signatures and solve the resulting system, or lattice it.
- **Verify, always.** Each of these attacks produces a plausible 256-bit integer even when
  wrong. `d*G == Q` is the only proof.

## Tools

```sh
# clone a Python Mersenne Twister from 624 observed 32-bit outputs
pip install randcrack
python3 -c "
from randcrack import RandCrack
rc = RandCrack()
for v in observed_624_values: rc.submit(v)
print(rc.predict_getrandbits(32))"
```

```python
# SageMath: solve the 2-signature recurrence symbolically if you forget the formula
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
R = Zmod(n); var('k1 dd')
sol = solve([s1*k1 == h1 + r1*dd, s2*(a*k1 + c) == h2 + r2*dd], k1, dd)
print(sol)
```

## References

- https://datatracker.ietf.org/doc/html/rfc6979
- https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
- https://github.com/tna0y/Python-random-module-cracker (randcrack)
- Naccache, Nguyen, Tunstall, Whelan, "Experimenting with Faults, Lattices and the DSA" (PKC 2005)
