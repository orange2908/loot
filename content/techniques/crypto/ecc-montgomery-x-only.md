---
title: "ECC - Point Compression, x-Only Ladders and Curve25519 Pitfalls"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, point-compression, sec1, montgomery-ladder, x-only, curve25519, x25519, ed25519, rfc7748, clamping, cofactor, low-order-point, contributory-behaviour, birational-map, twist, tonelli-shanks, python, sage]
difficulty: medium
summary: "How compressed points decompress, how the Montgomery ladder works, and the six Curve25519 details CTFs actually target: clamping, cofactor 8, low-order u, sign loss."
when_to_use:
  - "A challenge transmits 32 bytes of x (or 33 bytes with a 02/03 prefix) and no y"
  - "You need to recover y from x, or you are missing the sign bit"
  - "X25519 / Curve25519 / Ed25519 appears in the source"
  - "An implementation accepts an attacker-chosen u-coordinate without checking it"
tools: [python, sage, pynacl]
related: [ecc-twist-attack, ecc-invalid-curve, ecc-recover-curve-params, ecc-cheatsheet, ecc-toolkit]
---

## TL;DR

A point is determined by `x` plus one sign bit, because `y^2 = f(x)` has two roots.
Compression ships `x` plus that bit (SEC1 `02`/`03`); x-only protocols drop the bit entirely
and use a ladder that never computes `y`. Everything a CTF attacks lives in the consequences:
you cannot tell `P` from `-P`, every `x` is on the curve *or* its twist, and Curve25519 has a
cofactor of 8 with a published list of low-order `u` values.

## Recognise it

- 33-byte pubkeys starting with `02` or `03` (compressed), 65 bytes starting with `04`
  (uncompressed), 32 bytes with no prefix (x-only / X25519).
- `a24`, `cswap`, `x2, z2, x3, z3` in the source: that is a Montgomery ladder.
- `p = 2**255 - 19`, `A = 486662`, basepoint `u = 9`.
- The code clamps: `k[0] &= 248; k[31] &= 127; k[31] |= 64`.
- A shared secret is used without checking it is not all-zero.

## Theory

**Compression.** For `y^2 = x^3 + a x + b` over `GF(p)`, compute `y = sqrt(f(x))`. When
`p = 3 (mod 4)` that is one exponentiation, `y = f(x)^((p+1)/4)`; otherwise use
Tonelli-Shanks. Both roots `y` and `p - y` have different parities (since `p` is odd), so one
bit selects. SEC1 encodes the prefix `0x02` for even `y`, `0x03` for odd `y`.
If `f(x)` is a non-residue, the `x` is simply not on the curve -- it is on the twist.

**Montgomery form and the ladder.** `B y^2 = x^3 + A x^2 + x`. In projective `(X : Z)` with
`a24 = (A + 2)/4`:

$$\text{xDBL}:\; X_2 = (X+Z)^2 (X-Z)^2, \quad Z_2 = 4XZ\big((X-Z)^2 + a_{24}\cdot 4XZ\big)$$

$$\text{xADD}:\; X_{P+Q} = Z_{P-Q}\big((X_P - Z_P)(X_Q + Z_Q) + (X_P + Z_P)(X_Q - Z_Q)\big)^2$$

The ladder keeps `(R0, R1)` with `R1 - R0 = P` fixed, so `xADD` always knows the difference.
Constant time, no branches, no `y`, no `B`. Exactly what makes twist attacks possible.

**Curve25519 specifics.**

| item | value | why it matters |
| --- | --- | --- |
| `p` | `2^255 - 19` | `p = 5 (mod 8)`, so square roots need the `2^((p-1)/4)` trick |
| `A` | 486662 | ladder constant `a24 = 121665` |
| `#E` | `8 * l`, `l = 2^252 + 27742317777372353535851937790883648493` | cofactor 8 |
| `#E'` (twist) | `4 * l'`, `l'` prime `~2^253` | twist-secure: twist attack dead |
| clamping | clear bits 0,1,2; clear bit 255; set bit 254 | forces `k = 8*m` in a fixed range |
| basepoint | `u = 9` | order `l` |

Clamping does two things: the multiple of 8 kills any order-8 component of a hostile input,
and the fixed top bit makes the ladder run a constant number of steps.

**Low-order `u` values.** These are the `u` for which `8 * P = O`; feeding one makes the
shared secret all-zero (or a fixed constant) regardless of the private key:

```
0
1
325606250916557431795983626356110631294008115727848805560023387167927233504
39382357235489614581723060781553021112529911719440698176882885853963445705823
2^255 - 20   (= p - 1)
2^255 - 19   (= p,   reduces to 0)
2^255 - 18   (= p+1, reduces to 1)
```

RFC 7748 says X25519 implementations MAY check for an all-zero output; if the protocol needs
*contributory behaviour* (both parties influence the key) it MUST. CTF challenges love the
version that does not check.

**Sign loss.** x-only gives `x(kP) = x(-kP)`, so you never learn the sign of the scalar or of
the point. Any protocol that relies on the `y` parity (say, Ed25519 verification rebuilt on
top of X25519 primitives) breaks here.

## Attack surface checklist

1. Is the `u`/`x` validated at all? -> invalid-curve / twist attack.
2. Is the twist order smooth? -> twist attack (`ecc-twist-attack`).
3. Is the shared secret checked for all-zero? -> low-order point forces a known key.
4. Is the cofactor cleared? -> unclamped scalars leak `d mod 8`.
5. Is the sign bit dropped somewhere it mattered? -> signature or KDF confusion.
6. Does an Ed25519 verifier accept non-canonical or small-order `A`/`R`? -> malleable
   signatures, "everything verifies" attacks.

## Code

```python
#!/usr/bin/env python3
"""Point compression, a generic Montgomery ladder, and X25519 with RFC 7748 vectors."""

# ---- SEC1 point compression over a short Weierstrass curve --------------

SECP256K1 = dict(
    p=2**256 - 2**32 - 977, a=0, b=7,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

def sqrt_mod(n, p):
    """Square root mod p (p = 3 mod 4 fast path, Tonelli-Shanks otherwise)."""
    n %= p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % p, i + 1
        bb = pow(c, 1 << (m - i - 1), p)
        m, c = i, bb * bb % p
        t, r = t * c % p, r * bb % p
    return r

def compress(x, y, size=32):
    """SEC1 compressed encoding: 02||x for even y, 03||x for odd y."""
    return bytes([2 + (y & 1)]) + x.to_bytes(size, "big")

def decompress(blob, p, a, b):
    """Inverse of compress(). Returns (x, y) or None if x is not on the curve."""
    prefix, xb = blob[0], blob[1:]
    assert prefix in (2, 3), "not a compressed point"
    x = int.from_bytes(xb, "big")
    y = sqrt_mod((x * x * x + a * x + b) % p, p)
    if y is None:
        return None                       # x lies on the quadratic twist
    if y & 1 != prefix & 1:
        y = p - y
    return (x, y)

# ---- generic Montgomery ladder ------------------------------------------

def ladder(k, x, a24, p):
    """x(k*P) as projective (X : Z); Z == 0 is the point at infinity."""
    if k == 0:
        return (1, 0)
    X0, Z0, X1, Z1 = 1, 0, x % p, 1
    for bit in bin(k)[2:]:
        A0 = (X0 + Z0) % p
        S0 = (X0 - Z0) % p
        A1 = (X1 + Z1) % p
        S1 = (X1 - Z1) % p
        if bit == "0":
            t0, t1 = S1 * A0 % p, A1 * S0 % p
            X1, Z1 = pow(t0 + t1, 2, p), x * pow(t0 - t1, 2, p) % p
            aa, bb = A0 * A0 % p, S0 * S0 % p
            e = (aa - bb) % p
            X0, Z0 = aa * bb % p, e * (bb + a24 * e) % p
        else:
            t0, t1 = S0 * A1 % p, A0 * S1 % p
            X0, Z0 = pow(t0 + t1, 2, p), x * pow(t0 - t1, 2, p) % p
            aa, bb = A1 * A1 % p, S1 * S1 % p
            e = (aa - bb) % p
            X1, Z1 = aa * bb % p, e * (bb + a24 * e) % p
    return X0, Z0

def x_affine(XZ, p):
    X, Z = XZ
    return None if Z % p == 0 else X * pow(Z, -1, p) % p

# ---- X25519 (RFC 7748) --------------------------------------------------

P25519 = 2**255 - 19
A24_25519 = 121665

def clamp(k_bytes):
    b = bytearray(k_bytes)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")

def x25519(k_bytes, u_bytes):
    k = clamp(k_bytes)
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        if swap ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P25519
        aa = a * a % P25519
        b = (x2 - z2) % P25519
        bb = b * b % P25519
        e = (aa - bb) % P25519
        c = (x3 + z3) % P25519
        d = (x3 - z3) % P25519
        da, cb = d * a % P25519, c * b % P25519
        x3 = pow(da + cb, 2, P25519)
        z3 = x1 * pow(da - cb, 2, P25519) % P25519
        x2 = aa * bb % P25519
        z2 = e * (aa + A24_25519 * e) % P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, "little")

LOW_ORDER_U = [
    0,
    1,
    325606250916557431795983626356110631294008115727848805560023387167927233504,
    39382357235489614581723060781553021112529911719440698176882885853963445705823,
    P25519 - 1,
    P25519,
    P25519 + 1,
]

def montgomery_to_weierstrass(A, B, p):
    """B*y^2 = x^3 + A*x^2 + x  ->  v^2 = u^3 + a*u + b with u = (x + A/3)/B, v = y/B.

    a = (3 - A^2) / (3*B^2),  b = (2*A^3 - 9*A) / (27*B^3)
    """
    a = (3 - A * A) % p * pow(3 * B * B % p, -1, p) % p
    b = (2 * pow(A, 3, p) - 9 * A) % p * pow(27 * pow(B, 3, p) % p, -1, p) % p
    return a, b

if __name__ == "__main__":
    # --- compression round-trip on secp256k1 ---
    C = SECP256K1
    blob = compress(C["Gx"], C["Gy"])
    assert blob.hex().startswith("02") or blob.hex().startswith("03")
    assert decompress(blob, C["p"], C["a"], C["b"]) == (C["Gx"], C["Gy"])
    flipped = bytes([blob[0] ^ 1]) + blob[1:]
    x, y = decompress(flipped, C["p"], C["a"], C["b"])
    assert (x, y) == (C["Gx"], C["p"] - C["Gy"])
    print("[ok] SEC1 compress/decompress, and the flipped prefix gives -G")

    # an x that is NOT on the curve decompresses to None (it is on the twist)
    off = next(v for v in range(2, 50)
               if pow((v ** 3 + 7) % C["p"], (C["p"] - 1) // 2, C["p"]) != 1)
    assert decompress(bytes([2]) + off.to_bytes(32, "big"), C["p"], C["a"], C["b"]) is None
    print(f"[ok] x = {off} is on the twist, decompression correctly refuses it")

    # --- RFC 7748 X25519 test vectors ---
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert x25519(k, u).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    k2 = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    u2 = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    assert x25519(k2, u2).hex() == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
    print("[ok] RFC 7748 section 5.2 scalar-multiplication vectors")

    # --- RFC 7748 Diffie-Hellman vector ---
    nine = (9).to_bytes(32, "little")
    apriv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bpriv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    apub, bpub = x25519(apriv, nine), x25519(bpriv, nine)
    assert apub.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert bpub.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519(apriv, bpub).hex() == shared == x25519(bpriv, apub).hex()
    print("[ok] RFC 7748 section 6.1 Diffie-Hellman vector")

    # --- low-order u values force an all-zero shared secret ---
    a24 = (486662 + 2) * pow(4, -1, P25519) % P25519
    for uu in LOW_ORDER_U:
        assert ladder(8, uu % P25519, a24, P25519)[1] % P25519 == 0, uu
        assert x25519(apriv, (uu % P25519).to_bytes(32, "little")) == bytes(32)
    print(f"[ok] all {len(LOW_ORDER_U)} published low-order u values give a zero secret")

    # --- Montgomery -> short Weierstrass keeps the x-line consistent ---
    aW, bW = montgomery_to_weierstrass(486662, 1, P25519)
    x9 = 9
    uW = (x9 + 486662 * pow(3, -1, P25519)) % P25519
    lhs = (uW ** 3 + aW * uW + bW) % P25519
    rhs = (x9 ** 3 + 486662 * x9 * x9 + x9) % P25519
    assert lhs == rhs
    print("[ok] Montgomery-to-Weierstrass conversion preserves the curve equation")
    print("all self-tests passed")
```

## Variants and pitfalls

- **`p = 5 (mod 8)`** (Curve25519's prime). `sqrt_mod` above falls into Tonelli-Shanks,
  which is correct but slower; the closed form is
  `y = n^((p+3)/8)`, multiplied by `sqrt(-1) = 2^((p-1)/4)` when `y^2 != n`.
- **Non-canonical encodings.** X25519 masks the top bit, so `u` and `u + 2^255` are the same
  point. Ed25519 verifiers that do *not* reject non-canonical `A`/`R` accept multiple
  encodings of one signature -- a classic consensus/malleability bug.
- **Cofactor 8 in Ed25519 verification.** `[8]R == [8](S*B - h*A)` (cofactored) and
  `R == S*B - h*A` (cofactorless) disagree on small-order components. CTFs exploit this to
  craft a signature valid under one verifier and not the other.
- **Birational map Ed25519 <-> Curve25519.** `u = (1 + y)/(1 - y)`, `y = (u - 1)/(u + 1)`.
  If a challenge mixes an Ed25519 public key into an X25519 exchange, convert rather than
  assume they are unrelated.
- **The all-zero check.** `if shared == b"\x00" * 32: abort`. Missing it means an attacker who
  sends a low-order `u` fixes the session key to a constant *without knowing any secret*.
- **Never invert `Z` without checking it.** `pow(0, -1, p)` raises; in C it silently returns
  garbage and leaks.
- **Compressed points in a challenge's "database".** If you only have `x`, remember you also
  only have `+/-P`; a signature check or a KDF that hashes `y` will need both tries.

## Tools

```python
# SageMath: decompress and inspect
E = EllipticCurve(GF(p), [a, b])
P = E.lift_x(x, all=True)           # both sign choices
print([Q.xy() for Q in P])
```

```sh
# pynacl for a reference X25519 to diff against your implementation
python3 -c "
from nacl.bindings import crypto_scalarmult
print(crypto_scalarmult(bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
                        bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')).hex())"
```

## References

- https://datatracker.ietf.org/doc/html/rfc7748
- https://datatracker.ietf.org/doc/html/rfc8032 (Ed25519)
- https://www.secg.org/sec1-v2.pdf (point compression, section 2.3.3)
- https://safecurves.cr.yp.to/
- https://eprint.iacr.org/2020/1244 (Ed25519 verification variants)
