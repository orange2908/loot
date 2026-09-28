---
title: "ECC - Formulas, Sage Recipes and the Attack Decision Table"
category: crypto
subcategory: ecc
type: cheatsheet
tags: [ecc, elliptic-curve, ecdlp, ecdsa, weierstrass, montgomery, edwards, point-addition, point-doubling, order, cofactor, discriminant, j-invariant, embedding-degree, anomalous, supersingular, singular-curve, twist, pohlig-hellman, smart-attack]
summary: "Point arithmetic in every curve form, order/cofactor checks, Sage and PARI one-liners, a decision table keyed on curve properties, and named-curve constants."
tools: [sage, pari, python, ecdsa, pycryptodome]
related: [ecc-recover-curve-params, ecc-singular-curve, ecc-smart-anomalous, ecc-mov-pairing, ecc-invalid-curve, ecc-pohlig-hellman, ecc-twist-attack, ecc-montgomery-x-only, ecc-toolkit, sagemath-cheatsheet]
---

## Which ECC attack applies (decision table)

Compute these five numbers first: `p`, `#E`, `factor(#E)`, `ord(P)`, `disc = 4a^3 + 27b^2 mod p`.

| Condition | Attack | Cost | File |
|---|---|---|---|
| `disc == 0` | singular curve: cusp -> `(GF(p),+)`, node -> `GF(p)^*` | trivial / Pohlig-Hellman | `ecc-singular-curve` |
| `#E == p` (trace 1) | Smart's attack (p-adic formal log) | `O(log p)` | `ecc-smart-anomalous` |
| `#E == p + 1` (trace 0, supersingular) | MOV / Frey-Ruck, `k <= 6` | field DLP | `ecc-mov-pairing` |
| `ord(p) mod ord(P)` small (`k <= 12`) | MOV / Frey-Ruck | `L[1/3]` in `GF(p^k)` | `ecc-mov-pairing` |
| `factor(ord(P))` all small | Pohlig-Hellman | `sum e_i sqrt(q_i)` | `ecc-pohlig-hellman` |
| `ord(P)` partly smooth | partial Pohlig-Hellman + kangaroo | mixed | `ecc-pohlig-hellman` |
| peer point never validated, static key | invalid-curve / small-subgroup | `sum q_i` queries | `ecc-invalid-curve` |
| x-only API, `2p + 2 - #E` smooth | twist attack | `sum q_i` queries | `ecc-twist-attack` |
| cofactor `h` large, no cofactor clearing | small-subgroup, learn `d mod h` | trivial | `ecc-invalid-curve` |
| `p` composite | CRT the ECDLP per prime factor | depends | `ecc-recover-curve-params` |
| nonce reuse in ECDSA (same `r`) | linear system | `O(1)` | `ecdsa-nonce-reuse` |
| short/biased ECDSA nonces | HNP + LLL | one LLL | `ecdsa-biased-nonce-lll` |
| none of the above, `ord(P)` a 256-bit prime | not the intended solve; re-read the challenge | - | - |

```python
# SageMath: the five-number triage
E = EllipticCurve(GF(p), [a, b]); P = E.gens()[0]
n = E.order(); print(p.nbits(), n, factor(n), P.order(), E.discriminant())
print("anomalous:", n == p, "supersingular:", E.is_supersingular())
print("embedding degree:", Mod(p, P.order()).multiplicative_order())
print("twist order:", factor(2*p + 2 - n))
```

## Curve forms and conversions

```text
# short Weierstrass
y^2 = x^3 + a*x + b                         over GF(p), p > 3
# Montgomery
B*y^2 = x^3 + A*x^2 + x                     ladder-friendly, x-only
# twisted Edwards
a*x^2 + y^2 = 1 + d*x^2*y^2                 complete addition law, no exceptions
```

```python
# Montgomery (A, B) -> short Weierstrass (a, b), with u = (x + A/3)/B
a = (3 - A**2) * pow(3 * B * B, -1, p) % p
b = (2 * A**3 - 9 * A) * pow(27 * pow(B, 3, p), -1, p) % p
```

```python
# Montgomery <-> twisted Edwards (birational)
# u = (1 + y)/(1 - y),  v = u/x        ;   y = (u - 1)/(u + 1),  x = u/v
A = 2 * (a_ed + d_ed) * pow(a_ed - d_ed, -1, p) % p
B = 4 * pow(a_ed - d_ed, -1, p) % p
```

```python
# Weierstrass with a1..a6 (general form) -> short form, char != 2, 3
b2 = a1*a1 + 4*a2; b4 = 2*a4 + a1*a3; b6 = a3*a3 + 4*a6
c4 = b2*b2 - 24*b4; c6 = -b2**3 + 36*b2*b4 - 216*b6
a_short = -27 * c4 % p; b_short = -54 * c6 % p
```

## Point arithmetic (short Weierstrass, affine)

```text
# doubling: P = (x1, y1), P != -P
lambda = (3*x1^2 + a) / (2*y1)
x3 = lambda^2 - 2*x1 ;  y3 = lambda*(x1 - x3) - y1
# addition: P != +/-Q
lambda = (y2 - y1) / (x2 - x1)
x3 = lambda^2 - x1 - x2 ;  y3 = lambda*(x1 - x3) - y1
# negation:  -(x, y) = (x, -y)       # identity: the point at infinity
```

```python
# minimal, correct group law over GF(p); None is the point at infinity
def add(p, a, P, Q):
    if P is None: return Q
    if Q is None: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    lam = ((3*x1*x1 + a) * pow(2*y1 % p, -1, p) if P == Q
           else (y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
    x3 = (lam*lam - x1 - x2) % p
    return (x3, (lam*(x1 - x3) - y1) % p)

def mul(p, a, k, P):
    R, S = None, P
    while k:
        if k & 1: R = add(p, a, R, S)
        S, k = add(p, a, S, S), k >> 1
    return R
```

```text
# Jacobian coordinates (X : Y : Z) with x = X/Z^2, y = Y/Z^3 -- no inversions in the loop
# doubling: S = 4*X*Y^2 ; M = 3*X^2 + a*Z^4
#   X' = M^2 - 2S ; Y' = M*(S - X') - 8*Y^4 ; Z' = 2*Y*Z
```

```text
# Montgomery ladder, a24 = (A + 2)/4, projective (X : Z), Z == 0 is infinity
# xDBL: X2 = (X+Z)^2 (X-Z)^2 ;  Z2 = 4XZ((X-Z)^2 + a24*4XZ)
# xADD: X3 = Z1((X-Z)(X'+Z') + (X+Z)(X'-Z'))^2 ;  Z3 = X1(... - ...)^2
```

```text
# twisted Edwards addition -- complete, no special cases
# x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
# y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
```

## Order, cofactor and validity checks

```python
# is the point on the curve?
(y*y - x*x*x - a*x - b) % p == 0
# discriminant (0 means singular, i.e. not a curve)
disc = (-16 * (4*pow(a, 3, p) + 27*b*b)) % p
# j-invariant
j = 1728 * (4*pow(a, 3, p)) % p * pow((4*pow(a, 3, p) + 27*b*b) % p, -1, p) % p
# Hasse interval: |#E - (p + 1)| <= 2*sqrt(p)
lo, hi = p + 1 - 2*isqrt(p), p + 1 + 2*isqrt(p)
# twist order
n_twist = 2*p + 2 - n
# cofactor
h = n // P.order()
```

```python
# exact order of P given any multiple N of it
def point_order(p, a, P, N):
    n = N
    for q, e in factor_dict(N).items():
        for _ in range(e):
            if mul(p, a, n // q, P) is None: n //= q
            else: break
    return n
```

```python
# naive point count, O(p): only for p < 10**7
n = 1 + sum(1 if (x**3 + a*x + b) % p == 0 else
            (2 if pow((x**3 + a*x + b) % p, (p-1)//2, p) == 1 else 0) for x in range(p))
```

```python
# lift an x to a point (p = 3 mod 4 fast path)
rhs = (x**3 + a*x + b) % p
y = pow(rhs, (p + 1)//4, p)         # valid only if y*y % p == rhs
```

```python
# full Tonelli-Shanks (any odd p)
def tonelli(n, p):
    n %= p
    if n == 0: return 0
    if pow(n, (p-1)//2, p) != 1: return None
    if p % 4 == 3: return pow(n, (p+1)//4, p)
    q, s = p - 1, 0
    while q % 2 == 0: q, s = q//2, s+1
    z = 2
    while pow(z, (p-1)//2, p) != p-1: z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q+1)//2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1: t2, i = t2*t2 % p, i+1
        b2 = pow(c, 1 << (m-i-1), p)
        m, c = i, b2*b2 % p
        t, r = t*c % p, r*b2 % p
    return r
```

## Sage: EllipticCurve recipes

```python
# SageMath
# build a curve and a point
E = EllipticCurve(GF(p), [a, b])
P = E(x, y)                       # raises if not on the curve
P = E.lift_x(x)                   # one point with that x
Ps = E.lift_x(x, all=True)        # both sign choices
```

```python
# SageMath
# orders
E.order(); E.cardinality()         # SEA under the hood
P.order()
E.abelian_group()                  # full group structure, e.g. Z/n1 x Z/n2
factor(E.order())
```

```python
# SageMath
# generators, random points, torsion
E.gens(); E.random_point(); E.abelian_group().invariants()
```

```python
# SageMath
# discrete logs
Q.log(P)                                            # Sage 10.x: Q.log(P), not P.discrete_log(Q)
discrete_log(Q, P, ord=P.order(), operation='+')      # explicit, works in every version
discrete_log_rho(Q, P, ord=P.order(), operation='+')
discrete_log_lambda(Q, P, (lo, hi), operation='+')  # kangaroo over an interval
```

```python
# SageMath
# curve properties
E.is_supersingular(); E.is_ordinary(); E.j_invariant(); E.discriminant()
E.trace_of_frobenius(); E.quadratic_twist(); E.frobenius()
```

```python
# SageMath
# pairings (need the n-torsion to be rational; base_extend first)
Ek = E.base_extend(GF(p**k, 'z'))
Ek(P).weil_pairing(Ek(Q), n)
Ek(P).tate_pairing(Ek(Q), n, k)
```

```python
# SageMath
# isogenies and division polynomials
E.division_polynomial(3)
phi = E.isogeny(K)                  # K a kernel point or polynomial
phi.codomain(); phi.degree(); phi.rational_maps()
```

```python
# SageMath
# curves over extension fields and over Z/nZ (composite modulus challenges)
E2 = EllipticCurve(GF(p**2, 'i'), [a, b])
E3 = EllipticCurve(Zmod(n), [a, b])   # arithmetic may fail: that failure factors n
```

```python
# SageMath
# base change, twists, and the curve from a j-invariant
E.base_extend(GF(p**2, 'i'))
EllipticCurve_from_j(GF(p)(j))
E.quadratic_twist(d)
```

## PARI/GP one-liners

```sh
# curve cardinality without Sage
gp -q -c 'p=...; E=ellinit([Mod(a,p),Mod(b,p)]); print(ellcard(E))'
# point order, addition, scalar multiple
gp -q -c 'E=ellinit([Mod(a,p),Mod(b,p)]); P=[Mod(x,p),Mod(y,p)]; print(ellorder(E,P))'
gp -q -c 'print(elladd(E,P,Q)); print(ellmul(E,P,k))'
# discrete log
gp -q -c 'print(elllog(E,Q,P))'
# is the curve supersingular? trace == 0 mod p
gp -q -c 'print(ellap(E))'
```

## Point encoding (SEC1)

```text
04 || X || Y      uncompressed, 1 + 2*ceil(log256 p) bytes (65 for P-256/secp256k1)
02 || X           compressed, y even
03 || X           compressed, y odd
00                the point at infinity
```

```python
# decompress
prefix, xb = blob[0], blob[1:]
x = int.from_bytes(xb, "big")
y = tonelli((x**3 + a*x + b) % p, p)
if y is None: raise ValueError("x is on the twist, not the curve")
if y & 1 != prefix & 1: y = p - y
```

```sh
# inspect a real key with openssl
openssl ec -in key.pem -text -noout
openssl ec -in key.pem -pubout -conv_form uncompressed -text -noout
openssl ecparam -list_curves
```

## Named curve constants

```text
# secp256k1  (Bitcoin/Ethereum, a = 0, cofactor 1)
p  = 2^256 - 2^32 - 977
a  = 0
b  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
h  = 1
```

```text
# NIST P-256 / secp256r1 / prime256v1   (a = -3, cofactor 1)
p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
h  = 1
```

```text
# NIST P-384 / secp384r1
p  = 2^384 - 2^128 - 2^96 + 2^32 - 1
a  = p - 3
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
h  = 1
```

```text
# Curve25519 (Montgomery) and Ed25519 (twisted Edwards) -- same group, cofactor 8
p  = 2^255 - 19
A  = 486662            a24 = 121665
basepoint u = 9
l  = 2^252 + 27742317777372353535851937790883648493        # prime order
#E = 8 * l             twist order = 4 * l'  (l' prime, so twist-secure)
# Ed25519: a = -1, d = -121665/121666
```

```text
# Curve448 (Montgomery, cofactor 4)
p  = 2^448 - 2^224 - 1
A  = 156326
basepoint u = 5
```

```text
# brainpoolP256r1
p  = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
a  = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
b  = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
n  = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
```

Full parameter database with Sage/Python exports: https://neuromancer.sk/std/

## ECDSA quick reference

```text
sign:    r = x(k*G) mod n ;  s = k^-1 (h + r*d) mod n
verify:  w = s^-1 ; R = (h*w)G + (r*w)Q ; accept iff x(R) mod n == r
recover: Q = r^-1 (s*R - h*G)  with R lifted from r (two candidates, plus cofactor)
```

```python
# nonce reuse (same r in two signatures)
k = (h1 - h2) * pow(s1 - s2, -1, n) % n
d = (s1 * k - h1) * pow(r, -1, n) % n
```

```python
# related nonces k2 = a*k1 + c, a and c known
d = (a*s2*h1 - s1*h2 + s1*s2*c) * pow(s1*r2 - a*s2*r1, -1, n) % n
```

```python
# malleability and canonicalisation
low_s = lambda r, s: (r, s if s <= (n - 1)//2 else n - s)
# degenerate probes a compliant verifier must reject
probes = [(0, 0), (r, 0), (0, s), (r, n), (n, s), (r, s + n)]
```

## Python libraries

```sh
pip install ecdsa pycryptodome tinyec fastecdsa
```

```python
# python-ecdsa: parse keys and signatures
from ecdsa import SigningKey, VerifyingKey, SECP256k1, NIST256p
sk = SigningKey.generate(curve=SECP256k1); vk = sk.verifying_key
vk.pubkey.point.x(), vk.pubkey.point.y()
VerifyingKey.from_pem(open("pub.pem").read())
```

```python
# pycryptodome
from Crypto.PublicKey import ECC
k = ECC.generate(curve="P-256"); print(k.pointQ.x, k.pointQ.y, k.d)
ECC.import_key(open("key.pem").read())
```

```python
# tinyec: quick arbitrary curves without Sage
from tinyec.ec import Curve, SubGroup, Point
field = SubGroup(p=p, g=(Gx, Gy), n=n, h=1)
curve = Curve(a=a, b=b, field=field, name="custom")
P = Point(curve, Gx, Gy); print(5 * P)
```

## Fast checks to run on any ECC challenge

```python
assert (y*y - x*x*x - a*x - b) % p == 0            # point actually on the curve
assert (4*pow(a,3,p) + 27*b*b) % p != 0            # not singular
assert is_prime(p)                                  # not a composite "prime"
assert mul(p, a, n, G) is None                      # n really is a multiple of ord(G)
assert mul(p, a, p, G) is not None                  # not anomalous (else Smart)
assert n != p + 1                                   # not supersingular (else MOV)
assert max(factor_dict(n)) > 2**64                  # not smooth (else Pohlig-Hellman)
```

## References

- https://neuromancer.sk/std/ (curve parameter database)
- https://safecurves.cr.yp.to/
- https://www.secg.org/sec2-v2.pdf (SEC 2 named curves)
- https://doc.sagemath.org/html/en/reference/arithmetic_curves/index.html
- https://hyperelliptic.org/EFD/ (explicit formulas database for every coordinate system)
