---
title: "Post-Quantum - Isogeny Crypto: SIDH/SIKE, the Castryck-Decru Break, and Toy Walks"
category: crypto
subcategory: pq
type: technique
tags: [post-quantum, pqc, isogeny, sidh, sike, csidh, supersingular, j-invariant, velu, montgomery-curve, castryck-decru, torsion-points, meet-in-the-middle, isogeny-graph, glue-and-split, sage, python]
difficulty: insane
summary: "SIDH is dead: published torsion images let Castryck-Decru recover the key in minutes. CTFs still ask you to walk a tiny isogeny graph, which is a meet-in-the-middle."
when_to_use:
  - "The challenge mentions SIDH, SIKE, isogeny, j-invariant or supersingular"
  - "A public key is a curve plus the images of two torsion points"
  - "p has the shape 2^a * 3^b - 1 (or l_A^a * l_B^b * f +/- 1)"
  - "The parameters are small enough to walk the graph by brute force"
tools: [sage, python]
related: [ecc-mov-pairing, pq-ntru-lwe, ecc-recover-curve-params, ecc-cheatsheet]
---

## TL;DR

SIDH walks the supersingular isogeny graph: both parties publish the codomain curve of a
secret isogeny *plus* the images of the other party's torsion basis. Those torsion images are
the fatal extra data: the Castryck-Decru attack (2022) uses them to glue the unknown isogeny
into a higher-dimensional abelian surface and recover the secret key, in minutes, classically.
SIKE is dead. CSIDH (a different, commutative construction that publishes no torsion images)
is not affected. In CTFs you almost always get toy parameters and a graph you can walk.

## Recognise it

- `p = 2^a * 3^b - 1` (SIKEp434: `a=216, b=137`; the toy `p = 431 = 2^4 * 3^3 - 1`).
- Arithmetic in `GF(p^2)`, curves in Montgomery form `y^2 = x^3 + A x^2 + x`.
- The public key is `(x(phi(P)), x(phi(Q)), x(phi(Q-P)))` -- three x-coordinates.
- "j-invariant", "Velu", "2-isogeny", "3-isogeny", "kernel generator".
- The word CSIDH, or class-group actions, means a *different* (still standing) scheme.

## Theory

**Supersingular curves.** Over `GF(p^2)` there are about `p/12` supersingular `j`-invariants.
For each small prime `l`, the `l`-isogeny graph on them is `(l+1)`-regular and a Ramanujan
expander: random walks mix in `O(log p)` steps. Hardness assumption: given two supersingular
curves, find an isogeny between them.

**SIDH.** Fix `p = l_A^a l_B^b f - 1` and a starting curve `E_0`. Alice picks a secret kernel
`<P_A + [s_A] Q_A>` of order `l_A^a`, computes `phi_A : E_0 -> E_A`, and publishes `E_A`
together with `phi_A(P_B), phi_A(Q_B)`. Bob does the same with `l_B`. Each then pushes the
other's points through their own isogeny and lands on the same `j`-invariant.

**Why the torsion images kill it.** Castryck-Decru: the auxiliary data `phi_A(P_B), phi_A(Q_B)`
says how the secret isogeny acts on a known subgroup. Combine `E_0` and `E_A` into a product
of elliptic curves and use Kani's criterion: if you guess the first few steps correctly, a
carefully built `(l_B^b)`-isogeny of *abelian surfaces* splits back into a product of elliptic
curves; if you guess wrong, it does not. That gives a decision oracle, and you recover the key
digit by digit. Maino-Martindale and Robert removed the need for `E_0` to have small-degree
endomorphisms; Robert's version works in dimension 8 for any starting curve. Total cost:
minutes on a laptop for SIKEp751.

**What survives.** CSIDH and its descendants (commutative class-group action, no torsion
images published) and SQIsign (signatures from the Deuring correspondence) are not broken by
this. Anything that publishes torsion images of a secret isogeny of known degree is.

**What a CTF actually asks.** Nearly always one of:

1. *Implement the walk.* Given `E_0` and a secret kernel, compute the codomain. You need Velu
   (or the SIKE Montgomery formulas) and `GF(p^2)` arithmetic.
2. *Small parameters, brute force.* With `p` of a few hundred, the graph has a few dozen
   vertices; enumerate.
3. *Meet in the middle.* Secret walk of length `e`; enumerate all walks of length `e/2` from
   both ends and match `j`-invariants. Cost `O(l^{e/2})` instead of `O(l^e)`.
4. *Run Castryck-Decru.* Load the public Sage implementation and feed it the parameters.

**The formulas you need (Montgomery, `l = 2`).** For `E_A : y^2 = x^3 + A x^2 + x` and a
kernel point of order 2 with `x`-coordinate `x_0 != 0`:

$$A' = 2\,(1 - 2x_0^2), \qquad \varphi(x) = \frac{x\,(x\,x_0 - 1)}{x - x_0}$$

The three 2-torsion `x`-coordinates are `0` and the roots of `x^2 + A x + 1 = 0`, i.e.
`x = (-A +/- sqrt(A^2 - 4))/2`. `j(A) = 256 (A^2 - 3)^3 / (A^2 - 4)`.

## Attack

1. Read off `p`, `l_A^a`, `l_B^b`, the starting curve and the public key format.
2. If the parameters are toy: build the graph and meet in the middle.
3. If the parameters are real SIKE: use the published Castryck-Decru Sage code.
4. If the scheme is CSIDH: look for an implementation bug (bad key validation, a reused
   ephemeral, a non-supersingular curve accepted), not for a break of the assumption.
5. Check whether the challenge validates that the supplied curve is supersingular -- a
   classic bug is accepting an ordinary curve, where the class-group action leaks.

## Code

```python
#!/usr/bin/env python3
"""Toy SIDH: GF(p^2), Montgomery 2-isogenies, graph walking, meet-in-the-middle."""
import random
from collections import deque

# p = 2^4 * 3^3 - 1 = 431, the standard toy SIDH prime (p = 3 mod 4)
P = 431
assert P % 4 == 3

class Fp2:
    """a + b*i in GF(p^2) with i^2 = -1 (valid because p = 3 mod 4)."""
    __slots__ = ("a", "b")

    def __init__(self, a, b=0):
        self.a, self.b = a % P, b % P

    def __eq__(self, o):
        return isinstance(o, Fp2) and self.a == o.a and self.b == o.b

    def __hash__(self):
        return hash((self.a, self.b))

    def __add__(self, o):
        return Fp2(self.a + o.a, self.b + o.b)

    def __sub__(self, o):
        return Fp2(self.a - o.a, self.b - o.b)

    def __neg__(self):
        return Fp2(-self.a, -self.b)

    def __mul__(self, o):
        return Fp2(self.a * o.a - self.b * o.b, self.a * o.b + self.b * o.a)

    def inverse(self):
        d = pow(self.a * self.a + self.b * self.b, -1, P)
        return Fp2(self.a * d, -self.b * d)

    def __truediv__(self, o):
        return self * o.inverse()

    def is_zero(self):
        return self.a == 0 and self.b == 0

    def __pow__(self, e):
        r, b = Fp2(1), self
        while e:
            if e & 1:
                r = r * b
            b, e = b * b, e >> 1
        return r

    def __repr__(self):
        return f"{self.a}+{self.b}i"

ZERO, ONE, TWO, THREE, FOUR = Fp2(0), Fp2(1), Fp2(2), Fp2(3), Fp2(4)

def sqrt_fp(n):
    """Square root in GF(p) for p = 3 mod 4, or None."""
    n %= P
    if n == 0:
        return 0
    r = pow(n, (P + 1) // 4, P)
    return r if r * r % P == n else None

def sqrt_fp2(z):
    """Square root in GF(p^2) via the norm ('complex') method, or None."""
    if z.is_zero():
        return Fp2(0)
    if z.b == 0:
        r = sqrt_fp(z.a)
        if r is not None:
            return Fp2(r)
        r = sqrt_fp((-z.a) % P)
        return None if r is None else Fp2(0, r)
    norm = (z.a * z.a + z.b * z.b) % P
    s = sqrt_fp(norm)
    if s is None:
        return None
    inv2 = pow(2, -1, P)
    for cand in ((z.a + s) * inv2 % P, (z.a - s) * inv2 % P):
        d0 = sqrt_fp(cand)
        if d0 is None or d0 == 0:
            continue
        d1 = z.b * pow(2 * d0 % P, -1, P) % P
        out = Fp2(d0, d1)
        if out * out == z:
            return out
    return None

# ---- Montgomery curve y^2 = x^3 + A*x^2 + x over GF(p^2) ----------------

def j_invariant(A):
    """j = 256 * (A^2 - 3)^3 / (A^2 - 4)."""
    a2 = A * A
    num = (a2 - THREE)
    return Fp2(256) * num * num * num / (a2 - FOUR)

def two_torsion_x(A):
    """x-coordinates of the order-2 points other than (0, 0)."""
    disc = sqrt_fp2(A * A - FOUR)
    if disc is None:
        return []
    inv2 = TWO.inverse()
    return [(-A + disc) * inv2, (-A - disc) * inv2]

def two_isogeny(A, x0):
    """Codomain constant of the 2-isogeny with kernel {O, (x0, 0)}, x0 != 0."""
    return TWO * (ONE - TWO * x0 * x0)

def push_point(x, x0):
    """Image x-coordinate under that 2-isogeny."""
    return x * (x * x0 - ONE) / (x - x0)

def neighbours(A):
    """2-isogenous curves reachable with kernel (x0, 0), x0 != 0.

    The third 2-isogeny, with kernel (0, 0), needs an extra square root to be put back
    into Montgomery form, so we stay on this 2-regular subgraph -- which already reaches
    every supersingular j-invariant for these parameters.
    """
    return [two_isogeny(A, x0) for x0 in two_torsion_x(A) if not x0.is_zero()]

# ---- full point arithmetic, used only to certify supersingularity -------

def lift_x(A, x):
    y = sqrt_fp2(x * x * x + A * x * x + x)
    return None if y is None else (x, y)

def ec_add(A, Pt, Q):
    if Pt is None:
        return Q
    if Q is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Q
    if x1 == x2 and (y1 + y2).is_zero():
        return None
    if x1 == x2 and y1 == y2:
        lam = (THREE * x1 * x1 + TWO * A * x1 + ONE) / (TWO * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - A - x1 - x2
    return (x3, lam * (x1 - x3) - y1)

def ec_mul(k, Pt, A):
    R, S = None, Pt
    while k:
        if k & 1:
            R = ec_add(A, R, S)
        S, k = ec_add(A, S, S), k >> 1
    return R

def is_supersingular(A, rng, tries=4):
    """#E(GF(p^2)) = (p+1)^2 for supersingular curves: check (p+1)*Pt == O."""
    checked = 0
    for _ in range(200):
        Pt = lift_x(A, Fp2(rng.randrange(P), rng.randrange(P)))
        if Pt is None or Pt[1].is_zero():
            continue
        if ec_mul(P + 1, Pt, A) is not None:
            return False
        checked += 1
        if checked == tries:
            return True
    return checked > 0

# ---- graph walking and meet in the middle ------------------------------

def walk(A, choices):
    """Follow a sequence of neighbour indices, never backtracking by j-invariant."""
    prev_j = None
    cur = A
    for c in choices:
        nb = [n for n in neighbours(cur) if j_invariant(n) != prev_j]
        if not nb:
            nb = neighbours(cur)
        prev_j = j_invariant(cur)
        cur = nb[c % len(nb)]
    return cur

def bfs_paths(A, depth):
    """{j-invariant: (A, path)} for every curve at distance <= depth."""
    out = {j_invariant(A): (A, ())}
    frontier = [(A, ())]
    for _ in range(depth):
        nxt = []
        for cur, path in frontier:
            for idx, nb in enumerate(neighbours(cur)):
                j = j_invariant(nb)
                if j not in out:
                    out[j] = (nb, path + (idx,))
                    nxt.append((nb, path + (idx,)))
        frontier = nxt
    return out

def meet_in_the_middle(A0, Atarget, max_half=6):
    """Grow both balls until they touch: cost O(deg^(d/2)) instead of O(deg^d)."""
    for half in range(1, max_half + 1):
        front = bfs_paths(A0, half)
        back = bfs_paths(Atarget, half)
        common = set(front) & set(back)
        if common:
            j = min(common, key=lambda k: len(front[k][1]) + len(back[k][1]))
            return front[j][1], back[j][1], j, half
    return None

if __name__ == "__main__":
    rng = random.Random(99)
    print(f"[ok] p = {P} = 2^4 * 3^3 - 1, working in GF(p^2)")

    # --- GF(p^2) sanity ---
    z = Fp2(17, 23)
    s = sqrt_fp2(z * z)
    assert s is not None and s * s == z * z
    assert (z * z.inverse()) == ONE
    print("[ok] GF(p^2) arithmetic and square roots")

    # --- the starting curve of the SIKE toy parameter set ---
    A0 = Fp2(6)
    assert is_supersingular(A0, rng)
    print(f"[ok] E0: y^2 = x^3 + 6x^2 + x is supersingular, j = {j_invariant(A0)}")

    # --- the 2-isogeny graph is 3-regular on supersingular j-invariants ---
    seen, queue = {j_invariant(A0): A0}, deque([A0])
    while queue:
        cur = queue.popleft()
        for nb in neighbours(cur):
            j = j_invariant(nb)
            if j not in seen:
                seen[j] = nb
                queue.append(nb)
    print(f"[ok] the walk reaches {len(seen)} distinct j-invariants "
          f"(the supersingular count is about p/12 = {P // 12})")
    for j, A in list(seen.items())[:5]:
        assert is_supersingular(A, rng), "every vertex must stay supersingular"
    print("[ok] sampled vertices are all supersingular: the walk never leaves the graph")

    # --- a secret walk, then a meet-in-the-middle recovery ---
    secret = [rng.randrange(3) for _ in range(4)]
    EA = walk(A0, secret)
    print(f"[ok] secret walk of length {len(secret)} -> j(EA) = {j_invariant(EA)}")

    found = meet_in_the_middle(A0, EA)
    assert found is not None, "meet in the middle failed"
    fpath, bpath, jmid, half = found
    print(f"[ok] MITM: balls of radius {half} from both ends meet at j = {jmid} "
          f"({len(fpath)} + {len(bpath)} steps)")

    # verify: the forward half really reaches the meeting curve
    cur = A0
    for idx in fpath:
        cur = neighbours(cur)[idx]
    assert j_invariant(cur) == jmid
    cur = EA
    for idx in bpath:
        cur = neighbours(cur)[idx]
    assert j_invariant(cur) == jmid
    print("[ok] both halves verified: E0 and EA are connected through the meeting curve")

    # --- pushing a point through an isogeny (what SIDH publishes) ---
    x0 = next(x for x in two_torsion_x(A0) if not x.is_zero())
    A1 = two_isogeny(A0, x0)
    Pt = None
    for _ in range(200):
        cand = lift_x(A0, Fp2(rng.randrange(P), rng.randrange(P)))
        if cand and not (cand[0] - x0).is_zero() and not cand[0].is_zero():
            Pt = cand
            break
    assert Pt is not None
    ximg = push_point(Pt[0], x0)
    assert lift_x(A1, ximg) is not None, "the image must land on the codomain curve"
    print("[ok] pushed a point through a 2-isogeny; the image lies on the codomain")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Backtracking.** Every step has `l + 1` neighbours, one of which walks back. A "random"
  walk that backtracks lands on a curve much closer to the start than you think. Track the
  previous `j`.
- **`j = 0` and `j = 1728`.** These have extra automorphisms; the graph has loops and
  multiplicities there. Toy parameters usually start at `j = 1728`, so expect a duplicate
  neighbour on step one.
- **Square roots in `GF(p^2)`.** The norm method above needs `p = 3 mod 4`. For other `p` use
  Tonelli-Shanks in `GF(p^2)` or Sage.
- **Montgomery vs Weierstrass.** SIKE uses Montgomery `(A : C)` projectively and never
  normalises; if you port formulas, watch the `A24 = (A + 2)/4` convention.
- **Supersingularity check.** `(p+1) P = O` for a few random `P` over `GF(p^2)` is the cheap
  test. A challenge that skips it may accept an ordinary curve from you.
- **Castryck-Decru needs the torsion images.** If a challenge only gives you `E_A` and nothing
  else (a pure isogeny-path problem), the attack does not apply -- that is the CSIDH/SQIsign
  setting, and you are back to meet-in-the-middle or `O(sqrt(p))` claw finding.
- **Do not reimplement Castryck-Decru.** Use the published Sage code; it is subtle
  (Richelot isogenies, genus-2 Jacobians, Kani's criterion).
- **`GF(p^2)` performance.** Pure Python is fine for `p < 2^20`. For SIKEp434 use Sage.

## Tools

```python
# SageMath: isogenies for real, with Velu built in
p = 431
Fp2.<i> = GF(p^2, modulus=x^2 + 1)
E = EllipticCurve(Fp2, [0, 6, 0, 1, 0])          # y^2 = x^3 + 6x^2 + x
print(E.is_supersingular(), E.j_invariant(), E.order() == (p + 1)^2)
K = E(0).division_points(2)                       # the 2-torsion
phi = E.isogeny(K[1])
print(phi.codomain().j_invariant(), phi.degree())
# walking with a kernel of order 2^4:
Pt = E.random_point() * ((p + 1) // 2^4)
print(E.isogeny(Pt, algorithm='factored').codomain().j_invariant())
```

```sh
# the Castryck-Decru attack, public SageMath implementation
git clone https://github.com/GiacomoPope/Castryck-Decru-SageMath
sage -python SIKE_challenge.py
```

## References

- Castryck, Decru, "An efficient key recovery attack on SIDH", https://eprint.iacr.org/2022/975 (EUROCRYPT 2023)
- Maino, Martindale, Panny, Pope, Wesolowski, "A direct key recovery attack on SIDH", https://eprint.iacr.org/2022/1026
- Robert, "Breaking SIDH in polynomial time", https://eprint.iacr.org/2022/1038
- De Feo, Jao, Plut, "Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies" (2011)
- Castryck, Lange, Martindale, Panny, Renes, "CSIDH: An efficient post-quantum commutative group action" (ASIACRYPT 2018)
- https://github.com/GiacomoPope/Castryck-Decru-SageMath
