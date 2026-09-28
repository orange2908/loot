---
title: "ECC - Smart's Attack on Anomalous Curves (#E == p)"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, smart-attack, anomalous-curve, ecdlp, dlp, discrete-log, padic, qp, formal-group, formal-logarithm, hensel-lifting, trace-one, sage, python, complex-multiplication]
difficulty: hard
summary: "When the curve order equals p exactly, the formal logarithm over Q_p turns the ECDLP into a single division mod p. Linear time, any key size."
when_to_use:
  - "E.order() == p (equivalently the trace of Frobenius is 1)"
  - "p*P == O for random points P on a curve over GF(p)"
  - "A challenge ships a weird non-standard 256-bit curve with no named reference"
  - "factor(E.order()) shows a single huge prime equal to the field characteristic"
tools: [sage, python, pari]
related: [ecc-recover-curve-params, ecc-pohlig-hellman, ecc-mov-pairing, ecc-toolkit, ecc-cheatsheet]
---

## TL;DR

A curve is *anomalous* when `#E(GF(p)) == p`. Then reduction mod `p` from `E(Q_p)` has a
kernel isomorphic to `(pZ_p, +)`, and multiplying a point by `p` drops it into that kernel
where the group law is plain addition. The formal logarithm reads off the value, and
`Q = kP` becomes a division in `GF(p)`. Cost: `O(log p)` -- a 256-bit key falls instantly.

## Recognise it

- `E.order() == p` in Sage, or `ellcard(E) == p` in PARI.
- `E.mul(p, P) is INF` for several random points (necessary, and in practice sufficient).
- The curve parameters look hand-made: `p` not from any standard, often of the shape
  `(1 + 3*v^2)/4` or `(1 + D*v^2)/4` (a complex-multiplication construction).
- `factor(E.order())` returns one prime, and that prime is the modulus.
- The challenge title says "anomalous", "trace one", "Smart" or "p-adic".

## Theory

Let `E/Q_p` be a lift of `E/GF(p)` (same `a`, `b` read as `p`-adic integers, or perturbed by
multiples of `p`). Reduction gives an exact sequence

$$0 \to E_1(\mathbb{Q}_p) \to E(\mathbb{Q}_p) \xrightarrow{\;\bmod p\;} E(\mathbb{F}_p) \to 0$$

where `E_1` is the kernel of reduction, the *formal group*. The formal group is isomorphic
to `(pZ_p, +)` through the formal logarithm, which to first order is just the parameter

$$t(P) = -\frac{x(P)}{y(P)}, \qquad \log_E(P) = t + O(t^2)$$

If `#E(GF(p)) = p`, then for any `P` in `E(Q_p)` the point `pP` lies in `E_1` (because
`pP` reduces to `p * P_bar = O`). Write `Q = kP` over `GF(p)`. Lift both, multiply both by
`p`, and use that the logarithm is a homomorphism:

$$\log_E(pQ) = k \cdot \log_E(pP) \pmod{p^2} \;\Longrightarrow\; k \equiv \frac{t(pQ)}{t(pP)} \pmod p$$

Both `t` values have valuation exactly 1, so the ratio is a unit and its residue is `k`.

**The one trap.** If the lifted curve over `Q_p` is itself anomalous, `pP` can be the point
at infinity and the ratio is undefined. Fix: lift with `a' = a + p*r1`, `b' = b + p*r2` for
random `r1, r2`. That changes nothing mod `p` but almost surely fixes the lift. The code
below retries until it works.

**Why the attack exists.** Anomalous curves have trace of Frobenius `t = 1`, so `p + 1 - t = p`.
Every standard curve is chosen to avoid this; only a deliberately crafted curve is anomalous.

## Attack

1. Verify `#E == p` (or at least `p*P == O` for random `P`).
2. Lift `a`, `b` to `Z_p` with a random `p`-multiple perturbation.
3. Hensel-lift `y_P` and `y_Q` to `Q_p` from their residues (Newton: `y <- (y + c/y)/2`).
4. Compute `pP` and `pQ` with the ordinary chord-and-tangent formulas over `Q_p`.
5. `k = (-x(pQ)/y(pQ)) / (-x(pP)/y(pP))`, take the residue mod `p`.
6. Verify `k*P == Q` on the original curve.

## Code

```python
#!/usr/bin/env python3
"""Smart's attack in pure Python: a minimal fixed-precision Q_p plus the formal log."""
import random

INF = None

# ---- fixed-precision p-adics: value = p^val * unit, unit known mod p^prec ----

class Qp:
    __slots__ = ("p", "val", "unit", "prec")

    def __init__(self, p, val, unit, prec):
        if val is None or unit == 0:
            self.p, self.val, self.unit, self.prec = p, None, 0, prec
            return
        while unit % p == 0 and prec > 0:
            unit, val, prec = unit // p, val + 1, prec - 1
        self.p, self.val, self.unit, self.prec = p, val, unit % p ** prec, prec

    @classmethod
    def from_int(cls, n, p, prec):
        return cls(p, 0, n % p ** prec, prec)

    def is_zero(self):
        return self.val is None

    def __add__(self, o):
        if self.is_zero():
            return o
        if o.is_zero():
            return self
        p, v = self.p, min(self.val, o.val)
        absprec = min(self.val + self.prec, o.val + o.prec)
        if absprec <= v:
            return Qp(p, None, 0, 1)
        mod = p ** (absprec - v)
        s = (self.unit * p ** (self.val - v) + o.unit * p ** (o.val - v)) % mod
        return Qp(p, v, s, absprec - v)

    def __neg__(self):
        return Qp(self.p, self.val, -self.unit, self.prec)

    def __sub__(self, o):
        return self + (-o)

    def __mul__(self, o):
        prec = min(self.prec, o.prec)
        if self.is_zero() or o.is_zero():
            return Qp(self.p, None, 0, prec)
        return Qp(self.p, self.val + o.val, self.unit * o.unit, prec)

    def inverse(self):
        assert not self.is_zero(), "cannot invert p-adic zero"
        return Qp(self.p, -self.val, pow(self.unit, -1, self.p ** self.prec), self.prec)

    def __truediv__(self, o):
        return self * o.inverse()

    def residue(self):
        assert self.val == 0, "residue() needs valuation 0"
        return self.unit % self.p

def qp_sqrt(c, root_mod_p):
    """Hensel-lift sqrt(c) matching root_mod_p; Newton doubles precision each step."""
    p, prec = c.p, c.prec
    y, two = Qp.from_int(root_mod_p, p, prec), Qp.from_int(2, p, prec)
    for _ in range(prec.bit_length() + 2):
        y = (y + c / y) / two
    return y if y.residue() == root_mod_p % p else -y

# ---- elliptic curve arithmetic over Q_p ---------------------------------

def qp_add(P, Q, A):
    if P is INF:
        return Q
    if Q is INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if (x1 - x2).is_zero() and (y1 + y2).is_zero():
        return INF
    if (x1 - x2).is_zero():
        three = Qp.from_int(3, A.p, A.prec)
        two = Qp.from_int(2, A.p, A.prec)
        lam = (three * x1 * x1 + A) / (two * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - x1 - x2
    return (x3, lam * (x1 - x3) - y1)

def qp_mul(k, P, A):
    R, S = INF, P
    while k:
        if k & 1:
            R = qp_add(R, S, A)
        S, k = qp_add(S, S, A), k >> 1
    return R

def smart_attack(p, a, b, P, Q, prec=8):
    """Solve Q = k*P on an anomalous curve y^2 = x^3 + a*x + b over GF(p)."""
    for _ in range(12):
        A = Qp.from_int(a + p * random.randrange(1, p), p, prec)
        B = Qp.from_int(b + p * random.randrange(1, p), p, prec)
        try:
            lifted = []
            for (x, y) in (P, Q):
                X = Qp.from_int(x, p, prec)
                lifted.append((X, qp_sqrt(X * X * X + A * X + B, y)))
            pP, pQ = qp_mul(p, lifted[0], A), qp_mul(p, lifted[1], A)
            if pP is INF or pQ is INF:
                continue
            k = (-(pQ[0] / pQ[1])) / (-(pP[0] / pP[1]))
            if k.val != 0:
                continue
            return k.residue()
        except AssertionError:
            continue
    raise ValueError("failed -- is the curve really anomalous?")

# ---- plain GF(p) arithmetic, for building and checking the demo ----------

def add(p, a, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    lam = ((3 * x1 * x1 + a) * pow(2 * y1 % p, -1, p) if P == Q
           else (y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)

def mul(p, a, k, P):
    R, S = None, P
    while k:
        if k & 1:
            R = add(p, a, R, S)
        S, k = add(p, a, S, S), k >> 1
    return R

if __name__ == "__main__":
    random.seed(3)
    # An anomalous curve built by complex multiplication with discriminant -3:
    # 4p = 1 + 3*v^2 forces trace 1, then y^2 = x^3 + b has order exactly p for some b.
    p = 0x3000000000000000000000000000000fc000000000000000000000000000014b
    a, b = 0, 13
    G = (0x2ba19fe4f01e17676e757e860dedee27532e2209a6fcb716c62947c91d68ed5b,
         0x5dab425c3d67157fee012930c209ef8d30d381d9897ec46edefc0a8a89e69db)
    assert (G[1] ** 2 - G[0] ** 3 - a * G[0] - b) % p == 0, "G not on the curve"
    assert mul(p, a, p, G) is None, "curve is not anomalous"
    print(f"[ok] #E == p, a {p.bit_length()}-bit anomalous curve")

    for secret in (0xdeadbeefcafebabe1234567890,
                   p - 2,
                   random.randrange(2, p)):
        Q = mul(p, a, secret, G)
        k = smart_attack(p, a, b, G, Q)
        assert k == secret % p, (hex(k), hex(secret))
        assert mul(p, a, k, G) == Q
    print("[ok] Smart's attack recovered 3/3 keys, no SageMath, no lattice")
    print("all self-tests passed")
```

## Building your own anomalous curve

```python
# SageMath: CM construction, discriminant -3 (j = 0, curves y^2 = x^3 + b)
v = 2^127 + 1
while True:
    v += 2
    if (1 + 3*v^2) % 4: continue
    p = (1 + 3*v^2) // 4
    if is_prime(p) and p % 3 == 1: break
for b in range(1, 200):
    E = EllipticCurve(GF(p), [0, b])
    if E.order() == p:
        print(hex(p), b, E.gens()[0]); break
```

## Variants and pitfalls

- **Precision.** `prec = 8` is comfortable; `prec = 2` is the theoretical minimum but the
  Newton square root and the double-and-add chain both burn digits. If the attack returns a
  value with `k.val != 0`, raise `prec`.
- **Not actually anomalous.** If `#E = p` fails, the ratio is meaningless. Check first.
- **Anomalous over an extension.** `#E(GF(p^n)) == p^n` on a curve over `GF(p^n)` has the
  same weakness, but you need `Q_{p^n}` (unramified extension) -- use Sage.
- **Trace `p` curves** (`#E = p + 1 - p = 1`) are a different degenerate case: the group is
  trivial, nothing to solve.
- **Supersingular curves** (`t = 0`, `#E = p + 1`) are *not* anomalous. They fall to MOV
  instead; see `ecc-mov-pairing`.
- **Mixed challenges.** Some tasks combine an anomalous curve with a smooth cofactor: solve
  the anomalous part with Smart and the rest with Pohlig-Hellman, then CRT.
- **The ratio is `t(pQ)/t(pP)`, not the reverse.** Getting it backwards yields `k^{-1} mod p`,
  which is also a perfectly valid-looking 256-bit number. Always verify `k*P == Q`.

## Tools

```python
# SageMath: the canonical five-line version
def smart(P, Q, p, prec=4):
    E = P.curve()
    Ep = EllipticCurve(Qp(p, prec), [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])
    Pp = [R for R in Ep.lift_x(ZZ(P[0]), all=True) if GF(p)(R[1]) == P[1]][0]
    Qp_ = [R for R in Ep.lift_x(ZZ(Q[0]), all=True) if GF(p)(R[1]) == Q[1]][0]
    (xP, yP), (xQ, yQ) = (p * Pp).xy(), (p * Qp_).xy()
    return ZZ((xQ / yQ) / (xP / yP))
```

```sh
# PARI/GP: confirm the order in one shot
gp -q -c 'p=...; E=ellinit([Mod(0,p),Mod(13,p)]); print(ellcard(E)==p)'
```

## References

- Smart, "The discrete logarithm problem on elliptic curves of trace one", Journal of Cryptology 12 (1999)
- https://wstein.org/edu/2010/414/projects/novotney.pdf
- https://doc.sagemath.org/html/en/reference/padics/index.html
