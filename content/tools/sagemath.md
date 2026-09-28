---
title: "Tool - SageMath"
category: crypto
subcategory: math
type: tool
tags: [sagemath, sage, math, number-theory, lattice, lll, coppersmith, elliptic-curve, discrete-log, polynomial, finite-field, matrix, groebner, crypto, factoring]
summary: "The mathematics system that has every algorithm CTF crypto needs already implemented: factoring, discrete logs, lattices, curves, polynomials."
related: [crypto-triage, rsa-decision-tree, math-constants-and-identities, z3]
---

## What it is

SageMath is a Python-based computer algebra system that bundles PARI/GP, FLINT, NTL, Singular, GAP and more behind one interface. For CTF crypto it means `factor()`, `discrete_log()`, `small_roots()` (Coppersmith), `LLL()`, elliptic curve arithmetic and finite-field polynomial algebra are all one call away.

If a crypto challenge involves lattices, curves, or polynomial rings, Sage is not optional.

## Install

```sh
# macOS
brew install --cask sage            # or: brew install sagemath
# Debian/Ubuntu/Kali
sudo apt install sagemath
# conda (most reliable cross-platform)
conda create -n sage -c conda-forge sage python=3.11 && conda activate sage
# Docker (fastest to get working, no local build)
docker run -it --rm -v "$PWD:/home/sage/work" sagemath/sagemath:latest
# verify
sage --version
```
If installing Sage is painful, the Docker image is the pragmatic answer during a CTF.

## The invocations that matter

```sh
# 1. run a one-liner
sage -c "print(factor(1234567891011))"
# 2. run a script (.sage files get preparsed: 2^10 means power, ints are Sage Integers)
sage solve.sage
# 3. interactive REPL
sage
# 4. use Sage's Python directly (no preparsing, plain Python semantics)
sage -python solve.py
# 5. convert a .sage file to .py to see what the preparser does
sage --preparse solve.sage && cat solve.sage.py
```

The calls that come up constantly:

```sage
# --- factoring and primes ---
factor(n)                                  # full factorisation
list(factor(n))                            # [(p, e), ...]
ecm.factor(n)                              # Lenstra ECM, for medium factors
is_prime(n); next_prime(n); previous_prime(n)
euler_phi(n); divisors(n); prime_range(100)

# --- modular arithmetic ---
R = Zmod(n)
R(5)^-1                                    # modular inverse
crt([2, 3, 2], [3, 5, 7])                  # Chinese remainder
inverse_mod(a, n); power_mod(a, e, n)
Mod(a, p).sqrt()                           # square root mod p
Mod(a, p).is_square()
Mod(g, p).multiplicative_order()
primitive_root(p)
kronecker_symbol(a, n)                     # Jacobi/Kronecker

# --- discrete logarithm (handles Pohlig-Hellman automatically) ---
discrete_log(Mod(h, p), Mod(g, p))
discrete_log(Mod(h, p), Mod(g, p), ord=q)  # much faster if you know the order

# --- polynomials ---
P.<x> = PolynomialRing(Zmod(n))
f = x^3 + 5*x + 7
f.roots()
gcd(f, g)                                  # polynomial gcd -> Franklin-Reiter
F.<a> = GF(2^8, modulus=x^8 + x^4 + x^3 + x + 1)   # AES field

# --- Coppersmith: small roots of a polynomial mod n ---
P.<x> = PolynomialRing(Zmod(n))
f = (known_high_bits + x).monic()
f.small_roots(X=2^128, beta=0.4, epsilon=0.02)

# --- lattices / LLL ---
M = Matrix(ZZ, [[1, 0, a], [0, 1, b], [0, 0, n]])
B = M.LLL()
B = M.BKZ(block_size=20)                   # stronger, slower

# --- elliptic curves ---
E = EllipticCurve(GF(p), [a, b])
E.order()
G = E(gx, gy)
P = k * G
G.order()
discrete_log(P, G, operation='+')          # ECDLP, uses Pohlig-Hellman
E.j_invariant(); E.discriminant()

# --- matrices / linear algebra ---
M = Matrix(GF(2), rows)
M.rank(); M.right_kernel(); M.solve_right(v); M.inverse()

# --- integers ---
Integer(n).nbits()
ZZ(n).isqrt()
continued_fraction(e/n).convergents()
```

A complete Coppersmith script:
```sage
# partial_p.sage -- recover p when you know its high bits
n = 0x00           # <- the modulus
p_high = 0x00      # <- known high bits of p, low bits zeroed
unknown = 200      # <- number of unknown low bits of p

P.<x> = PolynomialRing(Zmod(n))
f = (p_high + x).monic()
roots = f.small_roots(X=2^unknown, beta=0.4, epsilon=0.02)
for r in roots:
    p = int(p_high + r)
    if n % p == 0:
        q = n // p
        print("p =", p)
        print("q =", q)
        break
else:
    print("no root found - increase epsilon, or you know too few bits")
```

## Gotchas

- **`.sage` files are preparsed**: `^` means exponentiation (not XOR), integer literals become Sage `Integer`s, and `<x>` generator syntax works. In a `.py` run with `sage -python`, none of that applies - use `**` and `import sage.all`.
- `^` vs `**`: in a `.sage` file `^` is a power. If you need XOR there, use `.__xor__()` or `int(a) ^^ int(b)` (Sage's XOR operator in preparsed files is `^^`).
- Sage `Integer` is not Python `int`. Convert with `int(x)` before passing to `Crypto.Util.number.long_to_bytes` or `struct`.
- `small_roots` returns nothing when the bound is too large. Tune: raise `epsilon` (faster, weaker), lower `X`, or pass explicit `m`/`t` lattice parameters. If you know >= half the bits of `p`, it should work with `beta=0.4`.
- `discrete_log` without `ord=` will try to factor the group order first, which can hang on a large prime order. Supply the order when you know it.
- `factor(n)` on a 1024-bit RSA modulus will run forever. Sage is not magic - check `n.nbits()` first.
- Startup is slow (several seconds). For a loop over many inputs, do the loop inside one Sage process, not by calling `sage -c` repeatedly.
- Memory: `BKZ` with a large block size on a high-dimensional lattice will exhaust RAM. Start with LLL.
- Installing Sage natively can take a long time; if you are mid-CTF, use Docker.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You only need number theory basics | `sympy` (`factorint`, `discrete_log`, `sqrt_mod`, `primitive_root`, `nextprime`) |
| Fast big-integer arithmetic | `gmpy2` (`iroot`, `invert`, `powmod`, `is_prime`) |
| Lattice reduction without Sage | `fpylll` (the same LLL/BKZ library, as a Python package) |
| Coppersmith without Sage | `fpylll` + a hand-built lattice, or Defund's `coppersmith.sage` approach re-implemented |
| Factoring | `yafu`, `cado-nfs`, `msieve`, `ecm`, factordb |
| Elliptic curves | `tinyec`, `ecdsa`, or Sage in Docker |
| Constraint solving rather than algebra | `z3` (`ctfbrain search z3`) |
| Quick modular arithmetic | plain Python 3: `pow(a, -1, n)` and `pow(a, e, n)` are built in |
