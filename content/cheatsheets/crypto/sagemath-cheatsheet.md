---
title: "SageMath - Install, Preparser Gotchas and the 80 Idioms a CTF Crypto Player Needs"
category: crypto
subcategory: sagemath
type: cheatsheet
tags: [sage, sagemath, conda, docker, preparser, gf, finite-field, polynomialring, roots, small-roots, coppersmith, discrete-log, dlp, factor, ecm, matrix, lll, bkz, crt, chinese-remainder-theorem]
summary: "Install Sage three ways, avoid the preparser traps, call it from plain Python, and keep the ~80 one-liners that solve most CTF crypto in one place."
tools: [sage, pari, gp, conda, docker, python]
related: [ecc-cheatsheet, lattice-cheatsheet, lattice-coppersmith-small-roots, dlp-pohlig-hellman, ecc-toolkit, lattice-toolkit]
---

## Install

```sh
# conda-forge: the least painful native install, and it brings fpylll + pari
conda create -n sage -c conda-forge sage python=3.11
conda activate sage && sage --version
```

```sh
# docker: zero-install, mount the challenge directory
docker run -it --rm -v "$PWD":/home/sage/work sagemath/sagemath:latest
docker run -it --rm -v "$PWD":/work sagemath/sagemath sage /work/solve.sage
# non-interactive one-liner
docker run --rm sagemath/sagemath sage -c 'print(factor(2^67 - 1))'
```

```sh
# Linux distro packages (often a few releases behind, fine for CTF)
sudo apt install sagemath          # Debian/Ubuntu
sudo pacman -S sagemath            # Arch
brew install --cask sage           # macOS, or use conda/docker instead
```

```sh
# running things
sage                               # REPL
sage solve.sage                    # preparsed Sage file
sage -python solve.py              # plain CPython with Sage's libraries importable
sage -c 'print(factor(1000003))'   # one-liner
sage -q < script.sage              # quiet, stdin
sage -n jupyter                    # notebook
sage -pip install pwntools         # install into Sage's python
sage --preparse solve.sage         # emit solve.sage.py to see what the preparser did
```

## Preparser gotchas

```python
# SageMath
# ^ is POWER, not xor. Use ** if you copy code from Python, and ^^ for xor.
2^10          # 1024
2**10         # 1024
5^^3          # 6   (xor)
```

```python
# SageMath
# integer literals are Sage Integers, not python ints
type(2)               # <class 'sage.rings.integer.Integer'>
type(int(2))          # <class 'int'>
2/3                   # 2/3 as a Rational, NOT 0
int(2)/int(3)         # 0.666... (python semantics)
2//3                  # 0
ZZ(7) / ZZ(2)         # 7/2 -- use // or ZZ(...) to force integer division
```

```python
# SageMath
# convert before handing values to pure-python libraries
int(x); ZZ(x); Integer(x)
long_to_bytes(int(m))                    # pycryptodome wants a python int
[int(v) for v in vec]
```

```python
# SageMath
# the R.<x> = ... syntax only exists in .sage files / the REPL, not in sage -python
R = PolynomialRing(ZZ, 'x'); x = R.gen()     # the sage -python equivalent
F = GF(2**8, 'a'); a = F.gen()
```

```python
# SageMath
# reproducibility and timing
set_random_seed(1337)
%time factor(2^101 - 1)
timeit('LLL(M)')
```

## Calling Sage from a plain Python script

```python
# subprocess: write a .sage file, run it, parse stdout -- works everywhere
import json, subprocess, textwrap

def sage(code, **vars_):
    header = "\n".join(f"{k} = {v!r}" for k, v in vars_.items())
    src = header + "\n" + textwrap.dedent(code)
    out = subprocess.run(["sage", "-c", src], capture_output=True, text=True, check=True)
    return out.stdout.strip()

if __name__ == "__main__":
    n = 1000003 * 1000033
    print(sage("print(list(factor(n)))", n=n))
```

```sh
# or just run your solver under Sage's interpreter and keep writing normal Python
sage -python solve.py
```

```python
# inside sage -python, import what you need explicitly
from sage.all import GF, EllipticCurve, Matrix, ZZ, factor, discrete_log, crt
```

## Integers and number theory

```python
# SageMath
factor(n); list(factor(n)); factor(n, limit=10^6)
prime_factors(n); divisors(n); number_of_divisors(n)
is_prime(n); is_pseudoprime(n); next_prime(n); previous_prime(n); random_prime(2^256)
euler_phi(n); sigma(n); moebius(n); radical(n)
gcd(a, b); lcm(a, b); xgcd(a, b)            # xgcd -> (g, s, t) with s*a + t*b == g
inverse_mod(a, n); power_mod(a, e, n)
crt([r1, r2], [m1, m2]); CRT_list([r1, r2, r3], [m1, m2, m3])
valuation(n, p); n.nbits(); n.digits(2); n.exact_log(2)
kronecker(a, n); legendre_symbol(a, p); jacobi_symbol(a, n)
Integer(n).sqrt(); Integer(n).nth_root(3); Integer(n).is_square()
Integer(n).isqrt(); Integer(n).nth_root(3, truncate_mode=True)
continued_fraction(1234/5678).convergents()
```

```python
# SageMath
# ECM and other factoring back ends when factor() stalls
ecm.factor(n)                       # GMP-ECM, great for medium factors
ecm.find_factor(n, B1=1000000)
qsieve(n)                           # quadratic sieve
pari(n).factor()
```

## Modular arithmetic and finite fields

```python
# SageMath
R = Zmod(n); R = IntegerModRing(n)
a = R(5); a^-1; a.sqrt(); a.is_square(); a.multiplicative_order()
R.unit_group_order()
Mod(5, n)^-1
```

```python
# SageMath
F = GF(p)                                   # prime field
K.<a> = GF(2^128)                            # binary field, a is the generator
K = GF(3^5, 'g'); g = K.gen()
K = GF(p^2, 'i', modulus=x^2 + 1)            # explicit modulus
F.multiplicative_generator(); F.order(); K.modulus()
K(1).parent(); K.random_element()
```

```python
# SageMath
# discrete logs
discrete_log(F(h), F(g))                                 # Pohlig-Hellman + BSGS/rho
discrete_log(F(h), F(g), ord=q)
discrete_log_rho(F(h), F(g), ord=q)                      # ord must be PRIME
discrete_log_lambda(F(h), F(g), (lo, hi))                # kangaroo over an interval
bsgs(F(g), F(h), (0, q - 1))          # from sage.groups.generic import bsgs
F(g).multiplicative_order()
```

## Polynomials

```python
# SageMath
R.<x> = PolynomialRing(GF(p)); R.<x> = GF(p)[]
S.<x, y> = PolynomialRing(Zmod(N))
f = x^3 + 2*x + 1
f.roots()                                    # [(root, multiplicity), ...]
f.roots(multiplicities=False)
f.roots(ring=GF(p))                          # roots over another ring
f.factor(); f.is_irreducible(); f.degree(); f.monic()
f.coefficients(sparse=False); f.list()
f.derivative(); f.gcd(g); f.resultant(g, y); f.subs(x=5)
f.change_ring(ZZ); f.change_ring(Zmod(n))
R.quotient(f, 'z')                           # work in R[x]/(f)
```

```python
# SageMath
# Coppersmith small roots: the single most useful Sage feature in CTF crypto
P.<x> = PolynomialRing(Zmod(N))
((a + x)^3 - c).monic().small_roots(X=2^200, beta=1.0, epsilon=0.04)
(x + p_high).small_roots(X=2^128, beta=0.4)  # roots modulo a divisor of size ~ N^0.4
```

```python
# SageMath
# multivariate: Groebner bases and resultants
I = Ideal([f1, f2, f3])
I.groebner_basis()
I.variety()                                  # solutions over the base field
f1.resultant(f2, y)                          # eliminate y
```

## Matrices and lattices

```python
# SageMath
M = Matrix(ZZ, [[1, 2], [3, 4]]); M = matrix(GF(p), 3, 3, entries)
M = identity_matrix(ZZ, n); M = zero_matrix(ZZ, n, m); M = diagonal_matrix([1, 2, 3])
M = block_matrix(ZZ, [[A, B], [C, D]])
M.LLL(); M.LLL(delta=0.75); M.BKZ(block_size=30)
M.determinant(); M.rank(); M.transpose(); M.inverse(); M.rref(); M.echelon_form()
M.kernel(); M.left_kernel(); M.right_kernel_matrix()
M.solve_left(v); M.solve_right(v)
M.augment(v); M.stack(N); M.submatrix(0, 0, 2, 2)
M.charpoly(); M.eigenvalues(); M.smith_form()
vector(ZZ, [1, 2, 3]); v.norm(); v.dot_product(w)
```

```python
# SageMath
from sage.modules.free_module_integer import IntegerLattice
L = IntegerLattice(M)
L.shortest_vector(); L.closest_vector(vector(ZZ, t)); L.volume()
```

```python
# SageMath
# fpylll is bundled: drop to it when you want BKZ 2.0 or GSO details
from fpylll import IntegerMatrix, LLL, BKZ, GSO, SVP, CVP
A = IntegerMatrix.from_matrix([[int(v) for v in row] for row in M])
LLL.reduction(A); print(SVP.shortest_vector(A))
```

## Elliptic curves

```python
# SageMath
E = EllipticCurve(GF(p), [a, b])             # y^2 = x^3 + a x + b
E = EllipticCurve(GF(p), [a1, a2, a3, a4, a6])
E = EllipticCurve(Zmod(n), [a, b])           # composite modulus; failures factor n
P = E(x, y); P = E.lift_x(x); E.lift_x(x, all=True)
E.order(); E.cardinality(); E.abelian_group(); E.gens(); E.random_point()
P.order(); P.xy(); Q.log(P); (5*P + 3*Q)        # Q.log(P), not P.discrete_log(Q)
E.j_invariant(); E.discriminant(); E.is_supersingular(); E.trace_of_frobenius()
E.quadratic_twist(); E.base_extend(GF(p^2, 'i'))
E.division_polynomial(3); E.isogeny(K).codomain()
P.weil_pairing(Q, n); P.tate_pairing(Q, n, k)
EllipticCurve_from_j(GF(p)(1728))
```

## p-adics, reals, symbolics

```python
# SageMath
Qp(p, 20); Zp(p, 20)                         # p-adic fields and rings
K = Qp(5, 10); K(7).sqrt(); K(50).valuation()
RR(pi); RealField(200)(2).sqrt(); ComplexField(100)
var('x y'); solve([x + y == 3, x - y == 1], x, y)
find_root(cos(x) - x, 0, 1)
CyclotomicField(8); QQbar(2).sqrt()
```

## PARI/GP from inside Sage

```python
# SageMath
pari(n).factor()
pari('ellinit([0,7])')
pari(n).qfbclassno()
gp('znlog(Mod(%d,%d), Mod(%d,%d))' % (h, p, g, p))
gp.eval('factor(2^128+1)')
```

```sh
# or straight from the shell, no Sage needed
gp -q -c 'print(factor(2^128 + 1))'
gp -q -c 'print(znlog(Mod(5,1000003), Mod(2,1000003)))'
gp -q -c 'E=ellinit([Mod(3,1000003),Mod(8,1000003)]); print(ellcard(E))'
```

## Bytes, flags and interop

```python
# SageMath
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse
long_to_bytes(int(m))
bytes_to_long(b"flag{...}")
ZZ(bytes_to_long(data))
bytes(ZZ(m).digits(256)[::-1])               # without pycryptodome
''.join(chr(c) for c in ZZ(m).digits(256)[::-1])
```

```sh
# talking to a remote service from inside Sage: install into Sage's own python first
sage -pip install pwntools requests
```

```python
# SageMath
from pwn import remote
io = remote("host", 1337)
io.recvline(); io.sendline(str(int(x)).encode())
```

## The twelve highest-value one-liners

```python
# SageMath
factor(n)                                                 # factor the modulus
ecm.factor(n)                                             # when factor() is too slow
discrete_log(F(h), F(g))                                  # any DLP Sage can do
E.order(); factor(E.order())                              # curve triage
P.discrete_log(Q)                                         # ECDLP (Pohlig-Hellman + rho)
f.small_roots(X=2^300, beta=0.5)                          # Coppersmith
Matrix(ZZ, rows).LLL()                                    # every lattice attack
Matrix(ZZ, rows).BKZ(block_size=30)                       # when LLL is marginal
crt([r1, r2, r3], [m1, m2, m3])                           # CRT
continued_fraction(e/n).convergents()                      # Wiener
Zmod(n)(c).nth_root(e, all=True)                          # e-th roots mod n
PolynomialRing(Zmod(n), 'x')(poly).roots()                 # solve a congruence
```

## Common errors and what they mean

```text
NotImplementedError: root finding for this polynomial not implemented
    -> factor the modulus first, or use .change_ring(GF(p)) per prime factor
ZeroDivisionError: inverse of Mod(x, n) does not exist
    -> gcd(x, n) is a nontrivial factor of n. That IS the solve.
ArithmeticError: invariants ... define a singular curve
    -> discriminant is 0: see the singular-curve attack
ValueError: no discrete log of h to base g
    -> g does not generate the subgroup containing h; check orders
RuntimeError: Aborted / PARI stack overflow
    -> pari.allocatemem() or set the PARI stack: sage -c 'pari.allocatemem(10^9)'
TypeError: unsupported operand parent(s)
    -> you mixed rings; force with ZZ(...), GF(p)(...) or .change_ring(...)
SyntaxError on R.<x> = ...
    -> you are in sage -python; use R = PolynomialRing(...); x = R.gen()
```

## References

- https://doc.sagemath.org/
- https://doc.sagemath.org/html/en/reference/index.html
- https://hub.docker.com/r/sagemath/sagemath
- https://pari.math.u-bordeaux.fr/dochtml/html/
- https://github.com/fplll/fpylll
