---
title: "Lattices - Basis Templates, fpylll/Sage Recipes and LLL Debugging"
category: crypto
subcategory: lattice
type: cheatsheet
tags: [lattice, lll, lattice-reduction, bkz, svp, cvp, babai, kannan-embedding, hnp, hidden-number-problem, knapsack, subset-sum, cjloss, coppersmith, small-roots, truncated-lcg, lwe, ntru, gaussian-heuristic, scaling]
summary: "How to turn a problem into a lattice, every basis template worth memorising, fpylll/Sage/flatter commands, and a checklist for when LLL 'does not work'."
tools: [sage, fpylll, flatter, g6k, python]
related: [lattice-lll-fundamentals, lattice-hidden-number-problem, lattice-knapsack-subset-sum, lattice-coppersmith-small-roots, lattice-cvp-babai-scaling, lattice-linear-relations, lattice-toolkit, sagemath-cheatsheet]
---

## The recipe

```text
1. Name the small unknowns x_1..x_k and an honest bound X_j for each.
2. Write every relation as  sum_j c_j x_j == t  (mod n).
3. One row per unknown; one row per modulus (so the reduction can subtract n).
4. Put the constant term in via the Kannan embedding (extra row + extra column).
5. Scale column j by C / X_j so all target coordinates are about the same size.
6. Weight the "congruence" columns by a big W so a nonzero residual is never worth it.
7. Reduce. Scan EVERY row and BOTH signs. Unscale. Verify in the original problem.
```

```text
# does it even have a chance? compare against the Gaussian heuristic
target_norm  ~  sqrt(sum X_j^2)
lambda_1     ~  sqrt(dim / (2*pi*e)) * det^(1/dim)
# need target_norm << lambda_1, ideally by a factor 2 or more
```

```text
# conventions used everywhere below
rows are basis vectors (Sage, fpylll, this file). Papers often use columns: transpose.
delta = 0.99 for LLL. BKZ block_size 20-40 when LLL is marginal.
LLL is comfortable to dim ~150 (fpylll), ~40 (exact-arithmetic Python), 1000+ (flatter).
```

## Basis templates

```text
# HNP / biased ECDSA nonces: alpha*t_i - u_i is < K mod n, i = 1..m   (dim m+2)
[ n^2                                        ]
[      n^2                                   ]
[            ...                             ]
[ n*t_1  n*t_2  ...  n*t_m    K       0      ]
[ n*u_1  n*u_2  ...  n*u_m    0     n*K      ]
# short vector: (n*k_1, ..., n*k_m, alpha*K, -n*K)  ->  alpha = v[m] * K^-1 mod n
# recentre first: u_i += K/2, K //= 2   (one free bit of bias)
```

```text
# ECDSA -> HNP substitution
t_i = s_i^-1 * r_i mod n
u_i = -s_i^-1 * h_i mod n
K   = 2^(bits(n) - bias)          # bias = number of leading zero bits of each nonce
# need m * bias > bits(n), with 1.5x margin
```

```text
# subset sum, Lagarias-Odlyzko (density < 0.6463)          (dim n+1)
[ I_n   N*a ]
[ 0     N*s ]
# short vector: (e_1, ..., e_n, 0) with e_i in {0,1};  N = n+1
```

```text
# subset sum, CJLOSS (density < 0.9408) -- always prefer this  (dim n+1)
[ 2*I_n     N*a ]
[ 1 ... 1   N*s ]
# short vector: (2e_1 - 1, ..., 2e_n - 1, 0), all +/-1;  e_i = (v_i + 1)/2
```

```text
# Coppersmith univariate: f monic of degree d, root |x0| < X mod N    (dim d*m + t)
rows = coefficients of   x^j * N^(m-i) * f(x)^i      for i < m, j < d
       plus             x^j * f(x)^m                 for j < t
column k scaled by X^k
# reduced row -> divide coefficient k by X^k -> integer polynomial h with h(x0) = 0 over ZZ
# roots modulo an unknown divisor (beta < 1): use t comparable to m, not t = 1
```

```text
# truncated LCG, s_i = A_i*s_0 + B_i mod m, top bits y_i published     (dim t)
[ 1   A_1  A_2  ...  A_{t-1} ]
[ 0   m                      ]
[ 0        m                 ]
[ ...                        ]
target = (0, -C_1, ..., -C_{t-1}),  C_i = A_i*y_0*2^k + B_i - y_i*2^k
# Babai nearest plane; (closest - target) == (l_0, l_1, ..., l_{t-1}), the hidden low bits
# works for ANY modulus, including 2^64, because nothing is inverted
```

```text
# CVP by Kannan embedding                                   (dim n+1)
[ B   0 ]
[ t   M ]
# M ~ the expected distance ||t - v||. M = 1 only when the error is tiny;
# too small an M makes LLL reuse the target row and the embedding collapses.
```

```text
# modular equation system: sum_j a_ij x_j == c_i (mod n), |x_j| <= X_j
w_j = C / X_j  (C = prod X_j) ; W = big weight for the congruence columns
[ w_1                      W*a_11  W*a_21 ... ]
[      w_2                 W*a_12  W*a_22 ... ]
[ ...                                          ]
[                          W*n                 ]   one row per modulus/congruence
[                                W*n            ]
[ 0    0    ...            W*c_1  W*c_2  ...  M ]   the embedding row
# answer row has last coord +/-M and zero congruence coords; x_j = +/- v_j / w_j
```

```text
# NTRU (Coppersmith-Shamir), h public, N the ring degree      (dim 2N)
[ I_N   circ(h) ]
[ 0     q*I_N   ]
# short vector: (f, g) and every rotation (x^i f, x^i g)
```

```text
# LWE q-ary lattice, A in Z_q^(m x n), top n x n block A1 invertible   (dim m)
[ I_n           (A2 * A1^-1)^T ]
[ 0             q*I_(m-n)      ]
# Babai against b -> the lattice point A*s, then e = b - As, then solve A s = b - e mod q
```

```text
# integer relation: find small e with sum e_i v_i == S            (dim n+1)
[ I_n   0      K*v ]
[ 0     bound  K*S ]
# row with last coord 0 and |second-to-last| == bound gives e (up to sign)
```

```text
# simultaneous Diophantine approximation: p_i/q ~ alpha_i
[ 1        K*alpha_1 ... K*alpha_k ]
[ 0   -K                           ]
[ ...                              ]
# used by Shamir's Merkle-Hellman break and by several RSA partial-key attacks
```

## Sage

```python
# SageMath
# reduce
M = Matrix(ZZ, rows)
R = M.LLL()                                  # delta = 0.99 by default
R = M.LLL(delta=0.75, eta=0.51)
R = M.BKZ(block_size=30)
R = M.BKZ(block_size=40, proof=False, algorithm="NTL")
```

```python
# SageMath
# the lattice object: shortest/closest vector, determinant, Gram-Schmidt
from sage.modules.free_module_integer import IntegerLattice
L = IntegerLattice(Matrix(ZZ, rows))
L.shortest_vector()
L.closest_vector(vector(ZZ, target))
M.determinant(); M.gram_schmidt()
```

```python
# SageMath
# solve a linear system instead of guessing
M.solve_left(vector(ZZ, target))      # x with x*M == target
M.solve_right(vector(ZZ, target))     # x with M*x == target
M.kernel(); M.right_kernel_matrix()
```

```python
# SageMath
# Coppersmith, built in
P.<x> = PolynomialRing(Zmod(N))
f = (a + x)^e - c
f.monic().small_roots(X=2^200, beta=1.0, epsilon=0.04)
(x + p_high).small_roots(X=2^128, beta=0.4)      # roots mod a divisor ~ N^0.4
```

```python
# SageMath
# block matrices are the readable way to write a template
B = block_matrix(ZZ, [[identity_matrix(n), H], [zero_matrix(n), q*identity_matrix(n)]])
```

## fpylll

```sh
pip install fpylll            # needs fplll; conda-forge is far easier
conda create -n lat -c conda-forge fpylll python=3.11
sage -python -c "import fpylll; print(fpylll.__version__)"   # Sage ships it
```

```python
from fpylll import IntegerMatrix, LLL, BKZ, GSO, SVP, CVP, FPLLL
A = IntegerMatrix.from_matrix([[int(x) for x in row] for row in rows])
LLL.reduction(A)                                   # in place
BKZ.reduction(A, BKZ.Param(block_size=30))
out = [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)]
```

```python
# BKZ 2.0 with pruning and auto-abort, for the hard instances
from fpylll.algorithms.bkz2 import BKZReduction
BKZReduction(A)(BKZ.Param(block_size=45, max_loops=8, flags=BKZ.AUTO_ABORT|BKZ.GH_BND))
```

```python
# exact SVP / CVP and Babai
print(SVP.shortest_vector(A))
print(CVP.closest_vector(A, tuple(target)))
M = GSO.Mat(A); M.update_gso()
print(M.babai(tuple(target)))                      # coefficients of the close vector
print([M.get_r(i, i) for i in range(A.nrows)])     # squared GS norms: the profile
```

```python
# high precision when entries are huge
FPLLL.set_precision(200)
LLL.reduction(A, LLL.Wrapper(A))
```

```python
# random lattices for testing your pipeline
A = IntegerMatrix.random(40, "qary", k=20, bits=30)
A = IntegerMatrix.random(30, "uniform", bits=50)
```

## flatter (for big bases)

```sh
git clone https://github.com/keeganryan/flatter && cd flatter
mkdir build && cd build && cmake .. && make && sudo make install
# input/output use the Sage/fplll matrix format: [[a b][c d]]
flatter < basis.txt > reduced.txt
flatter -alpha 0.01 < basis.txt > reduced.txt
```

```python
# call it from Python on a Sage-format matrix
import subprocess
def flatter(rows):
    s = "[" + "".join("[" + " ".join(map(str, r)) + "]" for r in rows) + "]"
    out = subprocess.check_output(["flatter"], input=s.encode()).decode()
    return [[int(v) for v in line.split()] for line in
            out.strip().strip("[]").replace("[", "").split("]") if line.strip()]
```

## Babai, by hand

```python
# rounding: express the target in the reduced basis, round the coefficients
# nearest plane: project down the Gram-Schmidt vectors, one dimension at a time
def babai_nearest_plane(b, bs, target):        # b LLL-reduced, bs its GSO
    w = [Fraction(x) for x in target]
    for i in reversed(range(len(b))):
        d = sum(y*y for y in bs[i])
        c = round(sum(x*y for x, y in zip(w, bs[i])) / d)
        w = [x - c*y for x, y in zip(w, b[i])]
    return [int(t - x) for t, x in zip(target, w)]
```

```text
# rule of thumb: nearest plane beats rounding whenever the basis is skewed.
# If rounding gives a bad answer, try nearest plane before blaming the lattice.
```

## When LLL "does not work"

```text
1.  TRANSPOSED. Rows are basis vectors here. Papers often use columns.
2.  SCALING. One coordinate 2^200 and another 2^10 -> LLL ignores the small one.
    Multiply column j by C/X_j with integer weights.
3.  TARGET NOT SHORT. Compute sqrt(sum X_j^2) and compare with
    sqrt(dim/(2*pi*e)) * det^(1/dim). If the target is longer, no reduction helps:
    you need more samples/equations or tighter bounds.
4.  BOUNDS TOO LOOSE. Halving X often flips failure into success.
5.  NOT RECENTRED. Unknowns in [0, X) should become (-X/2, X/2): one free bit.
6.  ONLY CHECKED ROW 0. The answer is frequently in row 1, 2 or 3 -- and may be negated.
7.  SIGN ERROR in the constant term (u_i = -s^-1 h, not +).
8.  EMBEDDING CONSTANT M too small: the reduction reuses the target row. Set M ~ the
    expected coordinate size, not 1.
9.  CONGRUENCE COLUMN NOT WEIGHTED: LLL makes the residual small, not zero. Multiply
    those columns by a large W.
10. MODULUS ROWS MISSING. Without an n*e_i row the reduction cannot subtract the modulus.
11. BAD SAMPLE. One relation whose residual is not actually small destroys the lattice.
    Re-run on random subsets.
12. DIMENSION TOO SMALL: add samples. TOO LARGE: exact-arithmetic Python crawls past
    dim 40; switch to fpylll / flatter / Sage.
13. LLL NOT ENOUGH: BKZ with block_size 20 -> 30 -> 40. Each step costs a lot more.
14. NON-INTEGER WEIGHTS silently corrupt the lattice. Use C = prod X_j so C/X_j is exact.
15. NOT VERIFYING. Always plug the candidate back into the original equations; a short
    vector is not automatically your answer.
```

```python
# a debugging harness worth keeping
import math
def diagnose(rows, expected):
    dim = len(rows)
    det = abs(round(matrix_det(rows)))                 # any exact determinant routine
    gh = math.sqrt(dim / (2 * math.pi * math.e)) * det ** (1.0 / dim)
    tn = math.sqrt(sum(x * x for x in expected))
    print(f"dim={dim} det~2^{math.log2(det):.0f} GH~2^{math.log2(gh):.1f} "
          f"target~2^{math.log2(tn):.1f} ratio={tn/gh:.3f}")
    print("ratio < 1 means LLL has a real chance; > 1 means it does not")
```

```python
# print the Gram-Schmidt profile: a healthy reduction decays smoothly
M = GSO.Mat(A); M.update_gso()
print([round(math.log2(M.get_r(i, i)) / 2, 1) for i in range(A.nrows)])
# a cliff at position i means the first i vectors carry everything: usually good news
```

## Sizing table

| problem | dimension | practical limit |
|---|---|---|
| HNP with `m` samples | `m + 2` | `m` up to ~150 with fpylll |
| subset sum, `n` weights | `n + 1` | `n` up to ~250 with BKZ-30 |
| Coppersmith univariate, degree `d` | `d*m + t` | `dim` up to ~80 |
| truncated LCG, `t` outputs | `t` | trivial, `t` up to hundreds |
| NTRU, ring degree `N` | `2N` | `N` up to ~120 for full recovery |
| LWE, `m` samples | `m` | `m` up to ~150, then use BKZ/g6k |

## References

- https://github.com/fplll/fpylll
- https://github.com/keeganryan/flatter
- https://github.com/fplll/g6k (sieving, for the instances BKZ cannot reach)
- https://github.com/defund/coppersmith
- https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix_integer_dense.html
- Galbraith, *Mathematics of Public Key Cryptography*, chapters 16-19
