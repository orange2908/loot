---
title: "Hill Cipher - Known-Plaintext Key Recovery by Matrix Inversion mod 26"
category: crypto
subcategory: classical
type: technique
tags: [hill-cipher, hill, matrix-cipher, linear-algebra, known-plaintext, matrix-inverse, modular-inverse, determinant, adjugate, cofactor, mod-26, sympy, numpy, sage, polygraphic, classical-cipher]
difficulty: medium
summary: "Hill is linear: n*n known plaintext/ciphertext letters give a solvable matrix equation K = C * P^-1 mod 26, recovering the key outright."
when_to_use:
  - "Ciphertext length is a multiple of n (2, 3 or 4) and the alphabet is A-Z"
  - "Identical plaintext blocks map to identical ciphertext blocks, but single letters do not"
  - "You have or can guess n*n letters of plaintext (a flag prefix, a header, 'THE')"
  - "Challenge source shows a matrix multiplication mod 26"
tools: [python, sympy, numpy, sage, dcode]
related: [classical-transposition, classical-substitution-hillclimb, cipher-identification]
---

## TL;DR

Hill encrypts an $n$-letter block as a vector-matrix product mod 26. Because it is
**linear**, $n$ known plaintext blocks (i.e. $n^2$ letters) give you $K = C P^{-1}
\bmod 26$ and the whole key falls out in one step. Without known plaintext, a 2x2 key
is brute-forceable ($26^4 \approx 4.6 \times 10^5$ matrices, ~157k of them invertible)
and a 3x3 key is attacked by hill climbing or by guessing cribs.

## Recognise it

- Length is a clean multiple of 2, 3 or 4 (padding letter `X`/`Z` at the end).
- IoC is low (~0.04-0.05): polygraphic substitution flattens single-letter stats.
- Repeated **blocks** (aligned, length n) produce repeated ciphertext blocks. Repeated
  *letters* do not. That is the clean distinguisher from Playfair (which is 2-letter
  too, but never encrypts a doubled letter and never outputs `J`).
- Source code mentions `numpy`, `matrix`, `% 26`, `det`, `inv`.
- A `J` appears - rules out Playfair, consistent with Hill.

## Theory

Letters as $0..25$. Split the plaintext into column vectors $p$ of length $n$:
$$c = K p \pmod{26}, \qquad p = K^{-1} c \pmod{26}$$

$K$ is invertible mod 26 iff $\gcd(\det K, 26) = 1$, i.e. $\det K$ is odd and not
divisible by 13.

**Inverse mod 26.** Use the adjugate:
$$K^{-1} = (\det K)^{-1} \cdot \mathrm{adj}(K) \pmod{26}$$
where $\mathrm{adj}(K)_{ij} = (-1)^{i+j} M_{ji}$ and $M_{ji}$ is the $(j,i)$ minor.
All arithmetic stays in $\mathbb{Z}$; only the final $(\det K)^{-1}$ is a modular
inverse. Avoid floating-point `numpy.linalg.inv` - it will silently destroy you.

**Known-plaintext recovery.** Stack $n$ plaintext blocks as the columns of an
$n \times n$ matrix $P$ and their ciphertexts as the columns of $C$. Then
$$C = K P \pmod{26} \implies K = C P^{-1} \pmod{26}$$
provided $P$ itself is invertible mod 26. If your first $n$ blocks give a singular
$P$, slide the window: take blocks $1..n$, then $2..n+1$, and so on, until one works.

**Ciphertext-only.** For $n=2$: enumerate all invertible 2x2 matrices (157,248 of
them) and score the decryption. For $n=3$ full enumeration is $26^9$ - infeasible -
so hill-climb over matrices (random entry perturbations, keeping invertibility) with
an n-gram score, or crib-drag a guessed 9-letter plaintext.

**Affine Hill** adds a constant vector: $c = Kp + b$. Subtract two known pairs to
eliminate $b$, recover $K$ from the differences, then $b = c - Kp$.

## Attack

1. Determine $n$: try the divisors of the ciphertext length that are 2, 3, 4, 5.
2. Get a crib. Common cribs: `FLAG`, `CTF`, `THEFLAGIS`, the challenge title, the
   first word of a known quote. Pad it to a multiple of $n$.
3. Build $P$ and $C$ from aligned blocks; find a window where $\gcd(\det P, 26)=1$.
4. $K = C P^{-1} \bmod 26$. Verify by decrypting the whole message.
5. No crib and $n=2$? Brute force all invertible 2x2 matrices with n-gram scoring.
6. No crib and $n=3$? Hill-climb, or guess that the key matrix was built from a
   keyword (`"GYBNQKURP"` style - letters laid out row-major), and brute force a
   wordlist of 9-letter words.

## Code

```python
#!/usr/bin/env python3
"""Hill cipher: encrypt/decrypt, exact matrix inverse mod 26, known-plaintext key
recovery, and a 2x2 ciphertext-only brute force. Pure stdlib. Self-testing."""
from __future__ import annotations

import math
import string
from collections import Counter
from itertools import product

ALPHA = string.ascii_uppercase
M = 26

# --- small embedded English model for scoring brute-force candidates -------
_CORPUS = (
    "the quick brown fox jumps over the lazy dog and then returns to the river "
    "bank where it rests for a while before going home again the history of the "
    "world is in many ways the history of the ordinary people who lived through "
    "it and not only of the kings and generals whose names are written in books "
    "that children read at school in every village there were farmers who watched "
    "the weather and the price of grain and children who learned to count the days "
    "until the harvest they did not think of themselves as living in a period that "
    "would one day be given a name by scholars they thought about the rain and the "
    "road to the market and whether there would be enough bread in the house"
)


def clean(t: str) -> str:
    return "".join(c for c in t.upper() if c in ALPHA)


def _model(n: int):
    s = clean(_CORPUS)
    c = Counter(s[i:i + n] for i in range(len(s) - n + 1))
    tot, vocab = sum(c.values()), 26 ** n
    return ({g: math.log10((v + 1) / (tot + vocab)) for g, v in c.items()},
            math.log10(1 / (tot + vocab)))


_TRI, _TRIF = _model(3)


def eng_score(s: str) -> float:
    s = clean(s)
    if len(s) < 3:
        return -1e9
    return sum(_TRI.get(s[i:i + 3], _TRIF) for i in range(len(s) - 2))


# ------------------------- exact integer matrix helpers --------------------
def minor(mat, i, j):
    return [row[:j] + row[j + 1:] for k, row in enumerate(mat) if k != i]


def det_int(mat) -> int:
    n = len(mat)
    if n == 1:
        return mat[0][0]
    if n == 2:
        return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]
    return sum((-1) ** j * mat[0][j] * det_int(minor(mat, 0, j)) for j in range(n))


def adjugate(mat):
    n = len(mat)
    if n == 1:
        return [[1]]
    return [[((-1) ** (i + j)) * det_int(minor(mat, j, i)) for j in range(n)]
            for i in range(n)]


def mat_inv_mod(mat, m: int = M):
    """Exact inverse mod m via adjugate. Raises if not invertible."""
    d = det_int(mat) % m
    if math.gcd(d, m) != 1:
        raise ValueError(f"determinant {d} is not invertible mod {m}")
    d_inv = pow(d, -1, m)
    adj = adjugate(mat)
    return [[(d_inv * v) % m for v in row] for row in adj]


def mat_mul_mod(a, b, m: int = M):
    n, p, q = len(a), len(b), len(b[0])
    return [[sum(a[i][k] * b[k][j] for k in range(p)) % m for j in range(q)]
            for i in range(n)]


def is_invertible(mat, m: int = M) -> bool:
    return math.gcd(det_int(mat) % m, m) == 1


# ------------------------------ the cipher ---------------------------------
def hill_encrypt(pt: str, key, pad: str = "X") -> str:
    n = len(key)
    s = clean(pt)
    if len(s) % n:
        s += pad * (n - len(s) % n)
    out = []
    for i in range(0, len(s), n):
        vec = [[ord(c) - 65] for c in s[i:i + n]]
        res = mat_mul_mod(key, vec)
        out += [chr(r[0] + 65) for r in res]
    return "".join(out)


def hill_decrypt(ct: str, key) -> str:
    return hill_encrypt(ct, mat_inv_mod(key))


def key_from_keyword(word: str, n: int):
    s = clean(word)
    if len(s) != n * n:
        raise ValueError(f"keyword must be exactly {n*n} letters")
    return [[ord(s[i * n + j]) - 65 for j in range(n)] for i in range(n)]


# ------------------- known-plaintext key recovery --------------------------
def recover_key_known_plaintext(pt: str, ct: str, n: int):
    """K = C * P^-1 mod 26. Slides the block window until P is invertible."""
    p, c = clean(pt), clean(ct)
    nblocks = min(len(p), len(c)) // n
    if nblocks < n:
        raise ValueError(f"need at least {n*n} known letters, have {min(len(p),len(c))}")
    for start in range(nblocks - n + 1):
        cols = range(start, start + n)
        P = [[ord(p[b * n + r]) - 65 for b in cols] for r in range(n)]
        C = [[ord(c[b * n + r]) - 65 for b in cols] for r in range(n)]
        if not is_invertible(P):
            continue
        return mat_mul_mod(C, mat_inv_mod(P))
    raise ValueError("no window of n blocks gave an invertible plaintext matrix")


def recover_affine_hill(pt: str, ct: str, n: int):
    """Affine Hill c = K p + b. Differences kill b, then solve for b."""
    p, c = clean(pt), clean(ct)
    nblocks = min(len(p), len(c)) // n
    if nblocks < n + 1:
        raise ValueError(f"need {n+1} blocks for affine Hill")
    def block(s, i):
        return [ord(s[i * n + r]) - 65 for r in range(n)]
    base_p, base_c = block(p, 0), block(c, 0)
    for start in range(1, nblocks - n + 1):
        cols = range(start, start + n)
        P = [[(block(p, b)[r] - base_p[r]) % M for b in cols] for r in range(n)]
        C = [[(block(c, b)[r] - base_c[r]) % M for b in cols] for r in range(n)]
        if not is_invertible(P):
            continue
        K = mat_mul_mod(C, mat_inv_mod(P))
        Kp = mat_mul_mod(K, [[v] for v in base_p])
        b = [(base_c[r] - Kp[r][0]) % M for r in range(n)]
        return K, b
    raise ValueError("no invertible difference matrix found")


def affine_hill_encrypt(pt: str, key, b, pad: str = "X") -> str:
    n = len(key)
    s = clean(pt)
    if len(s) % n:
        s += pad * (n - len(s) % n)
    out = []
    for i in range(0, len(s), n):
        vec = [[ord(ch) - 65] for ch in s[i:i + n]]
        res = mat_mul_mod(key, vec)
        out += [chr((res[r][0] + b[r]) % M + 65) for r in range(n)]
    return "".join(out)


# ------------------ ciphertext-only brute force (n = 2) --------------------
def brute_force_2x2(ct: str, top: int = 3, limit: int | None = None):
    """Enumerate invertible 2x2 keys and rank decryptions. ~157k keys."""
    results = []
    tried = 0
    for a, b, c, d in product(range(M), repeat=4):
        det = (a * d - b * c) % M
        if math.gcd(det, M) != 1:
            continue
        tried += 1
        if limit and tried > limit:
            break
        key = [[a, b], [c, d]]
        try:
            pt = hill_decrypt(ct, key)
        except ValueError:
            continue
        results.append((eng_score(pt), key, pt))
    results.sort(key=lambda t: -t[0])
    return results[:top]


if __name__ == "__main__":
    # --- 2x2 round trip and inverse --------------------------------------
    k2 = [[3, 3], [2, 5]]                     # det = 9, gcd(9,26)=1
    assert is_invertible(k2)
    inv2 = mat_inv_mod(k2)
    assert mat_mul_mod(k2, inv2) == [[1, 0], [0, 1]], inv2
    ct = hill_encrypt("HELP", k2)
    assert ct == "HIAT", ct                   # classic textbook vector
    assert hill_decrypt(ct, k2) == "HELP"
    print(f"[ok] 2x2 hill round trip: HELP -> {ct} -> HELP")

    # --- 3x3 round trip ---------------------------------------------------
    k3 = key_from_keyword("GYBNQKURP", 3)     # the standard Wikipedia example key
    assert is_invertible(k3)
    msg = "ACT"
    assert hill_encrypt(msg, k3) == "POH", hill_encrypt(msg, k3)
    long_pt = "THEFLAGISHILLCIPHERSAREJUSTLINEARALGEBRA"
    ct3 = hill_encrypt(long_pt, k3)
    assert hill_decrypt(ct3, k3).startswith(long_pt)
    print(f"[ok] 3x3 hill round trip, key from keyword GYBNQKURP")

    # --- known-plaintext key recovery (3x3) -------------------------------
    # 18 letters = 6 blocks: the first two windows are singular, the third works,
    # which is exactly why the recovery slides its window.
    crib = long_pt[:18]
    rec = recover_key_known_plaintext(crib, ct3[:18], 3)
    assert rec == k3, (rec, k3)
    print(f"[ok] recovered 3x3 key from {len(crib)} known letters: {rec}")

    # --- known-plaintext key recovery (2x2) -------------------------------
    ct2 = hill_encrypt(long_pt, k2)
    assert recover_key_known_plaintext(long_pt[:4], ct2[:4], 2) == k2
    print("[ok] recovered 2x2 key from 4 known letters")

    # --- affine Hill ------------------------------------------------------
    bvec = [7, 11]
    act = affine_hill_encrypt(long_pt, k2, bvec)
    K, b = recover_affine_hill(long_pt[:10], act[:10], 2)
    assert K == k2 and b == bvec, (K, b)
    print(f"[ok] recovered affine Hill key {K} and shift {b}")

    # --- ciphertext-only 2x2 brute force ---------------------------------
    target = "THEARTOFWARTEACHESUSTORELYNOTONTHELIKELIHOODOFTHEENEMYNOTCOMING"
    ct_bf = hill_encrypt(target, k2)
    best = brute_force_2x2(ct_bf, top=3)
    assert best[0][1] == k2, best[0][1]
    assert best[0][2].startswith("THEARTOFWAR")
    print(f"[ok] 2x2 brute force recovered {best[0][1]}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Never use floating point.** `numpy.linalg.inv` then `% 26` gives wrong answers.
  Use the adjugate over integers, or `sympy.Matrix(K).inv_mod(26)`, or Sage's
  `Matrix(Zmod(26), K).inverse()`.
- **Non-invertible key.** If $\gcd(\det K, 26) \ne 1$ the cipher is not decryptable -
  the challenge author either used a different modulus (mod 29, mod 31, mod 256) or a
  different alphabet size. Check for digits/underscores in the charset.
- **Mod 29 / mod 37 / mod 256 variants.** 29 and 31 are prime, so *every* nonzero
  determinant is invertible - authors like that. Parameterise `M` in the code.
- **Row-vector vs column-vector convention.** Some implementations compute $pK$ rather
  than $Kp$. If your recovered key decrypts to garbage, transpose it.
- **Padding letters.** `X`, `Z`, or `A` at the tail; strip them after decrypting.
- **Singular known-plaintext matrix.** Very common with cribs like `THETHETHE`. Slide
  the window (the code does this) or mix in blocks from elsewhere in the message.
- **Hill is malleable.** $E(p_1) + E(p_2) = E(p_1 + p_2)$ with no constant term, which
  means a chosen-plaintext oracle leaks the key columns directly: encrypt the unit
  vectors `BAA`, `ABA`, `AAB`... and read the key off the outputs.
- **Key from a keyword.** `GYBNQKURP`, `DDCF`, `HILLCIPHR` - if the recovered matrix
  maps back to readable letters, that word is often the flag.

## Tools

- **sympy**: `Matrix(K).inv_mod(26)` - exact and one line.
- **SageMath**: `M = Matrix(Zmod(26), K); M.inverse()`, plus `M.det()` in `Zmod(26)`.
- **dcode.fr Hill cipher** - encrypt/decrypt with a key, and a known-plaintext solver.
- **CrypTool 2** - Hill cipher component with analysis.
- **numpy** - fine for the multiplication, dangerous for the inverse.

## References

- dcode.fr Hill cipher - <https://www.dcode.fr/hill-cipher>
- Practical Cryptography, "Hill Cipher" - <http://practicalcryptography.com/ciphers/hill-cipher/>
- SymPy matrices documentation - <https://docs.sympy.org/latest/modules/matrices/matrices.html>
