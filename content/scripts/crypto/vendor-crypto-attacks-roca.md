---
title: "Roca (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "factorization", "rsa", "coppersmith", "roca", "crypto"]
summary: "Algorithm 2."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/roca.py"
license: "MIT"
---

## What it does

Algorithm 2.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/roca.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/roca.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/roca.py
python3 vendor/crypto-attacks/attacks/factorization/roca.py
```

## Code

```python
import logging
import os
import sys
from math import log2

from sage.all import Zmod
from sage.all import factor

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import howgrave_graham


def _prime_power_divisors(M):
    divisors = []
    for p, e in factor(M):
        for i in range(1, e + 1):
            divisors.append(p ** i)

    divisors.sort()
    return divisors


# Algorithm 2.
def compute_max_M_(M, ord_):
    for p in _prime_power_divisors(M):
        ordp = Zmod(p)(65537).multiplicative_order()
        if ord_ % ordp != 0:
            M //= p

    return M


# Section 2.7.2.
def _greedy_find_M_(n, M):
    ord = Zmod(M)(65537).multiplicative_order()
    while True:
        best_r = 0
        best_ord_ = ord
        best_M_ = M
        for p in _prime_power_divisors(ord):
            ord_ = ord // p
            M_ = compute_max_M_(M, ord_)
            r = (log2(ord) - log2(ord_)) / (log2(M) - log2(M_))
            if r > best_r:
                best_r = r
                best_ord_ = ord_
                best_M_ = M_

        if log2(best_M_) < log2(n) / 4:
            return M

        ord = best_ord_
        M = best_M_


def factorize(N, M, m, t, g=65537):
    """
    Recovers the prime factors from a modulus using the ROCA method.
    More information: Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"
    :param N: the modulus
    :param M: the primorial used to generate the primes
    :param m: the m parameter for Coppersmith's method
    :param t: the t parameter for Coppersmith's method
    :param g: the generator value (default: 65537)
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    logging.info("Generating M'...")
    M_ = _greedy_find_M_(N, M)
    zmodm_ = Zmod(M_)
    g = zmodm_(g)
    c_ = zmodm_(N).log(g)
    ord_ = g.multiplicative_order()

    x = Zmod(N)["x"].gen()
    X = int(2 * N ** 0.5 // M_)
    logging.info("Starting exhaustive a' search...")
    for a_ in range(c_ // 2, (c_ + ord_) // 2 + 1):
        f = M_ * x + int(g ** a_)
        for k_, in howgrave_graham.modular_univariate(f, N, m, t, X):
            p = int(f(k_))
            if N % p == 0:
                return p, N // p

    return None

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
