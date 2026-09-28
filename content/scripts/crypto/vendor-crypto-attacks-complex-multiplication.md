---
title: "Complex Multiplication (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "factorization", "rsa", "ecc", "gcd", "complex-multiplication", "crypto"]
summary: "If some polynomial was not invertible during XGCD calculation, we can factor n."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/complex_multiplication.py"
license: "MIT"
---

## What it does

If some polynomial was not invertible during XGCD calculation, we can factor n.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/complex_multiplication.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/complex_multiplication.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/complex_multiplication.py
python3 vendor/crypto-attacks/attacks/factorization/complex_multiplication.py
```

## Code

```python
import logging
import os
import sys
from math import gcd

from sage.all import EllipticCurve
from sage.all import Zmod
from sage.all import hilbert_class_polynomial

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.polynomial import polynomial_inverse
from shared.polynomial import polynomial_xgcd


def factorize(N, D):
    """
    Recovers the prime factors from a modulus using Cheng's elliptic curve complex multiplication method.
    More information: Sedlacek V. et al., "I want to break square-free: The 4p - 1 factorization method and its RSA backdoor viability"
    :param N: the modulus
    :param D: the discriminant to use to generate the Hilbert polynomial
    :return: a tuple containing the prime factors
    """
    assert D % 8 == 3, "D should be square-free"

    zmodn = Zmod(N)
    pr = zmodn["x"]

    H = pr(hilbert_class_polynomial(-D))
    Q = pr.quotient(H)
    j = Q.gen()

    try:
        k = j * polynomial_inverse((1728 - j).lift(), H)
    except ArithmeticError as err:
        # If some polynomial was not invertible during XGCD calculation, we can factor n.
        p = gcd(int(err.args[1].lc()), N)
        return int(p), int(N // p)

    E = EllipticCurve(Q, [3 * k, 2 * k])
    while True:
        x = zmodn.random_element()

        logging.debug(f"Calculating division polynomial of Q{x}...")
        z = E.division_polynomial(N, x=Q(x))

        try:
            d, _, _ = polynomial_xgcd(z.lift(), H)
        except ArithmeticError as err:
            # If some polynomial was not invertible during XGCD calculation, we can factor n.
            p = gcd(int(err.args[1].lc()), N)
            return int(p), int(N // p)

        p = gcd(int(d), N)
        if 1 < p < N:
            return int(p), int(N // p)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
