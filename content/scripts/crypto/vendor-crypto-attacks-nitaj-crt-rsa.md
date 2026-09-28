---
title: "Nitaj Crt Rsa (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "gcd", "coppersmith", "chinese-remainder", "nitaj-crt-rsa", "crypto"]
summary: "nitaj crt rsa - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/nitaj_crt_rsa.py"
license: "MIT"
---

## What it does

`attacks/rsa/nitaj_crt_rsa.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/nitaj_crt_rsa.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/nitaj_crt_rsa.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/nitaj_crt_rsa.py
python3 vendor/crypto-attacks/attacks/rsa/nitaj_crt_rsa.py
```

## Code

```python
import logging
import os
import sys
from math import gcd
from math import log
from math import sqrt

from sage.all import RR
from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import herrmann_may_multivariate


def attack(N, e, delta, m, t, check_bounds=True):
    """
    Recovers the prime factors if one of the CRT-RSA private exponents is too small.
    More information: Nitaj A., "A new attack on RSA and CRT-RSA" (Section 4)
    :param N: the modulus
    :param e: the public exponent
    :param delta: the parameter delta such that dp <= N^delta
    :param m: the parameter m for small roots
    :param t: the parameter t for small roots
    :param check_bounds: perform bounds check (default: True)
    :return: a tuple containing the prime factors, or None if the factors could not be found
    """
    alpha = log(e, N)
    assert not check_bounds or 2 * delta < sqrt(2) / 2 - alpha, f"Bounds check failed ({2 * delta} < {sqrt(2) / 2 - alpha})."

    x, y = Zmod(N)["x", "y"].gens()
    f = x + e * y
    X = int(RR(N) ** delta)
    Y = int(e * RR(N) ** (delta - 1 / 2))  # Equivalent to N^(alpha + delta - 1 / 2)
    logging.info(f"Trying {m = }, {t = }...")
    for x0, y0 in herrmann_may_multivariate.modular_multivariate(f, N, m, t, [X, Y]):
        pz = int(f(x0, y0))
        p = gcd(pz, N)
        if 1 < p < N and N % p == 0:
            return p, N // p

    return None

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
