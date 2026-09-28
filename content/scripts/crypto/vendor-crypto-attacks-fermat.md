---
title: "Fermat (crypto-attacks)"
category: "crypto"
subcategory: "factorization"
type: "script"
tags: ["crypto-attacks", "factorization", "fermat", "crypto"]
summary: "fermat - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/fermat.py"
license: "MIT"
---

## What it does

`attacks/factorization/fermat.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/fermat.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/fermat.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/fermat.py
python3 vendor/crypto-attacks/attacks/factorization/fermat.py
```

## Code

```python
import os
import sys

from math import isqrt

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import is_square


def factorize(N):
    """
    Recovers the prime factors from a modulus using Fermat's factorization method.
    :param N: the modulus
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    a = isqrt(N)
    b = a * a - N
    while b < 0 or not is_square(b):
        a += 1
        b = a * a - N

    p = a - isqrt(b)
    q = N // p
    return p, q if p * q == N else None

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
