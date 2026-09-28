---
title: "Shor (crypto-attacks)"
category: "crypto"
subcategory: "factorization"
type: "script"
tags: ["crypto-attacks", "factorization", "gcd", "shor", "crypto"]
summary: "shor - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/shor.py"
license: "MIT"
---

## What it does

`attacks/factorization/shor.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/shor.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/shor.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/shor.py
python3 vendor/crypto-attacks/attacks/factorization/shor.py
```

## Code

```python
from math import gcd

from sage.all import divisors


def factorize(N, a, s):
    """
    Recovers the prime factors from a modulus if the order of a mod n is known.
    More information: M. Johnston A., "Shor's Algorithm and Factoring: Don't Throw Away the Odd Orders"
    :param N: the modulus
    :param a: the base
    :param s: the order of a
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    assert pow(a, s, N) == 1, "s must be the order of a mod N"

    for r in divisors(s):
        b_r = pow(a, s // r, N)
        p = gcd(b_r - 1, N)
        if 1 < p < N and N % p == 0:
            return p, N // p

    return None

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
