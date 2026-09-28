---
title: "Twin Primes (crypto-attacks)"
category: "crypto"
subcategory: "factorization"
type: "script"
tags: ["crypto-attacks", "factorization", "twin", "primes", "twin-primes", "crypto"]
summary: "twin primes - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/twin_primes.py"
license: "MIT"
---

## What it does

`attacks/factorization/twin_primes.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/twin_primes.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/twin_primes.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/twin_primes.py
python3 vendor/crypto-attacks/attacks/factorization/twin_primes.py
```

## Code

```python
from math import isqrt


def factorize(N):
    """
    Recovers the prime factors from a modulus if the factors are twin primes.
    :param N: the modulus
    :return: a tuple containing the prime factors, or None if there is no factorization
    """
    p = isqrt(N + 1) - 1
    q = isqrt(N + 1) + 1
    return p, q if p * q == N else None

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
