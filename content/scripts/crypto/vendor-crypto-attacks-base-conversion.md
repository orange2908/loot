---
title: "Base Conversion (crypto-attacks)"
category: "crypto"
subcategory: "factorization"
type: "script"
tags: ["crypto-attacks", "factorization", "base", "conversion", "base-conversion", "crypto"]
summary: "base conversion - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/base_conversion.py"
license: "MIT"
---

## What it does

`attacks/factorization/base_conversion.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/base_conversion.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/base_conversion.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/base_conversion.py
python3 vendor/crypto-attacks/attacks/factorization/base_conversion.py
```

## Code

```python
import logging

from sage.all import ZZ


def factorize(N, coefficient_threshold=32):
    """
    Recovers the prime factors from a modulus by converting it to different bases.
    :param N: the modulus
    :param coefficient_threshold: the threshold of coefficients below which we will try to factor a base k polynomial
    :return: a tuple containing the prime factors
    """
    R = ZZ["x"]
    base = 2
    while True:
        logging.debug(f"Trying {base = }...")
        poly = R(ZZ(N).digits(base))
        logging.debug(f"Got {len(poly.coefficients())} coefficients")
        if len(poly.coefficients()) < coefficient_threshold:
            facs = poly.factor()
            return tuple(map(lambda f: int(f[0](base)), facs))

        base += 1


def factorize_base_2x(N):
    """
    Recovers the prime factors from a modulus by converting it to different bases of the form 2^x.
    :param N: the modulus
    :return: a tuple containing the prime factors
    """
    R = ZZ["x"]
    base = 2
    while True:
        logging.debug(f"Trying {base = }...")
        poly = R(ZZ(N).digits(base))
        facs = poly.factor()
        if len(facs) > 1:
            return tuple(map(lambda f: int(f[0](base)), facs))

        base *= 2

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
