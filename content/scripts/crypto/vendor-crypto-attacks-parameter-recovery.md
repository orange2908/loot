---
title: "Parameter Recovery (crypto-attacks)"
category: "crypto"
subcategory: "prng"
type: "script"
tags: ["crypto-attacks", "lcg", "gcd", "parameter", "recovery", "parameter-recovery", "crypto"]
summary: "parameter recovery - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/lcg/parameter_recovery.py"
license: "MIT"
---

## What it does

`attacks/lcg/parameter_recovery.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/lcg/parameter_recovery.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/lcg/parameter_recovery.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/lcg/parameter_recovery.py
python3 vendor/crypto-attacks/attacks/lcg/parameter_recovery.py
```

## Code

```python
from math import gcd

from sage.all import GF
from sage.all import is_prime_power


def attack(y, m=None, a=None, c=None):
    """
    Recovers the parameters from a linear congruential generator.
    If no modulus is provided, attempts to recover the modulus from the outputs (may require many outputs).
    If no multiplier is provided, attempts to recover the multiplier from the outputs (requires at least 3 outputs).
    If no increment is provided, attempts to recover the increment from the outputs (requires at least 2 outputs).
    :param y: the sequential output values obtained from the LCG
    :param m: the modulus of the LCG (can be None)
    :param a: the multiplier of the LCG (can be None)
    :param c: the increment of the LCG (can be None)
    :return: a tuple containing the modulus, multiplier, and the increment
    """
    if m is None:
        assert len(y) >= 4, "At least 4 outputs are required to recover the modulus"
        for i in range(len(y) - 3):
            d0 = y[i + 1] - y[i]
            d1 = y[i + 2] - y[i + 1]
            d2 = y[i + 3] - y[i + 2]
            g = d2 * d0 - d1 * d1
            m = g if m is None else gcd(g, m)

        assert is_prime_power(m), "Modulus must be a prime power, try providing more outputs"

    gf = GF(m)
    if a is None:
        assert len(y) >= 3, "At least 3 outputs are required to recover the multiplier"
        x0 = gf(y[0])
        x1 = gf(y[1])
        x2 = gf(y[2])
        a = int((x2 - x1) / (x1 - x0))

    if c is None:
        assert len(y) >= 2, "At least 2 outputs are required to recover the multiplier"
        x0 = gf(y[0])
        x1 = gf(y[1])
        c = int(x1 - a * x0)

    return m, a, c

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
