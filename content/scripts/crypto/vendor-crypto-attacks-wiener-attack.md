---
title: "Wiener Attack (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "wiener", "attack", "wiener-attack", "crypto"]
summary: "wiener attack - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/wiener_attack.py"
license: "MIT"
---

## What it does

`attacks/rsa/wiener_attack.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/wiener_attack.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/wiener_attack.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/wiener_attack.py
python3 vendor/crypto-attacks/attacks/rsa/wiener_attack.py
```

## Code

```python
import os
import sys

from sage.all import ZZ
from sage.all import continued_fraction

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi


def attack(N, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    :param N: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors and the private exponent, or None if the private exponent was not found
    """
    convergents = continued_fraction(ZZ(e) / ZZ(N)).convergents()
    for c in convergents:
        k = c.numerator()
        d = c.denominator()
        if pow(pow(2, e, N), d, N) != 2:
            continue

        phi = (e * d - 1) // k
        factors = known_phi.factorize(N, phi)
        if factors:
            return *factors, int(d)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
