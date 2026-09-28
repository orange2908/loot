---
title: "Hastad Attack (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "gcd", "hastad", "chinese-remainder", "hastad-attack", "crypto"]
summary: "hastad attack - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/hastad_attack.py"
license: "MIT"
---

## What it does

`attacks/rsa/hastad_attack.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/hastad_attack.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/hastad_attack.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/hastad_attack.py
python3 vendor/crypto-attacks/attacks/rsa/hastad_attack.py
```

## Code

```python
import os
import sys
from math import gcd

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.rsa import low_exponent
from shared.crt import fast_crt


def attack(N, e, c):
    """
    Recovers the plaintext from e ciphertexts, encrypted using different moduli and the same public exponent.
    :param N: the moduli
    :param e: the public exponent
    :param c: the ciphertexts
    :return: the plaintext
    """
    assert e == len(N) == len(c), "The amount of ciphertexts should be equal to e."

    for i in range(len(N)):
        for j in range(len(N)):
            if i != j and gcd(N[i], N[j]) != 1:
                raise ValueError(f"Modulus {i} and {j} share factors, Hastad's attack is impossible.")

    c, _ = fast_crt(c, N)
    return low_exponent.attack(e, c)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
