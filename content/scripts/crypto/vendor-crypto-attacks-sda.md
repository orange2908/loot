---
title: "Sda (crypto-attacks)"
category: "crypto"
subcategory: "lattice"
type: "script"
tags: ["crypto-attacks", "acd", "lattice", "sda", "crypto"]
summary: "sda - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/acd/sda.py"
license: "MIT"
---

## What it does

`attacks/acd/sda.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/acd/sda.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/acd/sda.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/acd/sda.py
python3 vendor/crypto-attacks/attacks/acd/sda.py
```

## Code

```python
import os
import sys

from sage.all import ZZ
from sage.all import matrix

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import symmetric_mod
from shared.lattice import shortest_vectors


def attack(x, rho):
    """
    Solves the ACD problem using the simultaneous Diophantine approximation approach.
    More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 3)
    :param x: the x samples, with xi = p * qi + ri
    :param rho: the bit length of the r values
    :return: the secret integer p and a list containing the r values, or None if p could not be found
    """
    assert len(x) >= 2, "At least two x values are required."

    R = 2 ** (rho + 1)

    B = matrix(ZZ, len(x), len(x))
    B[0, 0] = R
    for i in range(1, len(x)):
        B[0, i] = x[i]
        B[i, i] = -x[0]

    for v in shortest_vectors(B):
        if v[0] != 0 and v[0] % R == 0:
            q0 = v[0] // R
            r0 = symmetric_mod(x[0], q0)
            p = abs((x[0] - r0) // q0)
            r = [symmetric_mod(xi, p) for xi in x]
            if all(-R < ri < R for ri in r):
                return int(p), r

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
