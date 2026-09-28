---
title: "Singular Curve (crypto-attacks)"
category: "crypto"
subcategory: "ecc"
type: "script"
tags: ["crypto-attacks", "ecc", "discrete-log", "singular-curve", "singular", "curve", "crypto"]
summary: "Singular point is a cusp."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ecc/singular_curve.py"
license: "MIT"
---

## What it does

Singular point is a cusp.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ecc/singular_curve.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ecc/singular_curve.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ecc/singular_curve.py
python3 vendor/crypto-attacks/attacks/ecc/singular_curve.py
```

## Code

```python
from sage.all import GF


def attack(p, a2, a4, a6, Gx, Gy, Px, Py):
    """
    Solves the discrete logarithm problem on a singular curve (y^2 = x^3 + a2 * x^2 + a4 * x + a6).
    :param p: the prime of the curve base ring
    :param a2: the a2 parameter of the curve
    :param a4: the a4 parameter of the curve
    :param a6: the a6 parameter of the curve
    :param Gx: the base point x value
    :param Gy: the base point y value
    :param Px: the point multiplication result x value
    :param Py: the point multiplication result y value
    :return: l such that l * G == P
    """
    x = GF(p)["x"].gen()
    f = x ** 3 + a2 * x ** 2 + a4 * x + a6
    roots = f.roots()

    # Singular point is a cusp.
    if len(roots) == 1:
        alpha = roots[0][0]
        u = (Gx - alpha) / Gy
        v = (Px - alpha) / Py
        return int(v / u)

    # Singular point is a node.
    if len(roots) == 2:
        if roots[0][1] == 2:
            alpha = roots[0][0]
            beta = roots[1][0]
        elif roots[1][1] == 2:
            alpha = roots[1][0]
            beta = roots[0][0]
        else:
            raise ValueError("Expected root with multiplicity 2.")

        t = (alpha - beta).sqrt()
        u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha))
        v = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
        return int(v.log(u))

    raise ValueError(f"Unexpected number of roots {len(roots)}.")

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
