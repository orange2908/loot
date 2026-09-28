---
title: "Deterministic Coefficients (crypto-attacks)"
category: "crypto"
subcategory: "shamir-secret-sharing"
type: "script"
tags: ["crypto-attacks", "shamir-secret-sharing", "deterministic", "coefficients", "deterministic-coefficients", "crypto"]
summary: "deterministic coefficients - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/shamir_secret_sharing/deterministic_coefficients.py"
license: "MIT"
---

## What it does

`attacks/shamir_secret_sharing/deterministic_coefficients.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/shamir_secret_sharing/deterministic_coefficients.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/shamir_secret_sharing/deterministic_coefficients.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/shamir_secret_sharing/deterministic_coefficients.py
python3 vendor/crypto-attacks/attacks/shamir_secret_sharing/deterministic_coefficients.py
```

## Code

```python
def attack(p, k, a1, f, x, y):
    """
    Recovers the shared secret if the coefficients are generated deterministically, and a single share is given.
    :param p: the prime used for Shamir's secret sharing
    :param k: the amount of shares needed to unlock the secret
    :param a1: the first coefficient of the polynomial
    :param f: a function which takes a coefficient and returns the next coefficient in the polynomial
    :param x: the x coordinate of the given share
    :param y: the y coordinate of the given share
    :return: the shared secret
    """
    s = y
    a = a1
    for i in range(1, k):
        s -= a * x ** i
        a = f(a)

    return s % p

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
