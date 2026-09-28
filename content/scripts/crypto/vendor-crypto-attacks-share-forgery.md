---
title: "Share Forgery (crypto-attacks)"
category: "crypto"
subcategory: "shamir-secret-sharing"
type: "script"
tags: ["crypto-attacks", "shamir-secret-sharing", "share", "forgery", "share-forgery", "crypto"]
summary: "share forgery - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/shamir_secret_sharing/share_forgery.py"
license: "MIT"
---

## What it does

`attacks/shamir_secret_sharing/share_forgery.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/shamir_secret_sharing/share_forgery.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/shamir_secret_sharing/share_forgery.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/shamir_secret_sharing/share_forgery.py
python3 vendor/crypto-attacks/attacks/shamir_secret_sharing/share_forgery.py
```

## Code

```python
def attack(p, s, s_, x, y, xs):
    """
    Forges a share to recombine into a new shared secret, s', if a single share and the x coordinates of the other participants are given.
    :param p: the prime used for Shamir's secret sharing
    :param s: the original shared secret
    :param s_: the target shared secret, s'
    :param x: the x coordinate of the given share
    :param y: the y coordinate of the given share
    :param xs: the x coordinates of the other participants (excluding the x coordinate of the given share)
    :return: the forged share
    """
    const = 1
    for i in xs:
        const *= i * pow(i - x, -1, p)

    return ((s_ - s) * pow(const, -1, p) + y) % p

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
