---
title: "Bleichenbacher Signature Forgery (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "bleichenbacher", "signature", "forgery", "bleichenbacher-signature-forgery", "crypto"]
summary: "bleichenbacher signature forgery - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/bleichenbacher_signature_forgery.py"
license: "MIT"
---

## What it does

`attacks/rsa/bleichenbacher_signature_forgery.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/bleichenbacher_signature_forgery.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/bleichenbacher_signature_forgery.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/bleichenbacher_signature_forgery.py
python3 vendor/crypto-attacks/attacks/rsa/bleichenbacher_signature_forgery.py
```

## Code

```python
def attack(suffix, suffix_bit_length):
    """
    Returns a number s for which s^3 ends with the provided suffix.
    :param suffix: the suffix
    :param suffix_bit_length: the bit length of the suffix
    :return: the number s
    """
    assert suffix % 2 == 1, "Target suffix must be odd"

    s = 1
    for i in range(suffix_bit_length):
        if (((s ** 3) >> i) & 1) != ((suffix >> i) & 1):
            s |= (1 << i)

    return s

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
