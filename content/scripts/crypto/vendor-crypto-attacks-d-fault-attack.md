---
title: "D Fault Attack (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "bit-flipping", "fault", "attack", "d-fault-attack", "crypto"]
summary: "d fault attack - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/d_fault_attack.py"
license: "MIT"
---

## What it does

`attacks/rsa/d_fault_attack.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/d_fault_attack.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/d_fault_attack.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/d_fault_attack.py
python3 vendor/crypto-attacks/attacks/rsa/d_fault_attack.py
```

## Code

```python
import os
import sys

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.partial_integer import PartialInteger


def attack(n, e, sv, sf):
    """
    Recovers the bits of the private exponent d that were flipped during generation of signatures.
    More faulty signatures reveal more bits of d, assuming the bit flip positions are different.
    :param n: the modulus
    :param e: the public exponent
    :param sv: the valid signature
    :param sf: the list of faulty signatures: for each entry in this list, at most one bit in d should have been flipped during signature generation
    :return: a PartialInteger containing the known and unknown bits of d
    """
    d_bits = [None] * n.bit_length()
    m = 2
    mi = {pow(m, 2 ** i, n): i for i in range(n.bit_length())}
    for sfi in sf:
        di0 = pow(sv, -1, n) * sfi % n
        di1 = sv * pow(sfi, -1, n) % n
        if di0 in mi:
            d_bits[mi[di0]] = 0
        if di1 in mi:
            d_bits[mi[di1]] = 1

    return PartialInteger.from_bits_le(d_bits)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
