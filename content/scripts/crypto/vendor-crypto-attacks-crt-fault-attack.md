---
title: "Crt Fault Attack (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "gcd", "sage", "chinese-remainder", "crt-fault-attack", "crypto"]
summary: "crt fault attack - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/crt_fault_attack.py"
license: "MIT"
---

## What it does

`attacks/rsa/crt_fault_attack.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/crt_fault_attack.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/crt_fault_attack.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/crt_fault_attack.py
python3 vendor/crypto-attacks/attacks/rsa/crt_fault_attack.py
```

## Code

```python
from math import gcd


def attack_known_m(n, e, m, s):
    """
    Recovers the prime factors from a modulus using a known message and its faulty signature.
    :param n: the modulus
    :param e: the public exponent
    :param m: the message
    :param s: the faulty signature
    :return: a tuple containing the prime factors, or None if the signature wasn't actually faulty
    """
    g = gcd(m - pow(s, e, n), n)
    return None if g == 1 else (g, n // g)


def attack_unknown_m(n, e, sv, sf):
    """
    Recovers the prime factors from a modulus using a correct valid and a faulty signature from the same (unknown) message.
    :param n: the modulus
    :param e: the public exponent
    :param sv: the valid signature
    :param sf: the faulty signature
    :return: a tuple containing the prime factors, or None if the signatures were both valid, or both faulty
    """
    assert sv != sf
    g = gcd(sv - sf, n)
    return None if g == 1 else (g, n // g)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
