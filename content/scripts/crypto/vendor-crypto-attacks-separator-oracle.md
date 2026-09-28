---
title: "Separator Oracle (crypto-attacks)"
category: "crypto"
subcategory: "ctr"
type: "script"
tags: ["crypto-attacks", "ctr", "separator", "oracle", "separator-oracle", "crypto"]
summary: "Ensure that at least 1 separator is missing."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ctr/separator_oracle.py"
license: "MIT"
---

## What it does

Ensure that at least 1 separator is missing.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ctr/separator_oracle.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ctr/separator_oracle.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ctr/separator_oracle.py
python3 vendor/crypto-attacks/attacks/ctr/separator_oracle.py
```

## Code

```python
def _find_separator_positions(separator_oracle, c):
    separator_positions = []
    c = bytearray(c)
    for i in range(len(c)):
        c[i] ^= 1
        valid = separator_oracle(c)
        c[i] ^= 1
        if not valid:
            c[i] ^= 2
            valid = separator_oracle(c)
            c[i] ^= 2
            if not valid:
                separator_positions.append(i)

    return separator_positions


def attack(separator_oracle, separator_byte, c):
    """
    Recovers the plaintext using the separator oracle attack.
    :param separator_oracle: the separator oracle, returns True if the separators are correct, False otherwise
    :param separator_byte: the separator which is used in the separator oracle
    :param c: the ciphertext
    :return: the plaintext
    """
    separator_positions = _find_separator_positions(separator_oracle, c)
    c = bytearray(c)
    # Ensure that at least 1 separator is missing.
    c[separator_positions[0]] ^= 1
    p = bytearray(len(c))
    for i in range(len(c)):
        if i in separator_positions:
            p[i] = separator_byte
        else:
            c_i = c[i]
            # Try every byte until an additional separator is created.
            for b in range(256):
                c[i] = b
                if separator_oracle(c):
                    p[i] = c_i ^ c[i] ^ separator_byte
                    break

            c[i] = c_i

    return p

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
