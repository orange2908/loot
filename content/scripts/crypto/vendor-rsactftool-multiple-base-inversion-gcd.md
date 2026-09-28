---
title: "Multiple Base Inversion Gcd (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "gcd", "multiple", "base", "inversion", "multiple-base-inversion-gcd", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/multiple_base_inversion_gcd.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/multiple_base_inversion_gcd.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/multiple_base_inversion_gcd.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/multiple_base_inversion_gcd.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/multiple_base_inversion_gcd.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd


def a(n):
    return int(str(n)[::-1])


def b(n):
    return int(bin(n)[2:][::-1], 2)


def c(n):
    return int(oct(n)[2:][::-1], 8)


def d(n):
    return int(hex(n)[2:][::-1], 16)


def FF(n):
    F = []
    for p in range(1, 6):
        np = pow(n, p)

        F.append(gcd(n, a(np)))
        F.append(gcd(n, b(np)))
        F.append(gcd(n, c(np)))
        F.append(gcd(n, d(np)))

        F.append(gcd(n, n ^ a(np)))
        F.append(gcd(n, n ^ b(np)))
        F.append(gcd(n, n ^ c(np)))
        F.append(gcd(n, n ^ d(np)))

    return list(set(filter(lambda x: n > x > 1, F)))


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Test n against gcds with inverted-factorial products in multiple bases"""
        try:
            pq = FF(publickey.n)
            if len(pq) == 2:
                publickey.p, publickey.q = pq
            elif len(pq) == 1:
                publickey.p = pq[0]
                publickey.q = publickey.n // pq[0]
            elif len(pq) > 2:
                self.logger.error("Multiprime RSA not supported...")
            else:
                self.logger.error("No factors found...")
                return None, None
        except Exception:
            self.logger.error("Factorization error...")
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = RSA.construct((3 * 5, 7)).publickey().exportKey()
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
