---
title: "Factorial Pm1 Gcd (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "gcd", "factorial", "pm1", "factorial-pm1-gcd", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/factorial_pm1_gcd.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/factorial_pm1_gcd.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/factorial_pm1_gcd.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/factorial_pm1_gcd.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/factorial_pm1_gcd.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against factorial +-1 composites"""
        limit = 30000
        p = q = None
        f = 1
        n = publickey.n
        for x in tqdm(range(2, limit), disable=(not progress)):
            # f = x! mod n; gcd(f - 1, n) is unaffected by the reduction and
            # keeping f small avoids ever-growing bignum gcds.
            f = (f * x) % n
            g = gcd(f - 1, n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
            g = gcd(f + 1, n)
            if 1 < g < n:
                p = publickey.n // g
                q = g
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCcwDQYJKoZIhvcNAQEBBQADFgAwEwIMBzd7j1U0b2YJk4yPAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
