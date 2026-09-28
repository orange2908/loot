---
title: "Primorial Pm1 Gcd (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "gcd", "primorial", "pm1", "primorial-pm1-gcd", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/primorial_pm1_gcd.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/primorial_pm1_gcd.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/primorial_pm1_gcd.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/primorial_pm1_gcd.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/primorial_pm1_gcd.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, next_prime


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against primorial +-1 composites"""
        limit = 10000
        prime = 1
        primorial = 1
        p = q = None
        n = publickey.n
        for _ in tqdm(range(0, limit), disable=(not progress)):
            prime = next_prime(prime)
            # Keep the primorial reduced mod n; the gcds below are unchanged.
            primorial = (primorial * prime) % n
            primorial_p1 = [primorial - 1, primorial + 1]
            g0, g1 = (
                gcd(primorial_p1[0], publickey.n),
                gcd(primorial_p1[1], publickey.n),
            )
            if 1 < g0 < publickey.n:
                p = publickey.n // g0
                q = g0
                break
            if 1 < g1 < publickey.n:
                p = publickey.n // g1
                q = g1
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MGIwDQYJKoZIhvcNAQEBBQADUQAwTgJHRxjQFVPVvt1fa+cUt3fS5qNiHLa/OeaX
5USLac4dYG3GsvE97xPdzXfx6iQiM5u9608uoygqBRfr+YN4bTuvC6omcabKO30C
AwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
