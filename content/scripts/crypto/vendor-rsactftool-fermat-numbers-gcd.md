---
title: "Fermat Numbers Gcd (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "gcd", "fermat", "numbers", "fermat-numbers-gcd", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/fermat_numbers_gcd.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/fermat_numbers_gcd.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/fermat_numbers_gcd.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/fermat_numbers_gcd.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/fermat_numbers_gcd.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against fermat composites"""
        limit = 30
        p = q = None
        for x in tqdm(range(2, limit), disable=(not progress)):
            # gcd(F_x, n) == gcd(F_x mod n, n), and 2^(2^x) mod n costs
            # only x modular squarings - building the full Fermat number
            # instead (2^(2^29)+1 is a 670-million-bit integer) made the
            # last iterations of this loop dominate the whole attack.
            r = powmod(2, 1 << x, publickey.n)
            g = gcd(r + 1, publickey.n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MF4wDQYJKoZIhvcNAQEBBQADTQAwSgJDTuJNJVnOa1qp8n91iIWs30F6xA+I/nkf
MV7Ad/0M5seWOKImUngYig60DRfrXwXa7GWh8qmK0V5sR+ib27+bbZfwAQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
