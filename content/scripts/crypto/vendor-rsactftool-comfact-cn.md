---
title: "Comfact Cn (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "common-factor", "gcd", "comfact", "comfact-cn", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/comfact_cn.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/comfact_cn.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/comfact_cn.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/comfact_cn.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/comfact_cn.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd
from RsaCtfTool.lib.utils import s2n
from RsaCtfTool.lib.keys_wrapper import PrivateKey


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def comfact(self, cipher, publickey):
        for c in cipher:
            commonfactor = gcd(publickey.n, s2n(c))

            # commonfactor == n means c == 0 (mod n): the "split" (1, n)
            # is not a factorization and must not touch publickey.p/q.
            if 1 < commonfactor < publickey.n:
                publickey.q = commonfactor
                publickey.p = publickey.n // publickey.q
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        return (None, None)

    def attack(self, publickey, cipher=[], progress=True):
        """Try an attack where the public key has a common factor with the ciphertext - sourcekris"""
        return self.comfact(cipher, publickey) if cipher is not None else (None, None)

    def test(self):
        """FIXME: Implement testcase"""
        raise NotImplementedError

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
