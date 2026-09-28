---
title: "Prime Base Collision (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "prime", "base", "collision", "prime-base-collision", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/prime_base_collision.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/prime_base_collision.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/prime_base_collision.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/prime_base_collision.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/prime_base_collision.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.algos import prime_base_collision


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run prime_base_collision attack with a timeout"""
        try:
            if publickey.n <= 10_000_000_000:
                publickey.p, publickey.q = prime_base_collision(publickey.n)
            else:
                self.logger.error("[-] prime_base_collision is too slow for pubkeys > 10^10...")
                return None, None

        except FactorizationError:
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
