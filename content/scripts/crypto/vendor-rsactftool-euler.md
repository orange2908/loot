---
title: "Euler (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "gcd", "euler", "crypto"]
summary: "/usr/bin/env python code taken from RsaCtfTool.https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/euler.py"
license: "MIT"
---

## What it does

/usr/bin/env python code taken from RsaCtfTool.https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/euler.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/euler.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/euler.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/euler.py
```

## Code

```python
# /usr/bin/env python
# code taken from RsaCtfTool.https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf

import logging
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import euler
from RsaCtfTool.lib.number_theory import is_congruent


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Euler method"""
        # Euler attack
        try:
            if is_congruent(publickey.n, 1, 4):
                euler_res = euler(publickey.n)
            else:
                self.logger.error(
                    "[!] Public key modulus must be congruent 1 mod 4 to work with euler method."
                )
                return None, None
        except Exception:
            return None, None
        if euler_res is not None and len(euler_res) == 2:
            p, q = int(euler_res[0]), int(euler_res[1])
            # euler() derives its factors from GCDs that may also come out
            # as 1, n, or values whose product overshoots n (e.g. (45, 45)
            # for n = 225); only a genuine split of n may proceed.
            if 1 < p < publickey.n and 1 < q < publickey.n and p * q == publickey.n:
                publickey.p, publickey.q = p, q

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCIwDQYJKoZIhvcNAQEBBQADEQAwDgIHEAABggAEpQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data))
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
