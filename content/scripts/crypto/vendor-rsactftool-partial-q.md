---
title: "Partial Q (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "chinese-remainder", "partial", "partial-q", "crypto"]
summary: "!/usr/bin/env python3"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/partial_q.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/partial_q.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/partial_q.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/partial_q.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/partial_q.py
```

## Code

```python
#!/usr/bin/env python3

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.algos import solve_partial_q


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_q attack with a timeout"""
        try:
            if not isinstance(publickey, PrivateKey):
                self.logger.error(
                    "[!] partial_q attack is only for partial private keys not pubkeys..."
                )
                raise FactorizationError

            n = publickey.n
            if (e := publickey.e) == 0:
                e = 65537
            # dp/dq/di only exist on keys loaded from a partial-privkey
            # file; component-built PrivateKey objects lack the attributes
            # entirely, so fetch them defensively.
            dp = getattr(publickey, "dp", None)
            dq = getattr(publickey, "dq", None)
            di = getattr(publickey, "di", None)
            partial_q = publickey.q
            if None in (dp, dq, di, partial_q):
                self.logger.error(
                    "[!] partial_q needs CRT components (dp, dq, qinv) and a partial q..."
                )
                return None, None
            publickey.p, publickey.q = solve_partial_q(n, e, dp, dq, di, partial_q)
            if publickey.e == 0:
                publickey.e = 65537
            if publickey.n == 0:
                publickey.n = publickey.p * publickey.q

        except FactorizationError:
            return None, None

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=int(publickey.n),
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                # print(priv_key)
                return priv_key, None
            except ValueError:
                return None, None

        return None, None

    def test(self):
        raise NotImplementedError

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
