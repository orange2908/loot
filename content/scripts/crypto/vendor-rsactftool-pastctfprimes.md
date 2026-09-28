---
title: "Pastctfprimes (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "pastctfprimes", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/pastctfprimes.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/pastctfprimes.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/pastctfprimes.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/pastctfprimes.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/pastctfprimes.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.number_theory import is_divisible


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Search for previously used primes in CTFs"""
        data_dir = Path(__file__).resolve().parents[2] / "data"
        for txtfile in data_dir.glob("*.txt"):
            self.logger.info(f"[+] loading prime list file {txtfile}...")
            primes = [
                int(line.rstrip()) for line in txtfile.read_text().splitlines()
            ]
            for prime in tqdm(primes, disable=(not progress)):
                if is_divisible(publickey.n, prime):
                    publickey.q = prime
                    publickey.p = publickey.n // publickey.q
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return priv_key, None
        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIIBfjANBgkqhkiG9w0BAQEFAAOCAWsAMIIBZgKCAV0BAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAEcN5PtyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE7i1xIeWbfAOhAgMB
AAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
