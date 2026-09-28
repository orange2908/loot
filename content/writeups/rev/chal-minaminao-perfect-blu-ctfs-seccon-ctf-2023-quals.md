---
title: "Perfect Blu - Seccon CTF 2023 Quals"
category: "rev"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "perfect", "blu", "rev", "seccon-ctf-2023-quals"]
summary: "Challenge Perfect Blu with the author's own solution."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/perfect-blu"
license: "none stated"
ctf:
  name: "Seccon CTF 2023 Quals"
  year: 2023
  challenge: "Perfect Blu"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/perfect-blu>
- **CTF:** Seccon CTF 2023 Quals

---

# Perfect Blu

Co-author: [ptr-yudai](https://github.com/ptr-yudai)  

## Description 
No, I'm real!


## Solver: `solver.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-2023-quals/perfect-blu/solver/solver.py>

```python
CALL_OBJECT_BYTECODE = bytes.fromhex("21820000" + "000000")  # CALL_OBJECT 000000??
KEY = "1234567890QWERTYUIOPASDFGHJKL{ZXCVBNM_-}"
PACKET_LEN = 192
PACKET_HEADER_LEN = 8
FLAG_LEN = 47

flag = ""

for flag_i in range(FLAG_LEN):
    m2ts = open(f"STREAM/{flag_i:05}.m2ts", "rb").read()
    stream = b"".join(
        [
            m2ts[i + PACKET_HEADER_LEN : i + PACKET_LEN]
            for i in range(0, len(m2ts), PACKET_LEN)
        ]
    )

    key_i = 0
    for i in range(len(stream)):
        if not stream[i : i + len(CALL_OBJECT_BYTECODE)] == CALL_OBJECT_BYTECODE:
            continue
        dst = stream[i + len(CALL_OBJECT_BYTECODE)]
        if dst == flag_i + 1:
            flag += KEY[key_i]
        key_i += 1

print(flag)
```
