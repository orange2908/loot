---
title: "forker level2 - WPICTF 2018"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "canary", "forker", "level2", "stack", "binary-exploitation"]
summary: "In this challenge, you can leak stack canary with brute force."
source:
  name: "sajjadium/ctf-writeups"
  url: "https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/WPICTF/2018/forker.level2/README.md"
ctf:
  name: "WPICTF"
  year: 2018
  challenge: "forker level2"
---

## Source

- **CTF:** WPICTF 2018
- **Challenge:** forker level2
- **Repository:** [sajjadium/ctf-writeups](https://github.com/sajjadium/ctf-writeups)
- **File:** <https://github.com/sajjadium/ctf-writeups/blob/1fed8bd75274fd50981977a845d961ecd7dd99ef/ctfs/WPICTF/2018/forker.level2/README.md>

---
In this challenge, you can leak `stack canary` with brute force. The lesson-learned is that `stack canary` is generated at the program startup and is being re-used for all the function calls in that program. The interesting point is that it is also being reused in the `child process` when we use `fork`. Basically, you can brute force the stack canary one-byte at a time without the value being changed.
