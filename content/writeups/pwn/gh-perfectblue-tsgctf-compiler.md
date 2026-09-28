---
title: "compiler - tsgctf 2020"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "compiler", "binary-exploitation", "tsgctf", "perfectblue", "ctf-writeups"]
summary: "Our compiler backdoor works by intercepting all calls to read(),"
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/tsgctf-2020/compiler/README.md"
ctf:
  name: "tsgctf"
  year: 2020
  challenge: "compiler"
---

## Source

- **CTF:** tsgctf 2020
- **Challenge:** compiler
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2020/tsgctf-2020/compiler/README.md>

---
Our compiler backdoor works by intercepting all calls to `read()`,
hashing the input consumed so far, and injecting code whenever the hash matches a known value.
At the end of compilation the backdoor executes a [quine](https://en.wikipedia.org/wiki/Quine_%28computing%29)
to include itself in newly compiled compilers.

## Files

 - `compiler_backdoor.template` — original compiler but with hooks to backdoor inserted
 - `diff.py` — script that diffs `compiler_backdoor.template` with `compiler.y` and generates
   appropriate injection and quine code.
