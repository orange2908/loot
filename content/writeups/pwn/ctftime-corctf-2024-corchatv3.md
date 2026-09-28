---
title: "corchatv3 - corCTF 2024"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "uaf", "tcache-perthread-struct", "sqlite3", "sqlinjection", "python-exploitation", "tcache", "use-after-free", "one-gadget", "sqli", "reverse-shell", "heap", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "Use an SQL injection to target a vulnerable version of the libsqlite3 library."
source:
  name: "CTFtime writeup #39398"
  url: "https://ctftime.org/writeup/39398"
original_source: "https://sashactf.gitbook.io/pwn-notes/ctf-writeups/cor-ctf-2024/corchat-v3"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "corchatv3"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** corchatv3
- **Author team:** Sashastone
- **CTFtime tags:** uaf, tcache_perthread_struct, sqlite3, sqlinjection, python-exploitation
- **CTFtime:** <https://ctftime.org/writeup/39398>
- **Original writeup:** <https://sashactf.gitbook.io/pwn-notes/ctf-writeups/cor-ctf-2024/corchat-v3>

---
TLDR:  
Use an SQL injection to target a vulnerable version of the `libsqlite3` library. `json_set` contains a UAF, which can be used to free `tcache_perthread_struct`. Then using `json_extract`, you can re-allocate `tcache_perthread_struct` to get arbitrary writes, which you use to target `PyMem_Raw` (to turn `PyMem_RawFree` into a one_gadget that does a reverse shell), and `PyFunction_Type->tp_call` (to use this one_gadget when a python function is called).
