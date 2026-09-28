---
title: "Seccomp Hell - HITCON CTF 2024 Quals"
category: "pwn"
subcategory: "seccomp"
type: "writeup"
tags: ["pwn", "sandbox", "kernel", "userland", "ldt", "seccomp", "rop", "shellcode", "sandbox-escape", "hitcon-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "You need to exploit three parts in this challenge"
source:
  name: "CTFtime writeup #39332"
  url: "https://ctftime.org/writeup/39332"
original_source: "https://w0y.at/writeup/2024/07/16/hitcon-ctf-2024-quals-seccomp-hell.html"
ctf:
  name: "HITCON CTF 2024 Quals"
  year: 2024
  challenge: "Seccomp Hell"
---

## Metadata

- **CTF:** HITCON CTF 2024 Quals
- **Task:** Seccomp Hell
- **Author team:** WE_0WN_Y0U
- **CTFtime tags:** pwn, sandbox, kernel, userland, ldt, seccomp
- **CTFtime:** <https://ctftime.org/writeup/39332>
- **Original writeup:** <https://w0y.at/writeup/2024/07/16/hitcon-ctf-2024-quals-seccomp-hell.html>

---
## TL;DR  
You need to exploit three parts in this challenge

1\. userland exploitation   
backdoor that allows ROP chain that can be used to get arbitray code execution

2\. kernel backdoor   
backdoor that creates CALL GATE in the LDT (local descriptor table) to get kernel mode escalation and write kernel shellcode

3\. sandbox escape   
disable seccomp and escalate priviliges through kernel shellcode (corrupt current task_struct)

## [more ...](<https://w0y.at/writeup/2024/07/16/hitcon-ctf-2024-quals-seccomp-hell.html>)
