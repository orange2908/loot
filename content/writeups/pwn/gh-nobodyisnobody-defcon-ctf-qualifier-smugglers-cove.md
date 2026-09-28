---
title: "smugglers cove - DEFCON CTF Qualifier 2022"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "smugglers", "cove", "binary-exploitation", "smugglers-cove", "defcon-ctf-qualifier"]
summary: "was a pwn challenge from Defcon Quals 2022."
source:
  name: "nobodyisnobody/write-ups"
  url: "https://github.com/nobodyisnobody/write-ups/blob/b9cec85168dd73a9e9329b44420024c64f48b8c1/DEFCON.CTF.Qualifier.2022/pwn/smugglers_cove/README.md"
ctf:
  name: "DEFCON CTF Qualifier"
  year: 2022
  challenge: "smugglers cove"
---

## Source

- **CTF:** DEFCON CTF Qualifier 2022
- **Challenge:** smugglers cove
- **Repository:** [nobodyisnobody/write-ups](https://github.com/nobodyisnobody/write-ups)
- **File:** <https://github.com/nobodyisnobody/write-ups/blob/b9cec85168dd73a9e9329b44420024c64f48b8c1/DEFCON.CTF.Qualifier.2022/pwn/smugglers_cove/README.md>

---
#### **Smuggler's cove**

was a pwn challenge from Defcon Quals 2022.

It was a pwn challenge about exploiting a lua jit interpreter.

A shared library containing the lua jit interpreter was given, libluajit-5.1.so.2.

and two programs:

- cove  and  cove.c (its sources)

- dig_up_the_loot and  dig_up_the_loot.c (its sources),  a simple program that need to be executed with these arguments:                             

  `./dig_up_the_loot x marks the spot`

executing this way will display the flag.



The cove program, will take a input lua source code , of a maximum size of 433 bytes.

and execute it via the lua library.
