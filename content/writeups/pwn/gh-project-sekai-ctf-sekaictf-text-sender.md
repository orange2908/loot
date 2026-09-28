---
title: "text sender - sekaictf 2023"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "free-hook", "scanf", "binary-exploitation"]
summary: "This solution can be divided into three steps:"
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/pwn/text-sender/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "text sender"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** text sender
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/pwn/text-sender/solution/README.md>

---
# TextSender - Solution

This solution can be divided into three steps:

1. There is a bug in `edit_message()`. It compares our input with only the first part of the receiver name, which means if the receiver name is `Hello`, we just need to type `H`, `He`, `Hel`, or `Hell` and we can edit message of receiver `Hello` --> **Bruteforce** heap and `libc` address.

2. We can now conduct a [House of Einherjar](https://heap-exploitation.dhavalkapil.com/attacks/house_of_einherjar) attack. The `scanf()` in `input()` has a bug—if we set the correct combination of position of chunks, we can set the chunk of `message` from `0x201` to `0x200` due to the null byte added in `scanf()` when we input the maximum length. With a size of `0x200`, the `PREV_IN_USE` bit is removed and we make it overlap with other chunks.

3. Finally, we can use `getline()` in `edit_message()` to malloc a chunk and overwrite the forward pointer of any freed chunk in the tcache to change `__free_hook` into `system()`. Free a chunk containing the string `/bin/sh` and we get a shell!
