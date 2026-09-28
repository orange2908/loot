---
title: "riscv jit - CyberSecurityRumble CTF 2022"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "riscv", "jit", "binary-exploitation", "riscv-jit"]
summary: "Quick explanation for riscv-jit.."
source:
  name: "nobodyisnobody/write-ups"
  url: "https://github.com/nobodyisnobody/write-ups/blob/b9cec85168dd73a9e9329b44420024c64f48b8c1/CyberSecurityRumble.CTF.2022/pwn/riscv-jit/README.md"
ctf:
  name: "CyberSecurityRumble CTF"
  year: 2022
  challenge: "riscv jit"
---

## Source

- **CTF:** CyberSecurityRumble CTF 2022
- **Challenge:** riscv jit
- **Repository:** [nobodyisnobody/write-ups](https://github.com/nobodyisnobody/write-ups)
- **File:** <https://github.com/nobodyisnobody/write-ups/blob/b9cec85168dd73a9e9329b44420024c64f48b8c1/CyberSecurityRumble.CTF.2022/pwn/riscv-jit/README.md>

---
Quick explanation for riscv-jit..



we use recursion of bson opcode 6 to overwrite an entry in the riscv jump table at address 0x3e4

we replace entry for opcode 5 with a jump to read function()

with the read function we read another riscv shellcode and jump to it

this second shellcode read a third shellcode at address 0x86

this third shellcode use overflow of rw zone to rwx zone by writing a dword at address 0xffff,

3 bytes will overflow in the rwx zone..

we use this overflow to overwrite a rwx chunk_map , with a single `mov [rdi+rbp],dl`

that will expand mem  size in vm_state ,

then we read a x86 shellcode in the rwx zone and jumps to it...

and that's all...
