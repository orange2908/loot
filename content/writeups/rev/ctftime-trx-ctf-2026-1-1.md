---
title: "1+1 - TRX CTF 2026"
category: "rev"
type: "writeup"
tags: ["rev", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "1\\. Reversing the interpreter 1"
source:
  name: "CTFtime writeup #40721"
  url: "https://ctftime.org/writeup/40721"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-1-plus-1-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "1+1"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** 1+1
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40721>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-1-plus-1-writeup>

---
1\. Reversing the interpreter 1  
1 is a small statically linked ELF64 with no section headers. The entry point opens the path supplied as argv[1], reads the whole file into memory, treats it as an array of 64-bit little-endian cells, and starts executing at VM program counter 0.

Each instruction is a triple of cells:

[a, b, c]  
The VM logic is:

uint64_t *mem = read_entire_file(argv[1]);  
int64_t pc = 0;  
  
while (0 <= pc && pc < cell_count) {  
uint64_t a = mem[pc + 0];  
uint64_t b = mem[pc + 1];  
uint64_t c = mem[pc + 2];  
  
if ((int64_t)a == -1) {  
// input opcode  
unsigned char ch;  
read(0, &ch, 1);  
mem[b] = ch;  
pc = c;  
} else if ((int64_t)a == -2) {  
// output opcode  
print_hex_without_0x_or_leading_zeroes(mem[b]);  
write(1, " ", 1);  
pc = c;  
} else {  
// add-and-branch opcode  
mem[b] += mem[a];  
pc = ((int64_t)mem[b] > 0) ? pc + 3 : c;  
}  
}  
The important detail is the signed branch after the addition. The bytecode uses that one arithmetic instruction to implement loops, table indexing, byte arithmetic, copies, and the final hash.

A direct VM trace of the correct input runs for roughly 3,975,036,377 VM instructions and performs:

128 input opcodes  
32 output opcodes
