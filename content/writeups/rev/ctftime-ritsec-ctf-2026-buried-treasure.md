---
title: "Buried Treasure - RITSEC CTF 2026"
category: "rev"
subcategory: "packers"
type: "writeup"
tags: ["rev", "unpacking", "re", "packer", "buried", "treasure", "packers", "ritsec-ctf", "ritsec-ctf-2026", "2026", "ctf-writeup"]
summary: "We’re given a stripped, statically linked 64-bit ELF."
source:
  name: "CTFtime writeup #40704"
  url: "https://ctftime.org/writeup/40704"
original_source: "https://ctftime.org/team/431287"
ctf:
  name: "RITSEC CTF 2026"
  year: 2026
  challenge: "Buried Treasure"
---

## Metadata

- **CTF:** RITSEC CTF 2026
- **Task:** Buried Treasure
- **Author team:** Echelon Obscura
- **CTFtime tags:** unpacking, re
- **CTFtime:** <https://ctftime.org/writeup/40704>
- **Original writeup:** <https://ctftime.org/team/431287>

---
### Buried Treasure (Reversing) - RITSEC CTF 2026  
We’re given a stripped, statically linked 64-bit ELF. The size and noise already suggest this won’t be a straightforward reverse.

#### Approach  
Looking at `main`, the program:  
1\. Allocates memory with `mmap`  
1\. Sets up signal handlers (likely anti-debugging)  
1\. Transfers execution to a function that unpacks and executes another stage

Inside this function, a buffer is reconstructed by XORing a static payload with a repeating key, then executed.

So the binary is not the real target. It acts as a loader.

Running it with `strace` confirms this behavior:  
1\. Repeated `memfd_create`  
1\. Writing ELF binaries to memory  
1\. Executing them via `/proc/self/fd/...`

This happens multiple times, forming a multi-stage in-memory unpacking chain.

Instead of reversing every stage statically, it’s much easier to dump the final payload during execution.

Using `gdb`, I hooked the `write` syscall and captured buffers starting with `\x7fELF`. This allowed me to extract the last stage as a standalone binary.

#### Final Stage Analysis  
Once isolated, the final binary is much simpler.

The validation logic:  
1\. Requires input length = 36  
1\. Iterates over each character  
2\. Applies a transformation and compares against a table

From the disassembly: \  
`input[i] * 13 + i == table[i]`

This is easily reversible: \  
`input[i] = (table[i] - i) / 13`

So instead of brute forcing or emulating, we can directly recover each character.

#### Solution Script  
```python  
#!/usr/bin/env python3

table = [  
0x450, 0x895, 0x12e5, 0x9e9, 0x1b55, 0x1003,  
0x2b2f, 0x26c5, 0x302b, 0x306d, 0x40fc, 0x3f91,  
0x208b, 0x4e67, 0x51b5, 0x4d65, 0x645a, 0x5f47,  
0x3264, 0x3815, 0x7add, 0x6a5d, 0x3bcd, 0x864d,  
0x3d2e, 0x9ab9, 0x8d79, 0x9421, 0x8c29, 0xa4cb,  
0x5220, 0xc4e5, 0x55bd, 0xc51b, 0xccad, 0xe4cd,  
]

flag = []  
r12, r13 = 0x26, 0xd

for entry in table:  
char_val = (entry - r12) // r13  
flag.append(chr(char_val))  
r12 += 1  
r13 += 0xd

print(''.join(flag))  
```

#### Flag  
Once executed, the script reconstructs the full flag instantly, avoiding the need for further debugging or interaction with the binary:  
```bash  
$ python [solve.py](http://solve.py)  
RS{0k4y_i_th1nk_th47s_3n0ugh_l4y3rs}  
```

#### Notes  
The main challenge here was the layered unpacking.

Once the final stage is extracted, the actual check reduces to a simple linear equation.

For a full step-by-step breakdown including the dumping process and detailed analysis, I wrote a full post [here](<https://pnasis.gitlab.io/posts/ritsec-ctf-2026-reversing-writeups-part-3-buried-treasure/>) ;).
