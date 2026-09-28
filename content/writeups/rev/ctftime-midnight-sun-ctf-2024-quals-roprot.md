---
title: "roprot - Midnight Sun CTF 2024 Quals"
category: "rev"
subcategory: "rop"
type: "writeup"
tags: ["rev", "rop", "xor", "lsb", "subprocess", "midnight-sun-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "For the full experience with images see the original blog post!"
source:
  name: "CTFtime writeup #40242"
  url: "https://ctftime.org/writeup/40242"
original_source: "https://ik0ri4n.de/midnightsun-24-roprot"
ctf:
  name: "Midnight Sun CTF 2024 Quals"
  year: 2024
  challenge: "roprot"
---

## Metadata

- **CTF:** Midnight Sun CTF 2024 Quals
- **Task:** roprot
- **Author team:** KITCTF
- **CTFtime tags:** rev, rop
- **CTFtime:** <https://ctftime.org/writeup/40242>
- **Original writeup:** <https://ik0ri4n.de/midnightsun-24-roprot>

---
*For the full experience with images see the original blog post!*

The challenge download contains two files: a tool and the challenge binary itself.  
We ultimately didn't need the tool for our solve because it is too slow but it's a nice-to-have.  
The challenge binary itself is a 64-bit stripped and dynamically linked ELF crackme, nothing special so far.  
It takes a license string as a command-line argument, does some setup (we'll look at that later) and then performs the license check itself.

### License check

First off, the check verifies the format of the license key.  
It must be of length 18 (magenta highlight) and every fifth character must be `'-'` (white highlight), so we get 4 blocks of 4 chars.

license check function

The characters in these blocks are checked to be either uppercase alphabetic characters or numeric characters.  
In case you haven't come across such a check before, they are implemented via [locale tables](<https://refspecs.linuxbase.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/baselib---ctype-b-loc.html>) containing the characteristics for every character of a charset (see code below; watch out with endianness).  
These alphanumeric characters form a base-36 number which is converted to decimal (orange highlight).  
Excess bits are discarded here because of the multiplication implementation with `shl`.  
After the last character has been read, the lower and upper 32 bits are combined with XOR and compared against a hash value (cyan highlight).  
If equal the XOR-reduced key value is then used to set our random seed with `srand`.  
We can thus only use the least significant 32 bits and set the remaining characters to 0 when converting a number back to a license key.

```c  
# include <bits/endian.h>  
# if __BYTE_ORDER == __BIG_ENDIAN  
# define _ISbit(bit) (1 << (bit))  
# else /* __BYTE_ORDER == __LITTLE_ENDIAN */  
# define _ISbit(bit) ((bit) < 8 ? ((1 << (bit)) << 8) : ((1 << (bit)) >> 8))  
# endif

enum  
{  
_ISupper = _ISbit (0), /* UPPERCASE. LSB 0x0100 */  
_ISlower = _ISbit (1), /* lowercase. LSB 0x0200 */  
_ISalpha = _ISbit (2), /* Alphabetic. LSB 0x0400 */  
_ISdigit = _ISbit (3), /* Numeric. LSB 0x0800 */  
_ISxdigit = _ISbit (4), /* Hexadecimal numeric. LSB 0x1000 */  
_ISspace = _ISbit (5), /* Whitespace. LSB 0x2000 */  
_ISprint = _ISbit (6), /* Printing. LSB 0x4000 */  
_ISgraph = _ISbit (7), /* Graphical. LSB 0x8000 */  
_ISblank = _ISbit (8), /* Blank (usually SPC and TAB). LSB 0x0001 */  
_IScntrl = _ISbit (9), /* Control character. LSB 0x0002 */  
_ISpunct = _ISbit (10), /* Punctuation. LSB 0x0004 */  
_ISalnum = _ISbit (11) /* Alphanumeric. LSB 0x0008 */  
};  
```

Now, my naming already hints an important detail of the hash function:

16bit hash function

As you can see, the resulting hash value is calculated in a 16-bit integer.  
With 32-bit inputs we get around `2^16` collisions with `hash_16bit(0xbac9ab0c)` (of course, `0xbac9ab0c` is not the expected key).  
Reducing our search space of possible license keys to 16 bit is already enough to solve the challenge with sheer brute force (with 24h of competition; someone will always throw cores at such stuff).  
While that would reduce the time we'd have to think about a solve, where's the fun in that?!  
We haven't even looked at the main functionality of the binary yet.

### What the ROP?

main function

Once we pass the license check, the binary generates a huge buffer of random data with `rand()`.  
With this executable buffer and another buffer it then calls a function I called `start_rop`:

start_rop function

This function copies an array of constant offsets to our ROP stack and then sets the stack pointer to our ROP stack and returns.  
Thus, it essentially starts a ROP chain with specific addresses in a bunch of random data.  
ROP gadgets are usually small, containing only one or two instructions, and often only a few bytes long, e.g., `pop rdi; pop rsi; ret` (3 bytes).  
Large gadgets are very unlikely since they have to generated like that in a buffer of random data.  
As such, we can check that the ROP offsets are followed by a return instruction (byte `0xc3`) after a few bytes (we used around 16 bytes to account for large instructions).  
There are two especially small addresses in our ROP chain, `0x24a` and `0x54b`, that we used for this check.

I implemented a parallelized script to quickly find the remaining options for our license key.  
You can run it with `mpicc -o parallel -O3 parallel.c` and `mpirun -np 8 ./parallel > ./out.txt` to quickly get those 206 seeds (ca. 20s on my laptop).

```c  
#include <stdlib.h>  
#include <stdio.h>  
#include <stdint.h>  
#include <mpi.h>

uint64_t checksum(uint32_t arg1)  
{  
uint8_t val[0x4] = {0};  
*(uint32_t *)val = arg1;  
int16_t sum = 0xffff;  
for (uint64_t i = 0; i <= 3; i = (i + 1))  
{  
sum = (sum ^ ((int16_t)(((uint32_t)val[i]) << 8)));  
for (int32_t j = 0; j <= 7; j = (j + 1))  
{  
if (sum >= 0)  
{  
sum = (sum << 1);  
}  
else  
{  
sum = (0x1021 ^ (sum * 2));  
}  
}  
}  
return ((uint64_t)sum);  
}

int check(uint32_t seed)  
{  
srand(seed);  
int offset = 0x0000024a;  
int second = 0x0000054b - ((offset / 4 + 5) * 4);  
uint32_t target = 0xc3;

for (int i = 0; i < offset / 4; i++)  
{  
rand();  
}

int out = 0;  
for (int i = 0; i < 5; i++)  
{  
uint32_t val = rand();  
if ((val & 0xff) == target || (val & 0xff00) == (target << 8) || (val & 0xff0000) == (target << 16) || (val & 0xff000000) == (target << 24))  
{  
out = 1;  
}  
}

if (out == 0)  
{  
return 0;  
}

// Did you expect clean code here? Nah, I didn't think so ;)  
for (int i = 0; i < second / 4; i++)  
{  
rand();  
}

for (int i = 0; i < 5; i++)  
{  
uint32_t val = rand();  
if ((val & 0xff) == target || (val & 0xff00) == (target << 8) || (val & 0xff0000) == (target << 16) || (val & 0xff000000) == (target << 24))  
{  
return 1;  
}  
}

return 0;  
}

int main(int argc, char **argv)  
{  
int comm_rank, comm_size;

MPI_Init(&argc, &argv);  
MPI_Comm_size(MPI_COMM_WORLD, &comm_size);  
MPI_Comm_rank(MPI_COMM_WORLD, &comm_rank);

uint64_t count = 0;  
uint64_t max = 4294967296;  
uint64_t block_size = max / comm_size;

for (uint64_t value = comm_rank * block_size; value < (comm_rank + 1) * block_size; value++)  
{  
if (checksum(value) == 0x2cc2)  
{  
if (check(value) == 1)  
{  
printf("%ld\n", value);  
}  
}  
}

MPI_Finalize();  
return 0;  
}  
```

The fact that we can't know the exact license key and don't know much about what will happen in the ROP chain code is kind of unfortunate for us.  
We can make an educated guess though: it will very likely print something like `"Correct: <flag>"`.

output GIF

When we look at the setup function, we see that signals like `SIGSEGV` and `SIGILL` are handled by printing the fail message too.

setup function

The function I called `print_verify_license()` is responsible for the long delay before actually starting the app.  
We can remove that call with a quick patch and then just get the output for our 206 license keys in a few minutes.

```py  
import subprocess

with open('./out.txt', 'r') as file:  
lines = file.readlines()

for line in lines:  
seed = int(line)

license = ['x']*0x13

for i in range(0x13):  
if (i+1) % 5 == 0:  
license[i] = '-'

for i in range(0x13):  
if (i+1) % 5 == 0:  
continue

val = (seed % 36)  
if val < 10:  
license[0x12-i] = chr(ord('0') + val)  
else:  
license[0x12-i] = chr(ord('7') + val)  
seed //= 36

license = ''.join(license)

print(subprocess.getoutput(f"./patched {license}"))

```

After about 5 minutes (without parallelization here...) we have a flag in our output:

flag_output

In case you want to try it out yourself, one valid license key is `0000-0000-00Y9-0SOR`.

## Final thoughts

I found the idea to use ROP on a buffer of random data pretty ingenious.  
That was the first time I saw someone do that and I really enjoyed playing around with the challenge even though our solve ultimately was just a (slightly intelligent) brute force attack.

Now, had this not been a crackme but a real binary simply hashing the whole license key with a secure hash algorithm and a sufficient output size (at least 83 bits with this format) would be better.  
But then again, it is not and pure hash cracking wouldn't be as fun.
