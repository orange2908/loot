---
title: "Highly Optimized - UofTCTF 2025"
category: "rev"
subcategory: "vm"
type: "writeup"
tags: ["decompilation", "bytecode", "x86", "rev", "optimization", "reversing", "reverse-engineering", "linux", "vm", "pie", "custom-vm", "lsb", "base64", "uoftctf", "uoftctf-2025", "2025", "ctf-writeup"]
summary: "This is a write-up for CTF challenge named \"Highly Optimized\", organized by"
source:
  name: "CTFtime writeup #39807"
  url: "https://ctftime.org/writeup/39807"
original_source: "https://github.com/hakierspejs/ctf-uoftctf-2025-highlyoptimized"
ctf:
  name: "UofTCTF 2025"
  year: 2025
  challenge: "Highly Optimized"
---

## Metadata

- **CTF:** UofTCTF 2025
- **Task:** Highly Optimized
- **Author team:** Hakierspejs
- **CTFtime tags:** c, decompilation, bytecode, x86, rev, c, optimization, reversing, reverse_engineering, linux, vm
- **CTFtime:** <https://ctftime.org/writeup/39807>
- **Original writeup:** <https://github.com/hakierspejs/ctf-uoftctf-2025-highlyoptimized>

---
# Highly Optimized - writeup

This is a write-up for CTF challenge named "Highly Optimized", organized by  
University of Toronto 2025. At the time of writing, it's Saturday 7:55PM and  
the challenge has been solved 62 times, giving each of the teams 352 points.

> I set my compiler optimizations to the max, but my program still won't  
> complete. Maybe I just need to wait a few more minutes.  
> Author: 5UXFpebqXx4stj3

TL;DR:

1\. goal is to extract flag from 16600-byte 64-bit Linux ELF  
2\. decompiled using DogBolt, picked HexRays's output, because code was most  
readable  
3\. modified the code so that it compiles and runs (commented out many  
undefined attributes and symbols, e.g. gmon-related)  
4\. put main() into ChatGPT, heard it's a VM and was guided through  
understanding code  
5\. added printf's so I could track execution, found it keeps removing  
(?) from (??) in a loop  
6\. once I had `_QWORD code[265]` in a readable format, I tried to make it  
print characters  
7\. after "hello world", I experimented with replacing the first large number  
with something smaller  
8\. observed that the loop is effectively calculating the modulo  
9\. extracted all non-opcode numbers from code[265], deduplicated, saved as N  
10\. `print("".join([chr(N[::2][i] % N[1::2][i]) for i in range(len(N)//2)]))`

\---

## 1. First look at the binary

```  
> ls -l highly-optimized ; file highly-optimized   
-rwxr-xr-x 1 d d 16600 Jan 11 15:58 highly-optimized  
highly-optimized: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=b7adbc992d67014542b769741cb27404014c187c, for GNU/Linux 3.2.0,  
stripped  
```

Nice! It's something my computer can run. After running in `strace`, last  
thing we see is the following:

```  
write(1, "I will tell you the flag, if you"..., 69I will tell you the flag,  
if you don't mind waiting a few moments...  
) = 69  
```

One CPU gets maxed out and nothing else happens. I have less than two days  
for this task, so waiting isn't an option.

## 2. Decompiling

I'm not well versed with x86 assembly, so I reached for a decompiler. I  
uploaded the binary to DogBolt and got the following:

<https://dogbolt.org/?id=72d91063-cf12-4ecc-8119-7a142d056ab7>

I looked through the outputs and found that I liked code made by HexRays the  
most. I put a copy of the output here:

<https://github.com/hakierspejs/ctf-uoftctf-2025-highlyoptimized/commit/1c95>

## 3. Making it run

Trying to compile the code results in GCC complaining that it can't find  
defs.h. I found a working copy here:

<https://github.com/nihilus/hexrays_tools/blob/master/code/defs.h>

I checked it in, pointed the compiler to it, then commented out a couple of  
stubs that made the program actually compile (commit ea41 from the linked  
repository).

## 4. Asking ChatGPT for help

I asked ChatGPT-4o the following question: "I'm doing ctf. How to understand  
this decompiled program?", followed by a copy of main(). Here's a part of  
what it told me:

3\. **Control Flow**:  
\- The `while (1)` loop indicates continuous execution until a `return` or  
a break condition is met.  
\- The program seems to act on `qword_4020[v4]`, possibly an array of  
instructions or operations.

4\. **Switch Statement**:  
\- Each case seems to indicate an operation based on the value  
in `qword_4020[v4]`:  
\- **Case 0**: Loads data, increments counters, and stores into the `v10`.  
\- **Case 1**: Copies an element from `v10` to the next position.  
\- **Case 2**: Subtracts one element of `v10` from another.  
\- **Case 3**: Compares elements for a conditional operation.  
\- **Case 4**: Controls a loop or conditional execution (like a jump).  
\- **Case 5**: Outputs a character to standard output (`putchar`).  
\- **Case 6**: Ends the loop and program (`return`).

5\. **Interpretation**:  
\- This code is likely implementing a kind of bytecode interpreter or  
virtual machine, cycling through commands in `qword_4020`.  
\- It simulates execution of a language with stack-like operations,  
executing cases based on the bytecode.

With that knowledge, I experimented with renaming variables in this code and  
the result was commit 523f.

## 5. Adding log messages

In commit 969d, I added a couple of optional printfs. I put the output in  
step 7, because it's more relevant there.

## 6. "hello, world"

Consider this:

```C  
_QWORD code[265] =  
{  
OP_PUSH_VALUE,  
58541471996096977LL,  
OP_PUSH_VALUE,  
131LL,  
OP_SUBTRACT,  
OP_DUP_VALUE,  
OP_PUSH_VALUE,  
131LL,  
OP_CMP,  
OP_JNZ,  
9LL,  
OP_PUTCHAR,  
OP_PUSH_VALUE,  
42044768350026761LL,  
OP_PUSH_VALUE,  
130LL,  
OP_SUBTRACT,  
OP_DUP_VALUE,  
OP_PUSH_VALUE,  
130LL,  
OP_CMP,  
OP_JNZ,  
9LL,  
OP_PUTCHAR,  
```

We can see a pattern: two values (one huge, one small) are pushed, they're  
substracted from each other, the result is duplicated and it's compared to  
the small number. If it's larger, we we jump back by nine instructions.  
Otherwise, we print whatever we have on the top of the stack.

In order to see if our understanding is correct, let's add those three lines  
and see if we get a digit '3':

```C  
_QWORD code[265] =  
{  
// example that prints digit '3' (0x33):  
OP_PUSH_VALUE,  
0x33LL,  
OP_PUTCHAR,  
```

Unfortunately, that failed. I suspected that it might have something to do  
with buffering, so I added fflush(stdout). Now it works! This is documented  
in commit 51fe.

## 7. Trying to optimize the program

Here's what we can see if we run `make DEBUG=1`:

```  
[ip=0 sp=0] push -1695239727  
[ip=2 sp=1] push 131  
[ip=4 sp=2] sub -1695239858  
[ip=5 sp=1] dup -1695239858  
[ip=6 sp=2] push 131  
[ip=8 sp=3] cmp 1  
[ip=9 sp=2] jnz -1695239858  
[ip=2 sp=1] push 131  
[ip=4 sp=2] sub -1695239989  
[ip=5 sp=1] dup -1695239989  
[ip=6 sp=2] push 131  
[ip=8 sp=3] cmp 1  
[ip=9 sp=2] jnz -1695239989  
[ip=2 sp=1] push 131  
[ip=4 sp=2] sub -1695240120  
[ip=5 sp=1] dup -1695240120  
[ip=6 sp=2] push 131  
[ip=8 sp=3] cmp 1  
```

It looks like the reasoning is correct: we're in a loop and the top of the  
stack keeps decreasing by 131. Since the value is stored in a 64-bit integer,  
it's going to take a while...

Let's remove the puts() call and see if we can modify the code so that we can  
print the first character.

What would happen if we replaced 58541471996096977LL with 0LL?

```  
> sed -i 's/58541471996096977LL/0LL/' -i highlyoptimized.c  
> make ; ./highlyoptimized | head -c1 | hexdump -C  
cc -I. -w highlyoptimized.c -o highlyoptimized  
^C  
```

The program freezes. How about 131?

```  
> sed -i 's/58541471996096977LL/131LL/' -i highlyoptimized.c  
> make ; ./highlyoptimized | head -c1 | hexdump -C  
cc -I. -w highlyoptimized.c -o highlyoptimized  
00000000 00 |.|  
00000001  
^C  
```

137?

```  
> sed -i 's/58541471996096977LL/132LL/' -i highlyoptimized.c  
> make ; ./highlyoptimized | head -c1 | hexdump -C  
cc -I. -w highlyoptimized.c -o highlyoptimized  
00000000 01 |.|  
00000001  
^C  
> rm highlyoptimized ; make DEBUG=1 ; ./highlyoptimized | head  
cc -I. -w -DDEBUG highlyoptimized.c -o highlyoptimized  
[ip=0 sp=0] push 137  
[ip=2 sp=1] push 131  
[ip=4 sp=2] sub 6  
[ip=5 sp=1] dup 6  
[ip=6 sp=2] push 131  
[ip=8 sp=3] cmp 0  
[ip=9 sp=2] jnz 6  
[ip=11 sp=1] putchar 0  
[ip=12 sp=0] push 2049621001  
[ip=14 sp=1] push 130  
```

## 8. Observing the loop

Here's what it looks like for 270:

```  
> make DEBUG=1 ; ./highlyoptimized | head -n 20  
cc -I. -w -DDEBUG highlyoptimized.c -o highlyoptimized  
[ip=0 sp=0] push 270  
[ip=2 sp=1] push 131  
[ip=4 sp=2] sub 139  
[ip=5 sp=1] dup 139  
[ip=6 sp=2] push 131  
[ip=8 sp=3] cmp 1  
[ip=9 sp=2] jnz 139  
[ip=2 sp=1] push 131  
[ip=4 sp=2] sub 8  
[ip=5 sp=1] dup 8  
[ip=6 sp=2] push 131  
[ip=8 sp=3] cmp 0  
[ip=9 sp=2] jnz 8  
[ip=11 sp=1]putchar 0  
```

Observe that 270 % 131 == 8. Are we looking at a very inefficient modulo  
implementation?

## 9. Extracting the numbers

With the aid of ChatGPT, I wrote this spell that prints lines ending with LL  
that are between a line matching ^_QWORD and ^}:

```  
> awk '/^_QWORD/{flag=1} flag && /^ +[0-9]+LL,$/{print} /^}/{flag=0}' \  
highlyoptimized.c | grep -v ' 9LL,' | uniq  
270LL,  
131LL,  
42044768350026761LL,  
130LL,  
104093991169115492LL,  
146LL,  
128563766204312876LL,  
120LL,  
118183210859642192LL,  
121LL,  
31759579751918036LL,  
160LL,  
37922191436980238LL,  
143LL,  
139168641091494270LL,  
147LL,  
152909243010516658LL,  
138LL,  
88946238250907572LL,  
163LL,  
179824179782506694LL,  
170LL,  
45174131531571636LL,  
52LL,  
58562759984008198LL,  
65LL,  
60481677685756789LL,  
120LL,  
67459793699055203LL,  
141LL,  
33046999828954552LL,  
137LL,  
67963425659164234LL,  
135LL,  
43796972412552174LL,  
117LL,  
6408227318773632LL,  
68LL,  
75570635003173892LL,  
68LL,  
26842364308653847LL,  
122LL,  
60541299067063520LL,  
147LL,  
```

I excluded 9LL because it's the argument for the jump instruction. After  
deduplication, we have a nice set of (large_num, small_num) pairs.

## 10. Calculating the flag

```python  
#!/usr/bin/env python3

"""Extracts the flag from a modified version of highlyoptimized.c"""

import re

stack = []

def handle_mod(a, b):  
n = a % b  
print(chr(n), end='')

with open('highlyoptimized.c', 'r') as f:  
flag = False  
last_line = ''  
for line in f:  
if re.match(r'^_QWORD', line):  
flag = True  
if flag and re.match(r' +[0-9]+LL,$', line):  
# ignore the line with 9LL and duplicates  
if not re.match(r' 9LL,', line) and last_line != line:  
# remove LL, and spaces, convert to int  
num = int(re.sub(r'LL,', '', re.sub(r' +', '', line)))  
stack.append(int(num))  
if len(stack) == 2:  
handle_mod(stack[0], stack[1])  
stack = []  
last_line = line  
if re.match(r'}', line):  
flag = False  
print()  
```

Running the program gives us... the flag!

## 11. Bonus: how long would it take?

I was curious how long it would take for the program to complete, so I wrote the following:

```  
/*  
* optimized equivalent of:  
*  
OP_PUSH_VALUE,  
58541471996096977LL;  
OP_PUSH_VALUE,  
131LL,  
OP_SUBTRACT,  
OP_DUP_VALUE,  
OP_PUSH_VALUE,  
131LL,  
OP_CMP,  
OP_JNZ,  
9LL  
*/

#include <stdio.h>  
#include <time.h>

int main() {  
long int a, orig;  
a = orig = 58541471996096977LL;  
long int b = 131;  
long int iterations = 0;  
int started = time(NULL);  
while (a > b) {  
iterations++;  
if (iterations % (1000 * 1000 * 1000) == 0) {  
int epoch = time(NULL);  
int elapsed = epoch - started;  
if (elapsed == 10) {  
break;  
}  
printf("iterations: %ld, a: %ld, epoch: %d\n", iterations, a, epoch);  
}  
a -= b;  
}  
long int difference = orig - a;  
int hours = orig / difference / 3600;  
printf("hours: %d\n", hours); // prints "10" on my computer  
return 0;  
}  
```

I guess that settles is. Solving is better than waiting in this case.   
Keep in mind that the original program would also be executing the  
bytecode and would only print the flag if it finished all the computing!

\---

As someone who wasn't yet introduced to proper reverse engineering, I loved  
this task! It encouraged me to learn something new and gave me a bit of  
confidence. I think that the next step would be to write something similar,  
but for an unkown OS and CPU architecture, with an implementation of VM that's  
slightly less friendly for decompilers and maybe a bytecode that needs to  
actually be run in order to extract the flag. Anyway, thanks!

\---

Here's the .tar.xz copy of the git repository, base64-encoded:

```  
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  
AAAEWVo=  
```
