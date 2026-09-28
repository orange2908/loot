---
title: "guess-what (rev) | TJCTF 2024 - TJCTF 2024"
category: "misc"
subcategory: "static-analysis"
type: "writeup"
tags: ["misc", "ghidra", "scanf", "guess-what", "rev", "tjctf", "static-analysis", "tjctf-2024", "2024", "ctf-writeup"]
summary: "In this challenge you will get a a netcat and a linux binary file and once run"
source:
  name: "CTFtime writeup #39155"
  url: "https://ctftime.org/writeup/39155"
ctf:
  name: "TJCTF 2024"
  year: 2024
  challenge: "guess-what (rev) | TJCTF 2024"
---

## Metadata

- **CTF:** TJCTF 2024
- **Task:** guess-what (rev) | TJCTF 2024
- **Author team:** Seraphiem
- **CTFtime:** <https://ctftime.org/writeup/39155>

---
In this challenge you will get a a netcat and a linux binary file and once run 

```  
welcome to the guessing game!  
guess what I'm thinking  
```

The main focus of this challenge is the binary file and using ghidra we could dump the binary and get a rough c code but for this challenge its we got the logic right away.

```  
undefined8 main(void)

{  
int iVar1;  
undefined8 uVar2;  
long in_FS_OFFSET;  
int local_a4;  
FILE *local_a0;  
char local_98 [64];  
char local_58 [72];  
long local_10;  
  
local_10 = *(long *)(in_FS_OFFSET + 0x28);  
setbuf(stdout,(char *)0x0);  
puts("welcome to the guessing game!");  
puts("guess what I\'m thinking");  
fgets(local_98,0x40,stdin);  
iVar1 = strcmp(local_98,"nuh uh pls nolfjdl\n");  
if (iVar1 == 0) {  
puts("please guess a number between 0 and 100:");  
__isoc99_scanf(&DAT_00102089,&local_a4);  
if ((int)(0x17a / (long)local_a4) + 3 == local_a4) {  
puts("congratulations! you guessed the correct number!");  
}  
else {  
puts("sorry, you guessed the wrong number!");  
}  
local_a0 = fopen("flag.txt","r");  
if (local_a0 == (FILE *)0x0) {  
puts("flag.txt not found - ping us on discord if you are running this on the server");  
uVar2 = 1;  
}  
else {  
fgets(local_58,0x40,local_a0);  
puts(local_58);  
uVar2 = 0;  
}  
}  
else {  
puts("nuh uh!");  
uVar2 = 1;  
}  
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
/* WARNING: Subroutine does not return */  
__stack_chk_fail();  
}  
return uVar2;  
}  
```

here on

```  
puts("welcome to the guessing game!");  
puts("guess what I\'m thinking");  
fgets(local_98,0x40,stdin);  
iVar1 = strcmp(local_98,"nuh uh pls nolfjdl\n");  
```

we got a fgets and it will get a value local_98 and a string **"nuh uh pls nolfjdl"** and entering **"nuh uh pls nolfjdl"** we get the:

> please guess a number between 0 and 100:

```  
if ((int)(0x17a / (long)local_a4) + 3 == local_a4) {  
puts("congratulations! you guessed the correct number!");  
}  
else {  
puts("sorry, you guessed the wrong number!");  
}  
```

this is dosen't need to be overcomplicated because what ever you'll do it will go to the end to the:

```  
local_a0 = fopen("flag.txt","r");  
```

\--------------------------------------------------------------------------  
Full output:

```  
$ nc [tjc.tf](http://tjc.tf) 31478  
welcome to the guessing game!  
guess what I'm thinking  
nuh uh pls nolfjdl  
please guess a number between 0 and 100:  
90  
sorry, you guessed the wrong number!  
tjctf{n3v3r_c0uld_r34d_y0ur_m1nd_8e6646a1}  
```

> tjctf{n3v3r_c0uld_r34d_y0ur_m1nd_8e6646a1}
