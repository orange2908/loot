---
title: "unoriginal - ImaginaryCTF 2024"
category: "crypto"
subcategory: "static-analysis"
type: "writeup"
tags: ["crypto", "xor", "pie", "ghidra", "lsb", "gets", "static-analysis", "imaginaryctf", "imaginaryctf-2024", "2024", "ctf-writeup"]
summary: "We are given unoriginal and running file on it yields"
source:
  name: "CTFtime writeup #39339"
  url: "https://ctftime.org/writeup/39339"
ctf:
  name: "ImaginaryCTF 2024"
  year: 2024
  challenge: "unoriginal"
---

## Metadata

- **CTF:** ImaginaryCTF 2024
- **Task:** unoriginal
- **Author team:** 2amResearch
- **CTFtime:** <https://ctftime.org/writeup/39339>

---
We are given `unoriginal` and running file on it yields

```bash  
┌──(kali㉿kali)-[~/Desktop]  
└─$ file unoriginal   
unoriginal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e62dc74b0e909a63a0fc240a62ee75ab47936823, for GNU/Linux 3.2.0, not stripped  
```

When running the binary we are prompted to enter a value (assuming it's the flag).

```bash  
┌──(kali㉿kali)-[~/Desktop]  
└─$ ./unoriginal   
Enter your flag here: asdasdasd  
Incorrect.  
```

Running `strings` on the binary gives us a clue.

```text  
┌──(kali㉿kali)-[~/Desktop]  
└─$ strings unoriginal   
....  
Enter your flag here:   
lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx  
Correct!  
Incorrect.  
.....  
```

The idea here is that maybe the string ```lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx``` is used in a string comparison and the flag may get printed out. Let's give it a try:

```bash  
┌──(kali㉿kali)-[~/Desktop]  
└─$ ./unoriginal   
Enter your flag here: lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx  
Incorrect.  
```

Time to run the binary through Ghidra. After analysis we find the `main` function and see if we can find our interesting string.

```c  
undefined8 main(void)

{  
int iVar1;  
long in_FS_OFFSET;  
int local_4c;  
byte local_48 [56];  
long local_10;  
  
local_10 = *(long *)(in_FS_OFFSET + 0x28);  
printf("Enter your flag here: ");  
gets((char *)local_48);  
for (local_4c = 0; local_4c < 0x30; local_4c = local_4c + 1) {  
local_48[local_4c] = local_48[local_4c] ^ 5;  
}  
iVar1 = strcmp((char *)local_48,"lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx");  
if (iVar1 == 0) {  
puts("Correct!");  
}  
else {  
puts("Incorrect.");  
}  
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
/* WARNING: Subroutine does not return */  
__stack_chk_fail();  
}  
return 0;  
}  
```

From the code above it looks like the flag is being xor'd with the value 5 and then compared with the string we found earlier. A simple python script reverses the value and gets the flag.

```python  
inputStr = 'lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx'

flag = []  
for c in inputStr:  
charInt = ord(c)  
nextInt = charInt ^ 5  
flag.append(chr(nextInt))

print(''.join(flag))  
```

FLAG: `ictf{just_another_flag_checker_a3465d5e5ee234ba}`
