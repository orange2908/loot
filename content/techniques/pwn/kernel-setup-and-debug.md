---
title: "Linux Kernel Pwn - Setup, initramfs, QEMU and Debugging"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, qemu, initramfs, cpio, vmlinux, bzImage, gdb, kgdb, kallsyms, ioctl, lkm, static-compile, kaslr, smep, smap, kpti, pwndbg, gef, pwntools]
difficulty: medium
summary: "Unpack and repack the initramfs, read the run script, extract vmlinux, attach gdb, find the module base, and ship a static exploit into the VM."
when_to_use:
  - "A challenge ships bzImage + initramfs.cpio.gz + run.sh and a .ko driver"
  - "You need to get a root shell inside the VM to develop the exploit"
  - "gdb attaches but every symbol is ???"
  - "You need the runtime load address of the vulnerable module"
tools: [qemu, gdb, pwndbg, gef, cpio, gcc, extract-vmlinux, musl-gcc]
related: [kernel-mitigations, kernel-ret2usr-creds, kernel-rop-kpti-trampoline, kernel-slub-uaf-objects, kernel-pwn-cheatsheet]
---

## TL;DR

Kernel pwn challenges are: a `bzImage`, an `initramfs.cpio.gz` containing `/init` and
a vulnerable `.ko`, and a `run.sh` with the QEMU command line. Your loop is: unpack
initramfs -> add your statically-compiled exploit -> repack -> `./run.sh` -> if it
fails, re-run with `-s` and attach gdb against `vmlinux`. Everything else in kernel pwn
is downstream of getting this loop fast.

## Recognise it

- The archive contains `bzImage`, `initramfs.cpio.gz` (or `.cpio`, `rootfs.img`),
  `run.sh`/`boot.sh`/`start.sh`, and often a `*.ko` plus its source.
- `run.sh` contains `qemu-system-x86_64 -kernel bzImage -initrd ...`.
- `/init` inside the initramfs does `insmod /vuln.ko` and drops to a non-root shell.
- The flag is at `/root/flag` or `/flag` with mode 400, owned by root.

## Vulnerable code shape

The driver almost always looks like this:

```c
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#define VULN_ALLOC 0x1000
#define VULN_FREE  0x1001
#define VULN_READ  0x1002
#define VULN_WRITE 0x1003

struct req { unsigned long idx, size; void __user *buf; };

static char *slots[16];

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct req r;
    if (copy_from_user(&r, (void __user *)arg, sizeof r))
        return -EFAULT;

    switch (cmd) {
    case VULN_ALLOC:
        slots[r.idx] = kmalloc(r.size, GFP_KERNEL);   /* r.idx unchecked -> OOB */
        return 0;
    case VULN_FREE:
        kfree(slots[r.idx]);                          /* no NULL -> UAF */
        return 0;
    case VULN_READ:
        return copy_to_user(r.buf, slots[r.idx], r.size);   /* OOB read */
    case VULN_WRITE:
        return copy_from_user(slots[r.idx], r.buf, r.size); /* heap overflow */
    }
    return -EINVAL;
}
```

## Theory

### Reading `run.sh`

```bash
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 root=/dev/ram oops=panic panic=1 kaslr quiet" \
    -cpu qemu64,+smep,+smap \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -s
```

| flag | meaning for you |
|------|-----------------|
| `-m 128M` | RAM. Small RAM makes slab grooming tighter, physmap guessing harder. |
| `-kernel bzImage` | compressed image; extract `vmlinux` from it for symbols. |
| `-initrd ...` | the root filesystem - where your exploit binary goes. |
| `-append "..."` | `nokaslr` = KASLR off; `pti=on`/`kpti=1` = KPTI on, `nopti` = off; `oops=panic panic=1` = one oops kills the VM. |
| `-cpu qemu64,+smep,+smap` | SMEP/SMAP on. Plain `qemu64` means both are off. |
| `-s` | shorthand for `-gdb tcp::1234`. If absent, add it locally. |
| `-no-reboot` / `-nographic` | stop on panic; serial console on stdio. |
| `-monitor /dev/null` | stops you reaching the QEMU monitor with Ctrl-A C. |

**Always make a local copy of `run.sh`** with `-s`, `nokaslr`, and `-cpu qemu64` (no
smep/smap) so you can develop the bug first and add the mitigations back one at a time.

### initramfs surgery

Detect the compression before anything else - `file initramfs.cpio.gz` may lie.

```bash
file initramfs.cpio.gz            # gzip / XZ / LZ4 / raw "ASCII cpio archive"
```

```bash
# unpack (pick the decompressor `file` told you about)
mkdir fs && cd fs
gzip -dc ../initramfs.cpio.gz  | cpio -idmv       # gzip
xz   -dc ../initramfs.cpio.xz  | cpio -idmv       # xz
lz4  -dc ../initramfs.cpio.lz4 | cpio -idmv       # lz4
cpio -idmv < ../initramfs.cpio                    # uncompressed

# repack: --format=newc and --null are both load-bearing
find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../initramfs.cpio.gz
```

### Getting root inside the VM for development

Edit `fs/init`. Its last line is usually
`setsid /bin/cttyhack setuidgid 1000 /bin/sh` - change `1000` to `0` and you boot as
root, so `/proc/kallsyms`, `dmesg` and module symbols all work.
**Change it back** before testing the real exploit. Also useful in `init`:

```sh
echo 0 > /proc/sys/kernel/kptr_restrict      # kallsyms shows real addresses
echo 0 > /proc/sys/kernel/dmesg_restrict     # dmesg readable
```

### vmlinux and symbols

`bzImage` is a compressed, self-extracting image; gdb cannot read it. Extract:

```bash
# from the kernel source tree: scripts/extract-vmlinux
curl -sO https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
chmod +x extract-vmlinux
./extract-vmlinux ./bzImage > vmlinux
file vmlinux            # should say "ELF 64-bit LSB executable, statically linked"
```

Then:

```
$ gdb ./vmlinux
pwndbg> target remote :1234
pwndbg> p &commit_creds
pwndbg> p &prepare_kernel_cred
pwndbg> p/x (long)&commit_creds - 0xffffffff81000000     # the offset from _text
```

If KASLR is on, symbols are wrong until you rebase. The kernel text base is
`0xffffffff81000000 + slide`; find the slide by breaking anywhere and reading a known
symbol from `/proc/kallsyms` inside the VM (as root), or with
`pwndbg> p $rip` in an interrupt handler.

### Finding a module's load address

Inside the VM:

```sh
cat /proc/modules                       # "vuln 16384 0 - Live 0xffffffffc0000000"
cat /sys/module/vuln/sections/.text     # the .text base (root only)
grep vuln /proc/kallsyms
```

In gdb:

```
pwndbg> add-symbol-file ./vuln.ko 0xffffffffc0000000
pwndbg> b vuln_ioctl
```

### Compiling the exploit

The initramfs usually has no libc beyond busybox's, so link statically:

```bash
gcc -static -O2 -no-pie -o exp exp.c
# smaller, if musl is available:
musl-gcc -static -O2 -o exp exp.c
strip exp
```

Copy it into `fs/`, `chmod +x`, repack. For a size-constrained initramfs, compress the
binary with `gzip` and have `init` decompress it, or base64 it in over the serial
console with `base64 -d`.

## Attack

The development loop, start to finish:

1. `mkdir fs; cd fs; gzip -dc ../initramfs.cpio.gz | cpio -idmv`
2. `cat init` - note the `insmod`, the device node, and the uid it drops to.
3. Read the driver source (or reverse `vuln.ko` with Ghidra) and list the ioctls.
4. Write `exp.c` with ioctl wrappers; compile with `gcc -static`.
5. `cp exp fs/exp; cd fs; find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz`
6. `./run.sh` and run `/exp`.
7. When it crashes: add `-s` to the qemu line, boot, `gdb vmlinux -ex 'target remote :1234'`,
   `add-symbol-file vuln.ko <base>`, break on the ioctl handler.
8. Iterate. Re-enable `kaslr`, `+smep`, `+smap`, `pti=on` one at a time.

## Heap state

```text
  chal/
    bzImage              -> extract-vmlinux -> vmlinux (symbols for gdb)
    initramfs.cpio.gz    -> cpio -idmv       -> fs/init, fs/vuln.ko, fs/exp
    run.sh                                      (the qemu command line)

  memory map inside the guest (KASLR off)

    0x0000000000000000  user space  (your exploit, mmap, stack)
    0x00007fff........  user stack
    ------------------- SMAP/SMEP boundary -------------------
    0xffff888000000000  physmap: direct map of all physical RAM
    0xffffc90000000000  vmalloc / ioremap
    0xffffffff81000000  kernel .text  (_text)
    0xffffffff82000000  kernel .data/.bss  (modprobe_path lives here)
    0xffffffffc0000000  loadable modules (vuln.ko)
```

## Exploit

A skeleton `exp.c` that opens the device, wraps the ioctls, and reports symbols.

```c
/* exp.c - kernel pwn scaffolding.
 * Build: gcc -static -O2 -no-pie -o exp exp.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE "/dev/vuln"

#define VULN_ALLOC 0x1000
#define VULN_FREE  0x1001
#define VULN_READ  0x1002
#define VULN_WRITE 0x1003

struct req {
    unsigned long idx;
    unsigned long size;
    void *buf;
};

static int fd = -1;

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void dev_open(void)
{
    fd = open(DEVICE, O_RDWR);
    if (fd < 0)
        die("open " DEVICE);
}

static long v_alloc(unsigned long idx, unsigned long size)
{
    struct req r = { .idx = idx, .size = size, .buf = NULL };
    return ioctl(fd, VULN_ALLOC, &r);
}

static long v_free(unsigned long idx)
{
    struct req r = { .idx = idx, .size = 0, .buf = NULL };
    return ioctl(fd, VULN_FREE, &r);
}

static long v_read(unsigned long idx, void *buf, unsigned long size)
{
    struct req r = { .idx = idx, .size = size, .buf = buf };
    return ioctl(fd, VULN_READ, &r);
}

static long v_write(unsigned long idx, void *buf, unsigned long size)
{
    struct req r = { .idx = idx, .size = size, .buf = buf };
    return ioctl(fd, VULN_WRITE, &r);
}

/* Read a symbol address from /proc/kallsyms. Needs kptr_restrict == 0,
 * which is usually only true while you are developing as root. */
static unsigned long ksym(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[512], sym[256], type;
    unsigned long addr = 0, val;

    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx %c %255s", &val, &type, sym) != 3)
            continue;
        if (strcmp(sym, name) == 0) {
            addr = val;
            break;
        }
    }
    fclose(f);
    return addr;
}

/* Pin ourselves to one CPU: slab grooming is per-CPU and this removes
 * an entire class of flaky behaviour. */
static void pin_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof set, &set) < 0)
        die("sched_setaffinity");
}

int main(void)
{
    unsigned long commit_creds, prepare_kernel_cred, modprobe;
    char buf[0x100];

    pin_cpu0();
    dev_open();

    commit_creds = ksym("commit_creds");
    prepare_kernel_cred = ksym("prepare_kernel_cred");
    modprobe = ksym("modprobe_path");
    printf("[+] commit_creds        = %#lx\n", commit_creds);
    printf("[+] prepare_kernel_cred = %#lx\n", prepare_kernel_cred);
    printf("[+] modprobe_path       = %#lx\n", modprobe);

    /* Minimal smoke test of the ioctl surface. */
    if (v_alloc(0, 0x100) < 0)
        die("VULN_ALLOC");
    memset(buf, 'A', sizeof buf);
    if (v_write(0, buf, 0x100) < 0)
        die("VULN_WRITE");
    memset(buf, 0, sizeof buf);
    if (v_read(0, buf, 0x100) < 0)
        die("VULN_READ");
    printf("[+] round trip ok: %.4s\n", buf);
    v_free(0);

    puts("[*] scaffolding works - now write the actual exploit");
    return 0;
}
```

Supporting shell scripts:

```bash
#!/bin/sh
# build.sh - compile, inject into the initramfs, boot.
set -e

# static link: the initramfs has no shared libc
gcc -static -O2 -no-pie -o exp exp.c
strip exp

# refresh the extracted filesystem copy of the exploit
cp exp fs/exp
chmod +x fs/exp

# repack: newc format is what the kernel's initramfs loader expects
( cd fs && find . -print0 | cpio --null -ov --format=newc 2>/dev/null ) \
    | gzip -9 > initramfs.cpio.gz

# boot with a gdb stub on :1234 and KASLR disabled for development
qemu-system-x86_64 \
    -m 128M \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=1 nokaslr quiet" \
    -cpu qemu64 \
    -nographic -no-reboot -s
```

```bash
#!/bin/sh
# debug.sh - attach gdb with module symbols already loaded.
# Usage: ./debug.sh 0xffffffffc0000000
MODBASE="${1:-0xffffffffc0000000}"
gdb ./vmlinux -ex "target remote :1234" \
    -ex "add-symbol-file ./fs/vuln.ko $MODBASE" -ex "b vuln_ioctl" -ex "c"
```

## Variants & pitfalls

- **`cpio: Malformed number`** on repack = wrong format. It must be `--format=newc`.
- **Permissions are lost.** `cpio -idmv` as a normal user cannot restore ownership;
  `init` runs as root and recreates what it needs, but **do** `chmod +x` your exploit.
- **`gdb` shows `??` everywhere** = you are debugging `bzImage`, not `vmlinux`.
- **Breakpoints never hit with KASLR on.** Boot with `nokaslr` while developing.
- **`oops=panic panic=1`** kills the VM on the first bad dereference with no backtrace
  scroll. Remove it locally so you can read the oops.
- **`/proc/kallsyms` returns all zeros** as an unprivileged user (`kptr_restrict=1`).
  That is the intended state; your exploit must not depend on it.
- **The flag is readable only by root**, so `id` printing `uid=0` is not enough -
  `cat /root/flag` is the proof.
- **Slab noise.** Other processes allocate too. `pin_cpu0()` and a tight spray loop
  remove most of the flakiness.

## Debugging

```text
pwndbg> target remote :1234
pwndbg> add-symbol-file ./vuln.ko 0xffffffffc0000000
pwndbg> b vuln_ioctl
pwndbg> p &commit_creds
pwndbg> x/s &modprobe_path
pwndbg> p/x $cr4                     # bit 20 = SMEP, bit 21 = SMAP
pwndbg> bt
pwndbg> x/32gx $rsp
pwndbg> lx-dmesg                     # needs scripts/gdb from the kernel tree
```

```bash
# Inside the VM, as root, during development:
cat /proc/modules
cat /sys/module/vuln/sections/.text
grep -E 'commit_creds|prepare_kernel_cred|modprobe_path' /proc/kallsyms
dmesg | tail -40
cat /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict
```

## Tools

- `qemu-system-x86_64`, `gdb` with `pwndbg` or `gef`.
- `scripts/extract-vmlinux` from the kernel tree; `vmlinux-to-elf` when that produces
  a symbol-less binary (it rebuilds the symbol table from the embedded kallsyms).
- `Ghidra` / `IDA` for the `.ko`; `musl-gcc` for small static binaries.

## References

- Linux kernel documentation: `Documentation/admin-guide/kernel-parameters.txt`.
- `scripts/extract-vmlinux` and `scripts/gdb/` in the kernel source tree.
