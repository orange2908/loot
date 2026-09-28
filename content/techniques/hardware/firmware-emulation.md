---
title: "Firmware Emulation - qemu-user, qemu-system, chroot and FAT"
category: hardware
subcategory: firmware
type: technique
tags: [qemu, qemu-user, qemu-system, chroot, binfmt-misc, firmadyne, firmware-analysis-toolkit, emulation, mips, arm, nvram, libnvram, gdbserver, buildroot, openwrt]
difficulty: hard
summary: "Run a router binary or a whole firmware image on your host with qemu-user or qemu-system so you can debug and exploit it interactively."
when_to_use:
  - "You extracted a rootfs and want to run the web server or a CGI binary"
  - "You need a live target to fuzz or debug instead of static analysis"
  - "The challenge expects you to reach a service the image would expose"
tools: [qemu, qemu-user-static, chroot, gdb-multiarch, firmadyne, fat]
related: [firmware-extraction, firmware-arch-identification, uart-serial, mcu-reversing]
---

## TL;DR

Two levels. **qemu-user** runs a single binary using your host kernel - fast, easy, and
enough for most CGI/httpd challenges: `chroot rootfs ./qemu-mipsel-static /usr/sbin/httpd`.
**qemu-system** boots a whole kernel + rootfs - slower, needs a matching kernel and a
board model, but survives binaries that need real devices. Most failures come from
missing NVRAM, missing `/dev` nodes, and the wrong endianness.

## Recognise it

- You have an extracted rootfs with `bin/busybox` and a web server in `usr/sbin/`.
- `file bin/busybox` says e.g.
  `ELF 32-bit MSB executable, MIPS, MIPS32 ... dynamically linked, interpreter /lib/ld-uClibc.so.0`.
- The challenge description mentions a web UI, a port, or "get a shell on the device".
- Static analysis found a command injection in a CGI and you want to prove it.

## Theory

### Choosing the mode

| | qemu-user | qemu-system |
|---|---|---|
| runs | one process | a whole kernel + userland |
| speed | near native | slow |
| needs | matching `qemu-<arch>-static` | kernel image + dtb/board model |
| syscalls | translated to the host kernel | real guest kernel |
| `/proc`, `/sys` | host's (often wrong) | guest's (correct) |
| device access (`/dev/mtd`, nvram ioctls) | fails | works if modelled |
| networking | host's | user-mode or tap |

Start with qemu-user. Escalate only when the binary needs real devices.

### Architecture to qemu binary

| `file` output | qemu-user | qemu-system |
|---|---|---|
| MIPS, MSB (big endian) | `qemu-mips-static` | `qemu-system-mips` |
| MIPS, LSB (little endian) | `qemu-mipsel-static` | `qemu-system-mipsel` |
| ARM, LSB, EABI | `qemu-arm-static` | `qemu-system-arm` |
| ARM aarch64 | `qemu-aarch64-static` | `qemu-system-aarch64` |
| PowerPC, MSB | `qemu-ppc-static` | `qemu-system-ppc` |
| x86-64 | native | `qemu-system-x86_64` |

`-static` matters: a dynamically linked qemu cannot run inside the target chroot.

### Why binaries crash immediately

1. **Missing NVRAM** - the binary calls `nvram_get("lan_ipaddr")`, gets NULL, and
   segfaults. Fix with `libnvram.so` preloaded via `LD_PRELOAD`, which fakes a key/value
   store backed by a directory.
2. **Missing `/dev`** - `/dev/null`, `/dev/urandom`, `/dev/console`, `/dev/nvram`,
   `/dev/mtd*` must exist. Bind-mount or `mknod` them.
3. **Missing `/proc`** - many binaries read `/proc/net/dev` or `/proc/cpuinfo`.
4. **Hardware ioctls** on `/dev/mtd` or a custom driver - only fixable in system mode,
   or by patching the binary.
5. **Watchdog** - the process exits after N seconds unless a watchdog device is kicked.
6. **Wrong library path** - the interpreter is `/lib/ld-uClibc.so.0` which must exist
   *inside the chroot*, at that exact path.

## Attack

1. Identify the architecture from any ELF in the rootfs (`file bin/busybox`).
2. Copy the matching static qemu into the rootfs and chroot into it.
3. Run `/bin/sh` first to prove the chroot works.
4. Run the target binary; read the failure and fix `/dev`, `/proc`, NVRAM in that order.
5. Expose the port (`-p` with qemu-user is not a thing - use the host network, the
   process binds on your host directly).
6. When you have it listening, curl it, then attack it.
7. Attach `gdb-multiarch` through `qemu-<arch> -g 1234` for debugging.

## Code

### qemu-user + chroot

```bash
#!/bin/sh
# emulate-user.sh - run a binary from an extracted rootfs with qemu-user
set -eu
ROOT="${1:?usage: emulate-user.sh ./rootfs /usr/sbin/httpd}"
TARGET="${2:-/bin/sh}"

# 1. which architecture?
file "$ROOT/bin/busybox" 2>/dev/null || file "$ROOT/bin/sh"

# 2. pick the qemu binary (adjust after reading the file output)
case "$(file -b "$ROOT/bin/busybox" 2>/dev/null)" in
  *"MIPS"*"MSB"*)   QEMU=qemu-mips-static ;;
  *"MIPS"*"LSB"*)   QEMU=qemu-mipsel-static ;;
  *"ARM"*"aarch64"*) QEMU=qemu-aarch64-static ;;
  *"ARM"*)          QEMU=qemu-arm-static ;;
  *"PowerPC"*)      QEMU=qemu-ppc-static ;;
  *)                QEMU=qemu-mipsel-static ;;
esac
echo "using $QEMU"

# 3. copy qemu into the rootfs so it is reachable after chroot
cp "$(which $QEMU)" "$ROOT/"

# 4. minimal runtime environment
mkdir -p "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/tmp" "$ROOT/var/run"
mount -t proc none "$ROOT/proc" 2>/dev/null || mount --bind /proc "$ROOT/proc"
mount --bind /sys "$ROOT/sys"
mount --bind /dev "$ROOT/dev"

# 5. sanity check: a shell must work before anything else will
chroot "$ROOT" "/$QEMU" /bin/sh -c 'echo chroot-ok; id; ls /'

# 6. run the real target
chroot "$ROOT" "/$QEMU" "$TARGET" || echo "exit code $?"

# 7. cleanup
umount "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" 2>/dev/null || true
```

```bash
# run a single binary without chroot, giving qemu the library path
qemu-mipsel-static -L ./rootfs ./rootfs/usr/sbin/httpd
qemu-arm-static -L ./rootfs -E LD_PRELOAD=/libnvram.so ./rootfs/usr/sbin/httpd

# strace what it is missing (qemu has a built-in strace)
qemu-mipsel-static -strace -L ./rootfs ./rootfs/usr/sbin/httpd 2>&1 | tail -40
qemu-mipsel-static -d unimp,guest_errors -L ./rootfs ./rootfs/bin/foo

# transparent execution via binfmt_misc (then you can just run ./rootfs/bin/foo)
apt-get install -y qemu-user-static binfmt-support
update-binfmts --display | head -20
systemctl restart systemd-binfmt || true

# debugging: qemu listens for gdb on 1234
qemu-mipsel-static -g 1234 -L ./rootfs ./rootfs/usr/sbin/httpd &
gdb-multiarch ./rootfs/usr/sbin/httpd \
  -ex 'set architecture mips' -ex 'target remote :1234' -ex 'b main' -ex 'c'
```

### Faking NVRAM

```bash
# many router binaries link against libnvram and die without it.
# firmadyne's libnvram.so implements nvram_get/nvram_set against a directory.
cp libnvram.so rootfs/
mkdir -p rootfs/firmadyne/libnvram rootfs/firmadyne/libnvram.override

# seed the values the binary expects (find them with strings)
strings rootfs/usr/sbin/httpd | grep -E '^[a-z_]{3,30}$' | sort -u | head -40
for k in lan_ipaddr lan_netmask wan_ifname http_username http_passwd; do
  echo -n "192.168.1.1" > "rootfs/firmadyne/libnvram/$k"
done

chroot rootfs /qemu-mipsel-static -E LD_PRELOAD=/libnvram.so /usr/sbin/httpd
```

### qemu-system for a full boot

```bash
# 1. get a kernel that matches the architecture. debian publishes ready-made
#    qemu kernels + initrd images for mips/mipsel/armel; firmadyne ships its own.

# --- MIPS malta board, little endian ---
qemu-system-mipsel \
  -M malta \
  -kernel vmlinux-3.2.0-4-4kc-malta \
  -hda rootfs.ext2 \
  -append "root=/dev/sda console=ttyS0 nokaslr" \
  -nographic \
  -net nic -net user,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22

# --- ARM versatilepb ---
qemu-system-arm \
  -M versatilepb \
  -kernel vmlinuz-3.2.0-4-versatile \
  -initrd initrd.img-3.2.0-4-versatile \
  -hda rootfs.qcow2 \
  -append "root=/dev/sda1 console=ttyAMA0" \
  -nographic \
  -net nic -net user,hostfwd=tcp::8080-:80

# --- ARM virt board (modern, needs a virt-capable kernel) ---
qemu-system-arm -M virt -cpu cortex-a15 -m 1024 \
  -kernel zImage -dtb virt.dtb \
  -drive if=none,file=rootfs.img,format=raw,id=hd \
  -device virtio-blk-device,drive=hd \
  -append "root=/dev/vda console=ttyAMA0" -nographic \
  -netdev user,id=n0,hostfwd=tcp::8080-:80 -device virtio-net-device,netdev=n0

# --- debug the guest kernel ---
qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.ext2 \
  -append "root=/dev/sda console=ttyS0" -nographic -s -S
# then: gdb-multiarch vmlinux -ex 'target remote :1234'

# build a rootfs image from an extracted tree
dd if=/dev/zero of=rootfs.ext2 bs=1M count=64
mkfs.ext2 -F rootfs.ext2
mkdir -p mnt && mount -o loop rootfs.ext2 mnt
cp -a extracted-rootfs/. mnt/
umount mnt
```

### Firmware Analysis Toolkit / firmadyne

```bash
# FAT wraps firmadyne: extract, infer the architecture, build a qemu image, boot it
python3 fat.py firmware.bin
# it prints the guest IP (usually 192.168.0.1 on a tap interface)

# firmadyne, step by step
./sources/extractor/extractor.py -b Target -sql 127.0.0.1 -np -nk firmware.bin images/
./scripts/getArch.sh ./images/1.tar.gz
./scripts/makeImage.sh 1
./scripts/inferNetwork.sh 1
./scratch/1/run.sh                       # boots the emulated device

# once it boots
ping 192.168.0.1
nmap -sV 192.168.0.1
curl -v http://192.168.0.1/

# the guest console is on the same terminal; log in as root if the image allows it
```

### Python helper: pick the right emulation setup

```python
#!/usr/bin/env python3
"""fw_emu.py - read an ELF header from an extracted rootfs and print the qemu setup.

Parses the ELF identification bytes directly, so it works without `file`.

Usage: python3 fw_emu.py ./rootfs/bin/busybox
"""
from __future__ import annotations

import os
import struct
import sys

EM = {
    0x03: ("x86", "qemu-i386-static", "qemu-system-i386"),
    0x08: ("MIPS", "qemu-mips-static", "qemu-system-mips"),
    0x14: ("PowerPC", "qemu-ppc-static", "qemu-system-ppc"),
    0x15: ("PowerPC64", "qemu-ppc64-static", "qemu-system-ppc64"),
    0x28: ("ARM", "qemu-arm-static", "qemu-system-arm"),
    0x2A: ("SuperH", "qemu-sh4-static", "qemu-system-sh4"),
    0x3E: ("x86-64", "qemu-x86_64-static", "qemu-system-x86_64"),
    0xB7: ("AArch64", "qemu-aarch64-static", "qemu-system-aarch64"),
    0xF3: ("RISC-V", "qemu-riscv64-static", "qemu-system-riscv64"),
}
BOARD = {"MIPS": "malta", "ARM": "versatilepb", "AArch64": "virt", "PowerPC": "g3beige"}


def parse_elf(path: str) -> dict:
    with open(path, "rb") as fh:
        ident = fh.read(16)
        if ident[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        bits = 32 if ident[4] == 1 else 64
        little = ident[5] == 1
        endian = "<" if little else ">"
        rest = fh.read(8)
        _etype, machine = struct.unpack(endian + "HH", rest[:4])
        name, user, system = EM.get(machine, (f"unknown(0x{machine:x})", "?", "?"))
        if name == "MIPS" and little:
            user, system = "qemu-mipsel-static", "qemu-system-mipsel"
        if name == "ARM" and not little:
            user, system = "qemu-armeb-static", "qemu-system-armeb"
        return {"bits": bits, "endian": "little" if little else "big",
                "arch": name, "qemu_user": user, "qemu_system": system,
                "board": BOARD.get(name, "virt")}


def interpreter(path: str) -> str | None:
    """Read PT_INTERP from the program headers to learn the required loader path."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    if is64:
        phoff = struct.unpack(endian + "Q", data[0x20:0x28])[0]
        phentsize, phnum = struct.unpack(endian + "HH", data[0x36:0x3A])
    else:
        phoff = struct.unpack(endian + "I", data[0x1C:0x20])[0]
        phentsize, phnum = struct.unpack(endian + "HH", data[0x2A:0x2E])
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + 8 > len(data):
            break
        ptype = struct.unpack(endian + "I", data[off:off + 4])[0]
        if ptype == 3:  # PT_INTERP
            if is64:
                p_offset = struct.unpack(endian + "Q", data[off + 8:off + 16])[0]
                p_filesz = struct.unpack(endian + "Q", data[off + 32:off + 40])[0]
            else:
                p_offset = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
                p_filesz = struct.unpack(endian + "I", data[off + 16:off + 20])[0]
            return data[p_offset:p_offset + p_filesz].rstrip(b"\x00").decode("ascii", "replace")
    return None


def report(path: str) -> None:
    info = parse_elf(path)
    interp = interpreter(path)
    root = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    print(f"arch     : {info['arch']} {info['bits']}-bit {info['endian']} endian")
    print(f"interp   : {interp or '(static)'}")
    if interp:
        full = os.path.join(root, interp.lstrip("/"))
        print(f"           {'present' if os.path.exists(full) else 'MISSING in rootfs'}")
    print(f"qemu-user: {info['qemu_user']}")
    print(f"qemu-sys : {info['qemu_system']}  -M {info['board']}")
    print()
    print("# quick start")
    print(f"cp $(which {info['qemu_user']}) {root}/")
    print(f"sudo chroot {root} /{info['qemu_user']} /bin/sh")
    print(f"sudo chroot {root} /{info['qemu_user']} {os.path.join('/', os.path.relpath(path, root))}")
    print()
    print("# with strace and a faked nvram")
    print(f"{info['qemu_user']} -strace -L {root} -E LD_PRELOAD=/libnvram.so {path}")
    print()
    print("# gdb")
    print(f"{info['qemu_user']} -g 1234 -L {root} {path} &")
    print(f"gdb-multiarch {path} -ex 'target remote :1234'")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    report(argv[1])
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # build a minimal 32-bit big-endian MIPS ELF header for the self-test
        hdr = bytearray(52)
        hdr[0:4] = b"\x7fELF"
        hdr[4] = 1          # 32-bit
        hdr[5] = 2          # big endian
        hdr[6] = 1          # version
        hdr[16:18] = (2).to_bytes(2, "big")    # ET_EXEC
        hdr[18:20] = (8).to_bytes(2, "big")    # EM_MIPS
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "bin"))
            p = os.path.join(d, "bin", "busybox")
            with open(p, "wb") as fh:
                fh.write(bytes(hdr))
            info = parse_elf(p)
            assert info["arch"] == "MIPS", info
            assert info["endian"] == "big", info
            assert info["qemu_user"] == "qemu-mips-static", info
            assert info["board"] == "malta", info
            report(p)
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

## Variants & pitfalls

- **"Exec format error"** in the chroot -> you copied a dynamically linked qemu, or the
  wrong architecture. Use the `-static` build.
- **"No such file or directory" on a binary that exists** -> the ELF interpreter
  (`/lib/ld-uClibc.so.0`) is missing inside the chroot. Check with the script above.
- **Segfault immediately after start** -> NVRAM. `LD_PRELOAD=/libnvram.so`.
- **Binds to an interface that does not exist** (`br0`, `eth0.1`) -> create it
  (`ip link add br0 type bridge`) or patch the config.
- **Endianness confusion**: MIPS big endian (`MSB`) is `qemu-mips`, little endian (`LSB`)
  is `qemu-mipsel`. Getting this wrong gives "Invalid ELF image".
- **Never run untrusted firmware unsandboxed.** Use a container or VM; init scripts can
  and do write outside the chroot through bind mounts.
- **Root is required for `chroot` and `mount`**; unprivileged alternatives are
  `qemu-<arch> -L rootfs` (no chroot) or `bwrap`/`proot`.

## Tools

- `qemu-user-static` (`qemu-mipsel-static` etc.) and `qemu-system-*`.
- `gdb-multiarch` - remote debugging via `-g`.
- `firmadyne` / `Firmware Analysis Toolkit (FAT)` - automated full-system emulation.
- `libnvram.so` (from firmadyne) - NVRAM shim.
- `proot` / `bwrap` - chroot without root.
- `buildroot` / `OpenWrt` SDK - build a matching kernel when none exists.

## References

- QEMU documentation: user-mode emulation and system emulation board models.
- firmadyne project documentation for its extraction and emulation scripts.
- Debian's published QEMU kernel images for mips/mipsel/armel guests.
