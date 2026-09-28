---
title: "Firmware Extraction - binwalk, squashfs, jffs2, ubifs and Finding the Root"
category: hardware
subcategory: firmware
type: technique
tags: [binwalk, unblob, squashfs, unsquashfs, sasquatch, jefferson, jffs2, ubi-reader, ubifs, cramfs, cpio, uboot, firmware, entropy, dd, file-carving]
difficulty: medium
summary: "Take an unknown firmware blob apart: identify the container, carve the filesystem, mount or unpack it, and find the interesting files."
when_to_use:
  - "You are handed a .bin / .img / .trx / .chk with no documentation"
  - "binwalk shows signatures but extraction produces nothing usable"
  - "You need /etc/shadow, a private key or a CGI binary out of a router image"
tools: [binwalk, unblob, sasquatch, jefferson, ubi_reader, dd, cpio, xz]
related: [firmware-arch-identification, firmware-emulation, mcu-reversing, uart-serial]
---

## TL;DR

`binwalk -e` first, `unblob` when binwalk fails. The output you want is a Linux root
filesystem (`bin/ etc/ usr/ lib/`). If you only see high entropy, the image is compressed
or encrypted - find the header, check for a vendor magic, and look for the bootloader that
decrypts it. Once you have a rootfs, the loot is in `/etc`, `/www`, `/usr/sbin` and
`/etc/init.d`.

## Recognise it

- `file firmware.bin` -> "data" (no format) is normal for a full flash image.
- `binwalk firmware.bin` lists offsets with types: `uImage header`, `Squashfs filesystem`,
  `LZMA compressed data`, `JFFS2 filesystem`, `UBI erase count header`, `CramFS`.
- `strings` shows `/bin/busybox`, `/etc/init.d/rcS`, `Linux version`, `U-Boot`.
- Entropy graph flat near 1.0 across the whole file -> compressed or encrypted.
- Entropy with clear low-entropy plateaus -> uncompressed sections (headers, padding).

## Theory

### Typical flash layout

```
0x000000  bootloader  (U-Boot / CFE / RedBoot)      low entropy, strings, "U-Boot 20xx"
0x040000  bootloader env / nvram                    key=value strings
0x050000  kernel      (uImage / zImage / vmlinuz)   0x27051956 magic for uImage
0x180000  rootfs      (squashfs / jffs2 / ubifs / cramfs)
0x7c0000  overlay / config partition                often jffs2, writable
0x7f0000  factory / calibration data (MAC, keys)
```

### Magic numbers worth knowing

| Magic (hex) | ASCII | Format |
|---|---|---|
| `27 05 19 56` | | uImage header (big endian) |
| `68 73 71 73` | `hsqs` | squashfs, little endian |
| `73 71 73 68` | `sqsh` | squashfs, big endian |
| `73 68 73 71` | `shsq` | squashfs LE, older |
| `85 19` | | JFFS2 node (little endian) |
| `19 85` | | JFFS2 node (big endian) |
| `55 42 49 23` | `UBI#` | UBI erase-count header |
| `55 42 49 21` | `UBI!` | UBI volume identifier |
| `28 CD 3D 45` | | CramFS |
| `5D 00 00` | | LZMA (alone) |
| `FD 37 7A 58 5A` | `.7zXZ` | XZ |
| `1F 8B 08` | | gzip |
| `04 22 4D 18` | | LZ4 |
| `D0 0D FE ED` | | device tree blob (FDT) |
| `30 37 30 37 30 31` | `070701` | cpio newc archive |
| `CE FA ED FE` / `7F 45 4C 46` | `ELF` | kernel or binary |

### Why binwalk extraction fails

- **Vendor squashfs**: many routers ship squashfs with a non-standard LZMA. Stock
  `unsquashfs` refuses; `sasquatch` (a patched unsquashfs) handles it.
- **JFFS2**: `binwalk` recognises it but cannot unpack - use `jefferson`.
- **UBI/UBIFS**: needs `ubireader_extract_files` / `ubidump`, and the right page/block size.
- **False positives**: binwalk signature matches inside compressed data. Check that the
  claimed size is plausible before carving.
- **Header offsets**: vendor wrappers (TRX, CHK, SEAMA, uImage) put a 32-112 byte header
  before the real payload.

## Attack

1. `file`, `binwalk`, `binwalk -E` (entropy) - decide compressed vs structured.
2. `binwalk -e --run-as=root` to auto-extract; check `_firmware.bin.extracted/`.
3. If that fails, read the signature table, `dd` the interesting offset out by hand, and
   unpack with the format-specific tool.
4. Find the rootfs: look for a directory containing `bin/`, `etc/`, `usr/`.
5. Loot: `etc/passwd`, `etc/shadow`, `etc/*.conf`, `www/`, `usr/sbin/*`, `etc/init.d/*`,
   any `.pem`/`.key`/`.crt`, hardcoded credentials in CGI binaries.
6. If nothing decompresses, go to `firmware-arch-identification` (raw code blob) or look
   for encryption (vendor key in the bootloader).

## Code

```bash
#!/bin/sh
# fw-extract.sh - identify and unpack an unknown firmware image
set -eu
FW="${1:?usage: fw-extract.sh firmware.bin}"
OUT="${2:-fw-out}"
mkdir -p "$OUT"

# 1. what is it at all
file "$FW"
ls -l "$FW"
xxd -l 64 "$FW"

# 2. signature scan; -B forces a full signature scan even on "data"
binwalk -B "$FW" | tee "$OUT/signatures.txt"

# 3. entropy: a flat 1.0 line means compressed/encrypted, dips mean structure
binwalk -E -J "$FW" && mv "$FW.png" "$OUT/entropy.png" 2>/dev/null || true

# 4. automatic extraction (binwalk v2 syntax; v3 uses --extract)
binwalk -e -M --directory "$OUT" "$FW" 2>/dev/null || binwalk --extract --directory "$OUT" "$FW"

# 5. unblob is better at nesting and at odd containers
unblob -e "$OUT/unblob" "$FW" 2>/dev/null || echo "unblob not installed"

# 6. find the root filesystem in whatever came out
find "$OUT" -type d -name 'bin' -o -type d -name 'etc' | head
find "$OUT" -name 'busybox' -o -name 'rcS' -o -name 'passwd' | head

echo "== signatures =="
cat "$OUT/signatures.txt"
```

### Carving and unpacking by hand

```bash
# read the offset/size of the filesystem from the binwalk output, then carve it
binwalk firmware.bin
# DECIMAL   HEXADECIMAL  DESCRIPTION
# 1572864   0x180000     Squashfs filesystem, little endian, version 4.0, size: 5242880
dd if=firmware.bin of=rootfs.sqfs bs=1 skip=1572864 count=5242880 status=progress
# faster for large offsets: use a block size that divides the offset
dd if=firmware.bin of=rootfs.sqfs bs=4096 skip=384 count=1280

# ---- squashfs ----
file rootfs.sqfs
unsquashfs -s rootfs.sqfs                 # superblock: version, compression, size
unsquashfs -d rootfs rootfs.sqfs          # stock tool
sasquatch -d rootfs rootfs.sqfs           # vendor LZMA variants
sasquatch -b -d rootfs rootfs.sqfs        # big endian
unsquashfs -ll rootfs.sqfs | head -40     # list without extracting

# ---- jffs2 ----
jefferson -d jffs2-out rootfs.jffs2
jefferson -v -d jffs2-out rootfs.jffs2    # verbose, shows node parsing
# or mount it on linux with a block2mtd device:
#   modprobe mtdram total_size=32768 erase_size=128
#   modprobe mtdblock
#   dd if=rootfs.jffs2 of=/dev/mtdblock0
#   mount -t jffs2 /dev/mtdblock0 /mnt

# ---- ubi / ubifs ----
ubireader_display_info firmware.bin        # page size, block size, volumes
ubireader_extract_images -o ubi-img firmware.bin
ubireader_extract_files -o ubi-files firmware.bin
ubidump -O ubi-out firmware.bin

# ---- cramfs ----
cramfsck -x cram-out rootfs.cramfs
mount -t cramfs -o loop rootfs.cramfs /mnt

# ---- cpio (initramfs) ----
cpio -idmv < initramfs.cpio
zcat initramfs.cpio.gz | cpio -idmv

# ---- ext2/3/4 ----
file rootfs.ext
debugfs -R 'ls -l /' rootfs.ext
mkdir -p mnt && mount -o loop,ro rootfs.ext mnt
7z x rootfs.ext -oext-out                  # works without root

# ---- raw compression ----
xz -d -c blob.xz > blob
gzip -d -c blob.gz > blob
lz4 -d blob.lz4 blob
unlzma -c blob.lzma > blob
zstd -d blob.zst -o blob
```

### Vendor container headers

```bash
# uImage (U-Boot): 64-byte header, big endian
xxd -l 64 kernel.uimage
mkimage -l kernel.uimage                  # prints load address, entry point, type, os, arch
dd if=kernel.uimage of=kernel.lzma bs=1 skip=64

# TRX (broadcom): "HDR0" magic, up to 4 partition offsets
xxd -l 32 firmware.trx | head -2

# SEAMA (d-link): "SEAMA" magic at 0
# CHK (netgear): header length at offset 4, big endian
# DLOB / dlink wrappers: strings 'dlob' near the start

# device tree blob - tells you the SoC, peripherals and memory map
dtc -I dtb -O dts -o board.dts board.dtb
fdtdump board.dtb | head -60
```

### Python: signature scanner and carver

```python
#!/usr/bin/env python3
"""fwcarve.py - scan a firmware blob for known magics, report entropy, and carve.

Pure stdlib alternative to binwalk when it is not installed, and a sanity check when
binwalk reports something implausible.

Usage:
  python3 fwcarve.py firmware.bin
  python3 fwcarve.py firmware.bin --carve 0x180000 0x500000 rootfs.sqfs
"""
from __future__ import annotations

import math
import sys
from collections import Counter

MAGICS: list[tuple[bytes, str]] = [
    (b"\x27\x05\x19\x56", "uImage header (big endian)"),
    (b"hsqs", "squashfs (little endian)"),
    (b"sqsh", "squashfs (big endian)"),
    (b"shsq", "squashfs (little endian, legacy)"),
    (b"qshs", "squashfs (big endian, legacy)"),
    (b"\x85\x19", "JFFS2 node (little endian)"),
    (b"\x19\x85", "JFFS2 node (big endian)"),
    (b"UBI#", "UBI erase count header"),
    (b"UBI!", "UBI volume id header"),
    (b"\x28\xcd\x3d\x45", "CramFS"),
    (b"\xfd7zXZ\x00", "XZ compressed"),
    (b"\x1f\x8b\x08", "gzip compressed"),
    (b"\x04\x22\x4d\x18", "LZ4 compressed"),
    (b"\x5d\x00\x00", "LZMA (alone) compressed"),
    (b"\x28\xb5\x2f\xfd", "zstd compressed"),
    (b"\xd0\x0d\xfe\xed", "device tree blob"),
    (b"070701", "cpio newc archive"),
    (b"\x7fELF", "ELF"),
    (b"HDR0", "TRX container (broadcom)"),
    (b"SEAMA", "SEAMA container (d-link)"),
    (b"PK\x03\x04", "zip"),
    (b"ustar", "tar"),
    (b"-rom1fs-", "romfs"),
    (b"\x53\xef", "ext2/3/4 superblock magic (at +0x438)"),
]

# JFFS2 nodes are everywhere, so only report a run of them once per window
NOISY = {"JFFS2 node (little endian)", "JFFS2 node (big endian)"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan(data: bytes) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    last_noisy = -1 << 30
    for magic, name in MAGICS:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            start = idx + 1
            if name in NOISY:
                if idx - last_noisy < 0x10000:
                    continue
                last_noisy = idx
            hits.append((idx, name))
    return sorted(hits)


def entropy_map(data: bytes, block: int = 4096) -> list[tuple[int, float]]:
    out = []
    for off in range(0, len(data), block):
        out.append((off, entropy(data[off:off + block])))
    return out


def summarise(path: str) -> None:
    with open(path, "rb") as fh:
        data = fh.read()
    print(f"== {path}: {len(data)} bytes ({len(data)/1024:.1f} KiB)")
    print(f"overall entropy: {entropy(data):.3f} bits/byte")

    print("\n-- signatures --")
    for off, name in scan(data):
        print(f"  0x{off:08x} ({off:>10})  {name}")

    print("\n-- entropy map (4 KiB blocks, low-entropy regions are structure) --")
    emap = entropy_map(data)
    run_start = None
    for off, e in emap:
        low = e < 6.0
        if low and run_start is None:
            run_start = off
        elif not low and run_start is not None:
            print(f"  0x{run_start:08x} - 0x{off:08x}  low entropy ({(off-run_start)//1024} KiB)")
            run_start = None
    if run_start is not None:
        print(f"  0x{run_start:08x} - 0x{len(data):08x}  low entropy (tail)")

    printable = sum(1 for b in data[:65536] if 32 <= b < 127)
    print(f"\nprintable ratio in first 64 KiB: {printable/65536:.2%}")


def carve(path: str, off: int, size: int, dest: str) -> None:
    with open(path, "rb") as fh:
        fh.seek(off)
        blob = fh.read(size)
    with open(dest, "wb") as fh:
        fh.write(blob)
    print(f"carved {len(blob)} bytes from 0x{off:x} -> {dest} (entropy {entropy(blob):.3f})")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    if "--carve" in argv:
        i = argv.index("--carve")
        carve(argv[1], int(argv[i + 1], 0), int(argv[i + 2], 0), argv[i + 3])
        return 0
    summarise(argv[1])
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        blob = (b"\x00" * 256 + b"\x27\x05\x19\x56" + b"A" * 1024 +
                b"hsqs" + bytes(range(256)) * 16 + b"UBI#" + b"\x00" * 512)
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.bin")
            with open(p, "wb") as fh:
                fh.write(blob)
            hits = scan(blob)
            names = [n for _o, n in hits]
            assert "uImage header (big endian)" in names, names
            assert "squashfs (little endian)" in names, names
            assert "UBI erase count header" in names, names
            summarise(p)
            carve(p, 256, 8, os.path.join(d, "hdr.bin"))
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Looting the rootfs

```bash
cd rootfs

# credentials
cat etc/passwd etc/shadow 2>/dev/null
grep -rIn -E 'password|passwd|admin|root:' etc/ 2>/dev/null | head -30
find . -name '*.htpasswd' -o -name 'shadow*' -o -name '*.pwd'

# keys and certificates
find . \( -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.p12' \) -exec ls -l {} +
find . -name 'authorized_keys' -o -name 'id_rsa*' -o -name 'dropbear*'

# startup and services - what runs, and as whom
cat etc/init.d/rcS etc/inittab 2>/dev/null
ls -la etc/init.d/ etc/rc.d/ 2>/dev/null
grep -rIn 'telnetd\|dropbear\|sshd\|httpd\|busybox' etc/ 2>/dev/null | head -20

# web interface (where the RCE usually is)
ls -la www/ usr/www/ htdocs/ 2>/dev/null
find . -name '*.cgi' -o -name '*.php' -o -name '*.asp' | head -30
grep -rIn 'system(\|popen(\|exec(' www/ usr/www/ 2>/dev/null | head -20

# binaries worth reversing
ls -la bin/ sbin/ usr/bin/ usr/sbin/ | head -40
file bin/busybox                          # tells you arch + endianness + libc
find . -type f -perm -u+x -exec file {} + | grep ELF | head -30

# hardcoded strings across every binary
find . -type f -exec file {} + | grep ELF | cut -d: -f1 |
  xargs strings -n 8 2>/dev/null | grep -iE 'password|secret|key=|token' | sort -u | head -40

# version fingerprint for known CVEs
cat etc/version etc/openwrt_release etc/banner 2>/dev/null
bin/busybox 2>/dev/null | head -2
```

## Variants & pitfalls

- **binwalk finds a squashfs but `unsquashfs` says "Can't find a SQUASHFS superblock"** -
  you carved the wrong offset (off by the header), or it is a vendor LZMA variant.
  Try `sasquatch`, and re-check the offset with `xxd | grep hsqs`.
- **Recursive extraction explodes** - `binwalk -M` follows nested archives and can produce
  gigabytes from a padded image. Bound it with `-d 2`.
- **Entropy 7.99 everywhere** = encrypted or compressed whole-image. Look for a small
  low-entropy header; the bootloader (unencrypted) contains the decryption routine.
- **JFFS2 extraction yields duplicate/older files** - JFFS2 is log-structured, so multiple
  versions of a file exist. `jefferson` picks the newest; older nodes may hold the flag.
- **The rootfs is read-only squashfs plus a writable overlay** - the runtime config
  (and credentials) lives in the overlay partition, not the squashfs.
- If there is genuinely no filesystem, it is a bare-metal MCU image - see
  `firmware-arch-identification` and `mcu-reversing`.

## Tools

- `binwalk` - signature scan, entropy, extraction.
- `unblob` - modern alternative with better nesting and more handlers.
- `sasquatch` - squashfs with vendor-patched LZMA.
- `jefferson` - JFFS2.
- `ubi_reader` (`ubireader_extract_files`) - UBI/UBIFS.
- `mkimage` (u-boot-tools), `dtc`, `cpio`, `7z`, `debugfs`.
- `firmware-mod-kit` - older but still useful for repacking.

## References

- binwalk project documentation for signature and extraction options.
- unblob project documentation for its handler list.
- U-Boot documentation on the uImage header format.
