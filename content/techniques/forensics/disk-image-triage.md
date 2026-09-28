---
title: "Disk Image Triage - Identify, Mount, Map"
category: forensics
subcategory: disk
type: technique
tags: [disk-image, dd, e01, ewf, ewfmount, vmdk, qcow2, qemu-nbd, vhdx, affuse, mmls, fls, fsstat, sleuthkit, losetup, dislocker, bitlocker, testdisk, partition-table, dfir]
difficulty: easy
summary: "Identify any disk image format from magic bytes, mount it read-only, parse the partition table, and do a first-pass carve before you commit to a full analysis."
when_to_use:
  - "You were handed a .dd / .raw / .img / .E01 / .qcow2 / .vmdk / .vhdx / .001 file"
  - "`mount` fails with 'wrong fs type, bad option, bad superblock'"
  - "You need the byte offset of a partition and only have `mmls` sector numbers"
  - "The challenge is 'find the deleted file' and you have not even opened the image yet"
  - "The partition table is corrupt or the image is a split/encrypted/RAID volume"
tools: [sleuthkit, libewf, qemu-utils, testdisk, dislocker, ddrescue, bulk-extractor, affuse]
related: [disk-ntfs-mft, disk-windows-registry, disk-windows-execution-artifacts, memory-volatility3-workflow]
---

## TL;DR

Every disk challenge starts the same way: identify the container, mount it **read-only**, and get a
partition map. `file` + `xxd | head` names the format, `mmls` gives you the partition start sectors,
and `offset = start_sector * sector_size` is the number `mount -o offset=` wants. If you only have
20 minutes, skip mounting entirely and run `fls -r -p -o <sector> image.dd` plus
`bulk_extractor -o out image.dd` - that finds most CTF flags without a single loop device.

## Recognise it

- `file image.dd` says `DOS/MBR boot sector` (raw), `EWF/Expert Witness` (E01), `QEMU QCOW Image`,
  `VMware4 disk image`, or just `data` if it is a partition rather than a whole disk.
- The first bytes decide it. `xxd image | head -2` and compare:

| Format | Offset | Magic | Notes |
| --- | --- | --- | --- |
| Raw / dd | 0x1FE | `55 AA` | MBR boot signature; no container header at all |
| GPT | 0x200 | `EFI PART` | LBA1; a protective MBR still sits at LBA0 |
| EWF / E01 | 0 | `45 56 46 09 0D 0A FF 00` = `EVF\x09\r\n\xff\x00` | segments `.E01`, `.E02`... or `.Ex01` (EWF2) |
| VMDK (sparse) | 0 | `4B 44 4D 56` = `KDMV` | monolithic sparse |
| VMDK (descriptor) | 0 | `# Disk DescriptorFile` ASCII | text stub pointing at `-flat`/`-s00x` extents |
| QCOW / QCOW2 | 0 | `51 46 49 FB` = `QFI\xfb` | byte 7 is the version (2 or 3) |
| VHD (fixed/dynamic) | 0 and EOF-512 | `conectix` | the **footer** is authoritative |
| VHDX | 0 | `vhdxfile` (UTF-16LE `v\0h\0d\0x\0...`) | Hyper-V gen2 |
| VDI | 0x40 | `7F 10 DA BE` | VirtualBox; ASCII banner at offset 0 |
| AFF4 | 0 | `50 4B 03 04` = `PK\x03\x04` | it is a ZIP; contains `container.description` |
| Split raw | n/a | none | `.001`/`.002`... or `.aa`/`.ab`; `cat` them back together |
| LUKS | 0 | `LUKS\xba\xbe` | encrypted; needs `cryptsetup` |
| BitLocker | 3 | `-FVE-FS-` | `MSWIN4.1` OEM id too on older volumes |

```sh
# name the container the lazy way
file image.dd image.E01 disk.qcow2
# first 64 bytes, the ground truth when `file` is unsure
xxd -l 64 image.dd
# the MBR/GPT boundary in one shot
xxd -s 0x1b8 -l 80 image.dd
# read the VHD footer (it lives in the LAST 512 bytes)
tail -c 512 disk.vhd | xxd | head -3
# qemu knows every virtual-disk format and prints the real size + backing file
qemu-img info disk.qcow2
# E01 metadata: acquiring tool, MD5, notes the examiner typed
ewfinfo image.E01
```

## Partition maps

```sh
# THE command. Sleuthkit partition list: slot, start sector, length, description
mmls image.dd
# force a scheme when autodetect fails (dos, gpt, mac, bsd, sun, gpt_nogpt)
mmls -t gpt image.dd
mmls -t dos image.dd
# mmls on a non-512 sector image (4Kn disks, some virtual disks)
mmls -b 4096 image.dd
# classic tools, useful cross-check
fdisk -l image.dd
gdisk -l image.dd
parted -s image.dd unit s print
parted -s image.dd unit B print
# filesystem details for ONE partition given its START SECTOR
fsstat -o 2048 image.dd
# what the kernel thinks a device/file is (UUID, TYPE, LABEL)
blkid image.dd
blkid -p -o full /dev/loop0p2
# broken or wiped partition table -> rebuild it interactively
testdisk image.dd
# non-interactive scan for filesystem signatures across the whole image
sigfind -t ntfs image.dd
sigfind -t fat image.dd
```

### The offset arithmetic (the thing everyone gets wrong)

`mmls` prints **sectors**. `mount -o offset=` and `losetup -o` want **bytes**.

```
offset_bytes = start_sector * sector_size
```

`sector_size` is 512 unless `mmls` says otherwise (its header line prints `Units are in 512-byte
sectors`). Sleuthkit tools (`fls`, `icat`, `fsstat`, `istat`) take `-o` in **sectors**, not bytes.
So for a partition starting at sector 2048:

```sh
# sleuthkit: -o is in SECTORS
fls -o 2048 -r -p image.dd
# mount: offset is in BYTES -> 2048 * 512 = 1048576
mount -o ro,loop,offset=$((512*2048)) image.dd /mnt/img
# let the shell do it from a variable so you never fat-finger it
START=2048; SECSZ=512
mount -o ro,loop,offset=$((START*SECSZ)),noexec,nodev image.dd /mnt/img
# a partition's byte LENGTH matters too when you carve it out
LEN=41940992
dd if=image.dd of=part1.dd bs=512 skip=$START count=$LEN status=progress
```

## Mount read-only - every format

Always `ro`. Always `noexec,nodev`. On a real case you would also use a write blocker; in a CTF the
`ro` flag plus a hash before/after is enough.

```sh
# prepare a mountpoint set once
sudo mkdir -p /mnt/ewf /mnt/img /mnt/dis /mnt/raw
```

### Raw / dd / img

```sh
# -r read-only, -P scan the partition table into loopXpY nodes, -f pick a free device, --show print it
LOOP=$(sudo losetup -r -P -f --show image.dd) && echo "$LOOP"
# now mount a partition node directly, no offset maths needed
sudo mount -o ro,noexec,nodev "${LOOP}p2" /mnt/img
# or skip losetup entirely with an offset
sudo mount -o ro,loop,offset=$((512*2048)),noexec,nodev image.dd /mnt/img
# detach when done
sudo umount /mnt/img && sudo losetup -d "$LOOP"
```

### NTFS (always use ntfs-3g options)

```sh
# show_sys_files exposes $MFT/$LogFile; streams_interface=windows exposes ADS as file:stream
sudo mount -t ntfs-3g -o ro,loop,offset=$((512*2048)),noexec,nodev,show_sys_files,streams_interface=windows image.dd /mnt/img
# then the MFT is a normal file you can copy out
cp /mnt/img/\$MFT /tmp/MFT
# and an alternate data stream reads like this
cat '/mnt/img/Users/bob/notes.txt:hidden'
```

### E01 / EWF

```sh
# ewfmount exposes the decoded stream as a single raw file /mnt/ewf/ewf1
sudo ewfmount image.E01 /mnt/ewf
# it is a raw image from here on: partition it and mount as usual
mmls /mnt/ewf/ewf1
sudo mount -o ro,loop,offset=$((512*2048)),noexec,nodev /mnt/ewf/ewf1 /mnt/img
# sleuthkit reads EWF natively too, no mounting required
fls -i ewf -o 2048 -r -p image.E01
# multi-segment sets: point at the FIRST segment, libewf finds E02..E0n itself
ewfinfo image.E01
# verify the stored hashes match the stored data
ewfverify image.E01
# convert to raw if a tool refuses EWF
ewfexport -t image_raw -f raw image.E01
```

### QCOW2 / VMDK / VHD / VHDX / VDI via qemu-nbd

```sh
# load the nbd driver with room for partitions
sudo modprobe nbd max_part=16
# attach READ-ONLY; qemu autodetects the format
sudo qemu-nbd --read-only -c /dev/nbd0 disk.qcow2
# force the format when autodetect guesses wrong (and to avoid backing-file surprises)
sudo qemu-nbd --read-only -f vmdk -c /dev/nbd0 disk.vmdk
# make the kernel enumerate partitions
sudo partx -a /dev/nbd0
sudo partprobe /dev/nbd0
lsblk /dev/nbd0
# mount one
sudo mount -o ro,noexec,nodev /dev/nbd0p2 /mnt/img
# tear down in this order
sudo umount /mnt/img; sudo partx -d /dev/nbd0; sudo qemu-nbd -d /dev/nbd0
# alternative: flatten to raw first (safest, costs disk space)
qemu-img convert -p -O raw disk.vmdk disk.raw
# VMDK with a text descriptor + -flat extent: just use the flat file directly
mmls disk-flat.vmdk
```

### AFF / AFF4

```sh
# affuse exposes an AFF container as a raw file
affuse image.aff /mnt/ewf && mmls /mnt/ewf/image.aff.raw
# AFF4 is a zip: list it before anything else
unzip -l image.aff4
# pyaff4 / aff4imager can export the stream to raw
aff4imager --export-all -o ./out image.aff4
```

### Split raw

```sh
# sleuthkit reads split sets natively if you list the segments in order
mmls -i split image.001 image.002 image.003
fls -i split -o 2048 -r -p image.00?
# or just concatenate (needs the space)
cat image.0?? > image.dd
# affuse also presents a split set as one file
affuse image.001 /mnt/ewf
```

### LVM

```sh
# after losetup -P, make LVM notice the PVs
sudo pvscan --cache
sudo vgscan
# activate every volume group it found
sudo vgchange -ay
# see what appeared
sudo lvs && ls /dev/mapper/
sudo mount -o ro,noexec,nodev /dev/mapper/vg0-root /mnt/img
# deactivate when finished
sudo vgchange -an vg0
```

### Software RAID (mdadm)

```sh
# inspect the RAID superblock on each member
sudo mdadm --examine /dev/loop0p1 /dev/loop1p1
# assemble read-only from the members
sudo mdadm --assemble --readonly /dev/md0 /dev/loop0p1 /dev/loop1p1
# or let it scan
sudo mdadm --assemble --scan --readonly
sudo mount -o ro,noexec,nodev /dev/md0 /mnt/img
sudo mdadm --stop /dev/md0
```

### BitLocker

```sh
# carve the BitLocker partition out first if dislocker chokes on the whole disk
dd if=image.dd of=part.dd bs=512 skip=2048 status=progress
# -u prompts for the user password; -p<RECOVERY-KEY> for the 48-digit key; -c for a clear key
sudo dislocker -V part.dd -u -- /mnt/dis
# dislocker presents a decrypted raw file; mount THAT
sudo mount -o ro,loop,noexec,nodev /mnt/dis/dislocker-file /mnt/img
# recovery key form: dislocker -V part.dd -p111111-222222-...-888888 -- /mnt/dis
# BEK file from a USB: dislocker -V part.dd -f /path/to/key.BEK -- /mnt/dis
```

### APFS and HFS+ on Linux

```sh
# HFS+ is in-tree
sudo mount -t hfsplus -o ro,loop,offset=$((512*409640)) image.dd /mnt/img
# APFS: apfs-fuse (read-only by design, perfect for forensics)
apfs-fuse -o ro,allow_other image.dd /mnt/img
# list volumes inside the APFS container first
apfsutil image.dd
# sleuthkit 4.12+ has partial APFS support
fsstat -o 409640 image.dd
```

## Hash and preserve

```sh
# hash BEFORE you touch anything, and again after; they must match
sha256sum image.dd | tee image.dd.sha256
md5sum image.dd
# verify an E01 against the hashes the acquisition tool stored inside it
ewfverify image.E01
# image a failing device: noerror keeps going, sync pads bad blocks with zeros so offsets stay right
sudo dd if=/dev/sdb of=image.dd bs=1M conv=noerror,sync status=progress
# far better for bad media: ddrescue retries and keeps a resumable map file
sudo ddrescue -d -r3 /dev/sdb image.dd image.map
# second pass, scraping the remaining bad areas
sudo ddrescue -d -r3 -R /dev/sdb image.dd image.map
# acquire straight to E01 with hashes computed inline
ewfacquire -t image -f encase6 -c deflate:best /dev/sdb
```

## First-pass triage (before you mount anything)

```sh
# full recursive file listing with full paths; * marks deleted entries
fls -o 2048 -r -p image.dd
# deleted entries only
fls -o 2048 -r -p -d image.dd
# recover every allocated + unallocated file Sleuthkit can see into ./out
tsk_recover -o 2048 -e image.dd ./out
# allocated files only (-a) when -e is too noisy
tsk_recover -o 2048 -a image.dd ./out
# read one file by inode without mounting
icat -o 2048 image.dd 12345 > recovered.bin
# bodyfile for a MAC timeline, then sort it
fls -o 2048 -m / -r image.dd > bodyfile
mactime -b bodyfile -d -z UTC > timeline.csv
# emails, URLs, credit cards, zips, JSON, exif, and a histogram of each
bulk_extractor -o be_out image.dd
# the CTF shortcut that beats all of the above surprisingly often
strings -a -n 8 image.dd | grep -aoE 'flag\{[^}]+\}'
strings -a -el image.dd | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
# carve by file signature when the filesystem is gone
foremost -i image.dd -o fore_out
binwalk -e image.dd
photorec image.dd
```

## Code

```python
#!/usr/bin/env python3
"""disk_triage.py - sniff a disk image container format, parse `mmls`, and print
the exact read-only mount command for every partition it finds.

Usage:
    python3 disk_triage.py [image] [--sector-size N]

Defaults to ./image.dd. Requires `mmls` (sleuthkit) on PATH for the partition map;
format sniffing works with stdlib only.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

# (label, offset, magic-bytes, hint)
SIGNATURES: list[tuple[str, int, bytes, str]] = [
    ("EWF/E01 (EnCase)", 0, b"EVF\x09\r\n\xff\x00", "ewfmount + libewf"),
    ("EWF2/Ex01", 0, b"EVF2\x0d\x0a\x81\x00", "ewfmount + libewf"),
    ("VMDK sparse", 0, b"KDMV", "qemu-nbd -f vmdk"),
    ("VMDK descriptor", 0, b"# Disk Descriptor", "use the -flat/-s00x extent"),
    ("QCOW/QCOW2", 0, b"QFI\xfb", "qemu-nbd -f qcow2"),
    ("VHDX", 0, b"vhdxfile", "qemu-nbd -f vhdx"),
    ("VDI (VirtualBox)", 0x40, b"\x7f\x10\xda\xbe", "qemu-nbd -f vdi"),
    ("AFF4 (zip container)", 0, b"PK\x03\x04", "aff4imager / pyaff4"),
    ("AFF (legacy)", 0, b"AFF\x00", "affuse"),
    ("LUKS1/2", 0, b"LUKS\xba\xbe", "cryptsetup luksOpen"),
    ("BitLocker (FVE)", 3, b"-FVE-FS-", "dislocker -V"),
    ("NTFS volume", 3, b"NTFS    ", "mount -t ntfs-3g"),
    ("FAT32 volume", 82, b"FAT32   ", "mount -t vfat"),
    ("ext2/3/4 volume", 0x438, b"\x53\xef", "mount -t ext4"),
    ("HFS+ volume", 1024, b"H+", "mount -t hfsplus"),
    ("APFS container", 32, b"NXSB", "apfs-fuse"),
    ("Squashfs", 0, b"hsqs", "mount -t squashfs"),
    ("ISO9660", 32769, b"CD001", "mount -t iso9660"),
]

FS_MOUNT = {
    "ntfs": "-t ntfs-3g -o ro,noexec,nodev,show_sys_files,streams_interface=windows",
    "fat": "-t vfat -o ro,noexec,nodev",
    "exfat": "-t exfat -o ro,noexec,nodev",
    "ext": "-t ext4 -o ro,noexec,nodev",
    "hfs": "-t hfsplus -o ro,noexec,nodev",
    "apfs": "(use apfs-fuse -o ro)",
    "iso": "-t iso9660 -o ro,noexec,nodev",
    "swap": "(swap - nothing to mount, but carve it with strings/bulk_extractor)",
}


def sniff(path: str) -> list[tuple[str, str]]:
    """Return [(format name, hint)] for every signature that matches."""
    hits: list[tuple[str, str]] = []
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        for name, off, magic, hint in SIGNATURES:
            if off + len(magic) > size:
                continue
            fh.seek(off)
            if fh.read(len(magic)) == magic:
                hits.append((name, hint))
        # MBR boot signature at 0x1FE, GPT header at LBA1
        if size > 0x200:
            fh.seek(0x1FE)
            if fh.read(2) == b"\x55\xaa":
                hits.append(("Raw image with MBR boot signature", "losetup -r -P"))
        if size > 0x208:
            fh.seek(0x200)
            if fh.read(8) == b"EFI PART":
                hits.append(("GPT partition table", "mmls -t gpt"))
        # VHD keeps its authoritative copy in the last 512 bytes
        if size > 512:
            fh.seek(size - 512)
            if fh.read(8) == b"conectix":
                hits.append(("VHD (footer 'conectix')", "qemu-nbd -f vpc"))
    return hits


def split_set(path: str) -> list[str]:
    """Detect a .001/.002 or .aa/.ab split raw set and return the segments in order."""
    base, ext = os.path.splitext(path)
    if re.fullmatch(r"\.\d{3}", ext):
        pat = re.compile(re.escape(os.path.basename(base)) + r"\.\d{3}$")
    elif re.fullmatch(r"\.[a-z]{2}", ext):
        pat = re.compile(re.escape(os.path.basename(base)) + r"\.[a-z]{2}$")
    else:
        return []
    d = os.path.dirname(os.path.abspath(path)) or "."
    return sorted(os.path.join(d, f) for f in os.listdir(d) if pat.fullmatch(f))


MMLS_ROW = re.compile(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*?)\s*$")


def parse_mmls(text: str) -> tuple[int, list[dict]]:
    """Parse mmls stdout into (sector_size, [partition dicts])."""
    sector_size = 512
    m = re.search(r"Units are in (\d+)-byte sectors", text)
    if m:
        sector_size = int(m.group(1))
    parts: list[dict] = []
    for line in text.splitlines():
        row = MMLS_ROW.match(line)
        if not row:
            continue
        slot, kind, start, end, length, desc = row.groups()
        parts.append({
            "slot": int(slot),
            "kind": kind,
            "start": int(start),
            "end": int(end),
            "length": int(length),
            "desc": desc,
        })
    return sector_size, parts


def run_mmls(path: str, forced_type: str | None = None) -> str:
    if not shutil.which("mmls"):
        return ""
    cmd = ["mmls"]
    if forced_type:
        cmd += ["-t", forced_type]
    cmd.append(path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[!] mmls failed: {exc}", file=sys.stderr)
        return ""
    if proc.returncode != 0:
        print(f"[!] mmls: {proc.stderr.strip()[:200]}", file=sys.stderr)
        return ""
    return proc.stdout


def fs_family(desc: str) -> str:
    d = desc.lower()
    for key in ("ntfs", "exfat", "fat", "ext", "hfs", "apfs", "iso", "swap"):
        if key in d:
            return key
    return ""


def report(path: str, sector_size_override: int | None = None) -> int:
    if not os.path.exists(path):
        print(f"[!] no such file: {path}", file=sys.stderr)
        return 2
    print(f"== {path} ({os.path.getsize(path):,} bytes) ==")
    hits = sniff(path)
    if hits:
        for name, hint in hits:
            print(f"  format: {name:38s} -> {hint}")
    else:
        print("  format: unknown magic (probably a bare partition, not a whole disk)")
    seg = split_set(path)
    if len(seg) > 1:
        print(f"  split set of {len(seg)} segments -> mmls -i split " + " ".join(os.path.basename(s) for s in seg))

    out = run_mmls(path) or run_mmls(path, "dos") or run_mmls(path, "gpt")
    if not out:
        print("  [!] no partition table parsed. Try: mmls -t mac, gdisk -l, testdisk, sigfind -t ntfs")
        return 0
    sector_size, parts = parse_mmls(out)
    if sector_size_override:
        sector_size = sector_size_override
    print(f"  sector size: {sector_size}")
    print()
    for p in parts:
        if p["length"] == 0 or "Unallocated" in p["desc"] or "Table" in p["desc"]:
            continue
        byte_off = p["start"] * sector_size
        byte_len = p["length"] * sector_size
        fam = fs_family(p["desc"])
        opts = FS_MOUNT.get(fam, "-o ro,loop,noexec,nodev")
        print(f"slot {p['slot']:>3}  start={p['start']:<12} len={p['length']:<12} {p['desc']}")
        print(f"    bytes: {p['start']} * {sector_size} = {byte_off}  (size {byte_len:,})")
        if opts.startswith("("):
            print(f"    mount: {opts}")
        else:
            print(f"    mount: sudo mount {opts},loop,offset={byte_off} {path} /mnt/img")
        print(f"    tsk:   fls -o {p['start']} -r -p {path}")
        print(f"    tsk:   fsstat -o {p['start']} {path}")
        print(f"    carve: dd if={path} of=part{p['slot']}.dd bs={sector_size} "
              f"skip={p['start']} count={p['length']} status=progress")
        print()
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    image = args[0] if args else "image.dd"
    override = None
    for a in sys.argv[1:]:
        if a.startswith("--sector-size"):
            override = int(a.split("=", 1)[1]) if "=" in a else None
    return report(image, override)


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`mount` says "bad superblock"**: your offset is wrong, or you are pointing at the whole disk
  instead of a partition. Re-read the `mmls` header line for the unit size.
- **Sleuthkit `-o` is sectors, `mount -o offset=` is bytes.** This single mismatch causes most
  failed mounts.
- **Never mount writable.** A journal replay on mount silently changes the image and breaks your
  hash. `mount -o ro` still replays some journals; add `noload` for ext or use `ro,norecovery`.
- **E01 with a missing segment** fails silently mid-read. `ewfinfo` prints the segment count.
- **VMDK descriptor files** are 1 KB of text. The data is in the `-flat.vmdk` or `-s001.vmdk`
  extents next to them; `qemu-nbd` follows the descriptor, `losetup` does not.
- **qemu-nbd without `--read-only`** will happily write to your evidence. Always pass it.
- **Deleted `nbd` cleanup**: if `/dev/nbd0` stays busy, `sudo qemu-nbd -d /dev/nbd0` then
  `sudo rmmod nbd`.
- **4Kn images**: `mmls -b 4096`, and the multiplier becomes 4096 not 512.
- **A "disk image" that is actually a single partition** has no MBR. `mmls` errors; just use
  `fls -r -p image.dd` with no `-o`.
- **`hiberfil.sys`, `pagefile.sys`, `swapfile.sys`** on the mounted volume are free strings hunting
  grounds - run `strings -el` over them.
- **Unallocated space** is where the flag usually is. `blkls -o 2048 image.dd > unalloc.dd` then
  `foremost -i unalloc.dd`.

## Tools

`sleuthkit` (`mmls`, `fls`, `icat`, `istat`, `fsstat`, `blkls`, `blkcat`, `tsk_recover`,
`tsk_gettimes`, `sigfind`, `mactime`), `libewf` (`ewfmount`, `ewfinfo`, `ewfverify`, `ewfexport`,
`ewfacquire`), `qemu-utils` (`qemu-img`, `qemu-nbd`), `libguestfs` (`guestmount`, `virt-ls`),
`afflib` (`affuse`), `pyaff4`, `dislocker`, `cryptsetup`, `testdisk`/`photorec`, `ddrescue`,
`bulk_extractor`, `foremost`, `scalpel`, `binwalk`, `autopsy`, `apfs-fuse`, `xmount`.

## References

- Sleuthkit man pages (`man mmls`, `man fls`, `man icat`) are authoritative for `-o` semantics.
- `qemu-img --help` lists every format string your build supports.
- `ewfinfo`/`ewfverify` ship with libewf; `man ewfmount` documents the FUSE view.
