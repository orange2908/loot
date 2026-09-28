---
title: "Slack Space, Deleted Partitions and Hidden Volumes"
category: forensics
subcategory: hidden-data
type: technique
tags: [slack-space, file-slack, unallocated, blkls, sigfind, hpa, dco, hdparm, testdisk, mmls, veracrypt, truecrypt, luks, cryptsetup, hashcat, entropy, binwalk, hidden-volume, sleuthkit, dfir]
difficulty: hard
summary: "Where bytes hide when the filesystem says nothing is there: slack, unallocated space, HPA/DCO, wiped partition tables, and VeraCrypt/LUKS containers."
when_to_use:
  - "The image is far larger than the sum of its visible files"
  - "mmls shows unpartitioned gaps, or 'Cannot determine partition type'"
  - "A file is high-entropy with no magic bytes and a size that is a multiple of 512"
  - "The challenge says data was deleted but carving the allocated area finds nothing"
tools: [sleuthkit, testdisk, gpart, hdparm, binwalk, ent, veracrypt, cryptsetup, john, hashcat]
related: [disk-image-triage, disk-file-carving, disk-linux-forensics, memory-credential-extraction]
---

## TL;DR

Three places data hides below the filesystem: **slack** (the tail of the last allocated block),
**unallocated space** (freed blocks and unpartitioned gaps), and **host-protected areas**
(HPA/DCO, invisible to the OS but present in a physical image). Extract each with `blkls`, then
carve it. If what falls out is structureless high-entropy data whose size is a multiple of 512,
you have a VeraCrypt/TrueCrypt container and the job becomes key or password recovery.

## Recognise it

- `mmls image.dd` prints `Unallocated` rows of nontrivial size between partitions.
- `binwalk -E image.dd` shows a flat 8.0-bits/byte plateau with no signatures inside it.
- `ls -l container.bin` -> size is an exact multiple of 512 and `file` says `data`.
- `hdparm -N /dev/sdX` reports `max sectors = X/Y` with `X != Y` -> an HPA exists.
- `sigfind -o 0 55AA image.dd` hits at sector boundaries `mmls` never mentioned.

## Anatomy: the kinds of slack

A file occupies whole **clusters/blocks**; its logical size rarely matches, and the leftover is
slack.

- **RAM slack** (sector slack): from end-of-file to the end of the current **512-byte sector**.
  On DOS and old Windows it was filled from the RAM buffer, which is why it sometimes held
  passwords and fragments of other documents. Modern kernels zero-fill it, but CTFs still hide
  bytes there because no ordinary tool reads it.
- **File slack** (drive slack): from the end of the last used sector to the end of the
  **cluster/block**. The OS never writes here, so it still holds bytes from whatever file
  previously owned that cluster -- the classic deleted-fragment source.
- **Partition slack**: sectors inside a partition the filesystem does not cover, because the fs
  size is not an exact multiple of the partition size.
- **Volume slack**: sectors no partition covers -- the gap between the MBR and the first
  partition (traditionally sectors 1..62, now 1..2047), gaps between partitions, and the tail
  after the last one. A 1 MiB pre-partition gap is a very comfortable hiding spot.
- **HPA** (Host Protected Area): set with the ATA `SET MAX ADDRESS` command; the drive reports a
  smaller capacity and the OS cannot see the tail. **DCO** (Device Configuration Overlay): set
  with `DEVICE CONFIGURATION SET`, hides capacity *and* features and sits below the HPA, so a
  DCO-hidden region stays invisible even after the HPA is removed. Both are firmware-level, so
  only a physical acquisition (or removing them first) captures them.

## Extracting it

```sh
# partition map including the unallocated gaps; -B prints sizes in a raw-friendly form
mmls image.dd; mmls -B image.dd
# dump ONLY the slack space of every allocated block
blkls -s -o 2048 image.dd > slack.bin
# unallocated blocks (blkls' default), all blocks (-e), allocated only (-a), unalloc only (-A)
blkls -o 2048 image.dd > unalloc.bin; blkls -e -o 2048 image.dd > all.bin
blkls -a -o 2048 image.dd > alloc.bin; blkls -A -o 2048 image.dd > unalloc2.bin
# a specific block range
blkls -o 2048 image.dd 1000-2000 > range.bin
# now carve and grep what came out (offsets are relative to the EXTRACTED stream, not the image)
strings -a unalloc.bin | grep -aiE 'flag\{|password|BEGIN .*PRIVATE KEY'
foremost -t all -i unalloc.bin -o unalloc_carved; binwalk unalloc.bin
# map an offset in the blkls output back to a real filesystem block, and back again
blkcalc -o 2048 -u 4242 image.dd; blkcalc -o 2048 -d 98765 image.dd
# is a given block allocated, and which group is it in?
blkstat -o 2048 image.dd 98765
# which inode owns this data block (-d = the unit is a data block), and which owns a path
ifind -d 98765 -o 2048 image.dd; ifind -n /etc/passwd -o 2048 image.dd
# which path(s) point at an inode - -a includes deleted names
ffind -o 2048 image.dd 1337; ffind -a -o 2048 image.dd 1337
# scan the raw image for a 2-byte value at a fixed offset within each sector: 55AA at offset 510
# is an MBR/VBR boot signature, and -o 0 means "no offset adjustment"
sigfind -o 0 55AA image.dd
# built-in templates for filesystem boot sectors
sigfind -t ntfs image.dd; sigfind -t fat image.dd; sigfind -t ext3 image.dd
# does the media report a smaller size than it has? (physical acquisition only)
disk_stat /dev/sdb
```

HPA / DCO on real hardware:

```sh
# current vs native max sectors (a mismatch means an HPA hides the tail), then the DCO capacity
hdparm -N /dev/sdb; hdparm --dco-identify /dev/sdb
# TEMPORARILY restore full capacity (the "p" form is permanent); --dco-restore wipes the DCO
hdparm -N p<NATIVE_MAX_SECTORS> /dev/sdb; hdparm --dco-restore /dev/sdb
# confirm the kernel's new view, then image the drive
blockdev --getsz /dev/sdb; dd if=/dev/sdb of=full.dd bs=4M conv=noerror,sync status=progress
```

## Deleted and hidden partitions

```sh
# does the image have a readable table at all? force a type when autodetect fails
mmls image.dd; mmls -t gpt image.dd; mmls -t dos image.dd
# guess partitions by scanning for filesystem signatures, ignoring the table entirely,
# then write the guess back into the table (on a COPY of the image)
gpart image.dd; gpart -W image.dd image.dd
# interactive recovery: Analyse -> Quick Search -> Deeper Search -> Write
testdisk image.dd
# the GPT header magic "EFI PART" sits at LBA 1, and a BACKUP header at the LAST LBA
xxd -s 512 -l 96 image.dd; xxd -s $(( $(stat -c%s image.dd) - 512 )) -l 96 image.dd
# rebuild the primary GPT from the backup; -e also relocates the backup to the true end
sgdisk -e /dev/sdb; sgdisk -v /dev/sdb; sgdisk -p /dev/sdb
# gdisk's recovery menu: "r" then "b" = load the backup GPT, "c" = load the MBR into the GPT
gdisk image.dd
# NTFS: the OEM ID "NTFS    " is at offset 3 of the volume boot record
grep -aob 'NTFS    ' image.dd | head
# FAT32: "FAT32   " at offset 82 of the VBR (FAT16 has "FAT16   " at offset 54)
grep -aob 'FAT32   ' image.dd | head
# ext2/3/4: the magic is little-endian, so on disk it is 53 ef at superblock+56 = fs byte 1080
grep -aob $'\x53\xef' image.dd | head -50
# confirm a candidate at byte B: B+1080 holds 53 ef, and fsstat takes B/512 as its -o
xxd -s $((CANDIDATE + 1080)) -l 2 image.dd; fsstat -o $((CANDIDATE / 512)) image.dd
```

Rebuilding an MBR entry by hand: the four 16-byte entries live at bytes 446..509, each one
`status(1) CHS_first(3) type(1) CHS_last(3) LBA_start(4, LE) sectors(4, LE)`, and bytes 510..511
are `55 AA`. Types: `0x83` Linux, `0x07` NTFS/exFAT, `0x0B`/`0x0C` FAT32, `0x8E` Linux LVM,
`0xEE` GPT protective. Write it with `dd ... conv=notrunc seek=446` -- on a **copy**.

## Hidden volumes: VeraCrypt / TrueCrypt / LUKS

A VeraCrypt/TrueCrypt container has **no magic bytes by design**: the first 64 bytes are the
salt and the next 448 are an encrypted header whose plaintext `VERA`/`TRUE` magic only appears
after correct key derivation. You detect it statistically, not structurally: uniformly high
entropy (~7.99 bits/byte) with no periodicity, a size that is an exact multiple of 512 (usually
of 1 MiB), no file type, no compression header, and no repeated blocks anywhere.

```sh
# whole-file entropy view (a container is one flat plateau edge to edge), then numeric entropy
# and chi-square: expect "Entropy = 7.99..." and a plausible chi-square
binwalk -E container.hc; ent container.hc
# is the size a clean multiple of 512?
python3 -c "import os,sys;s=os.path.getsize(sys.argv[1]);print(s, s%512)" container.hc
# confirm there is genuinely nothing recognisable inside
binwalk container.hc; file container.hc; strings -n 8 container.hc | head
```

A **hidden volume** lives in the free space of an **outer volume**, with its own header at byte
offset 65536 of the same container (plus a backup near the end). The outer password shows decoy
files, the hidden password shows the real ones, and the outer volume has no idea the hidden one
exists -- so writing to the outer volume **destroys** the hidden one unless you mount with
hidden-volume protection.

```sh
# mount read-only and headless at an explicit mount point
veracrypt --text --mount container.hc /mnt/vc --mount-options=ro
# protect a hidden volume from being overwritten (this asks for BOTH passwords)
veracrypt --text --mount container.hc /mnt/vc --protect-hidden=yes
# non-interactive (CTF only - the password lands in your shell history)
veracrypt --text --non-interactive --mount container.hc /mnt/vc --password='hunter2' \
  --pim=0 --keyfiles='' --protect-hidden=no
# keyfiles change the KDF input entirely: without them no password will ever work
veracrypt --text --mount container.hc /mnt/vc --keyfiles=/evidence/photo.jpg
# list and dismount
veracrypt --text --list; veracrypt --text --dismount container.hc
# cryptsetup opens TrueCrypt AND VeraCrypt containers with no veracrypt binary at all
cryptsetup open --type tcrypt --veracrypt container.hc vc0
# the HIDDEN volume instead of the outer one, and a whole-disk (system) VeraCrypt volume
cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden container.hc vc0
cryptsetup open --type tcrypt --veracrypt --tcrypt-system /dev/sdb2 vc0
# then treat /dev/mapper/vc0 as an ordinary block device
fsstat /dev/mapper/vc0; mount -o ro /dev/mapper/vc0 /mnt/vc; cryptsetup close vc0
# extract a crackable hash from the header (john-jumbo ships both extractors), then crack
veracrypt2john.py container.hc > vc.hash; truecrypt2john.py container.tc > tc.hash
john --wordlist=rockyou.txt --rules=Jumbo vc.hash; john --show vc.hash
# hashcat cracks the RAW container: 13721 = SHA512+AES, 13722 = +Twofish, 13723 = +Serpent
hashcat -m 13721 -a 0 container.hc rockyou.txt
# the RIPEMD160 family is 13711/13712/13713, Whirlpool 13731/13732/13733
hashcat -m 13711 -a 0 container.hc rockyou.txt; hashcat -m 13721 vc.hash rockyou.txt
# LUKS: dump the header without unlocking - version, cipher, hash, KDF, used keyslots
cryptsetup luksDump /dev/sdb2; cryptsetup luksDump container.img
# which LUKS version? v1's header magic is "LUKS\xba\xbe" at offset 0; v2 adds a JSON area
xxd -l 16 container.img
# extract and crack (luks2john handles v1 and v2 in modern john-jumbo); hashcat LUKS v1 = 14600
luks2john container.img > luks.hash; john --wordlist=rockyou.txt luks.hash
hashcat -m 14600 -a 0 luks.hash rockyou.txt; hashcat --help | grep -i luks
# unlock, map, and dump the master key so you can decrypt an image offline
cryptsetup open /dev/sdb2 luks0 && fsstat /dev/mapper/luks0
cryptsetup luksDump --dump-master-key /dev/sdb2
# BitLocker, for completeness
bitlocker2john -i bde.img > bde.hash; hashcat -m 22100 bde.hash rockyou.txt
dislocker -V bde.img -u -- /mnt/bde && mount -o ro,loop /mnt/bde/dislocker-file /mnt/win
```

**If you also have a memory image the key is in it**, and you never need to crack anything --
this is usually the intended CTF path:

```sh
# volatility 2: is a TrueCrypt/VeraCrypt volume mounted, and what are its keys?
vol.py -f mem.raw --profile=Win7SP1x64 truecryptsummary
vol.py -f mem.raw --profile=Win7SP1x64 truecryptmaster
vol.py -f mem.raw --profile=Win7SP1x64 truecryptpassphrase
# generic: AES key schedules are findable in any raw dump
aeskeyfind mem.raw; rsakeyfind mem.raw; bulk_extractor -E aes -o out mem.raw
```

## Code

```python
#!/usr/bin/env python3
"""Per-block Shannon entropy with a text sparkline, for spotting hidden volumes.

H = -sum(p_i * log2(p_i)) over the 256 byte values in each block, in bits per
byte: 0.0 (all one byte) .. 8.0 (uniform random). Text ~4.0-5.0, native code
~6.0-6.5, compressed ~7.9, encrypted ~7.999. A flat plateau above --threshold
with no file magic inside it is a VeraCrypt/LUKS container or an encrypted blob.

    python3 entropy_map.py image.dd --block 65536 --threshold 7.5
    python3 entropy_map.py --selftest
"""
import argparse, collections, math, sys

SPARK = " .:-=+*#%@"
MAXH = 8.0

def block_entropy(block: bytes) -> float:
    """Shannon entropy of one block, in bits per byte."""
    if not block:
        return 0.0
    n = len(block)
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(block).values())

def spark(value: float) -> str:
    """Map 0.0..8.0 onto one character of the ramp."""
    return SPARK[int(max(0.0, min(value, MAXH)) / MAXH * (len(SPARK) - 1))]

def iter_blocks(path: str, size: int):
    """Yield (offset, block_bytes) for every block of the file."""
    with open(path, "rb") as fh:
        offset = 0
        while True:
            block = fh.read(size)
            if not block:
                return
            yield offset, block
            offset += len(block)

def regions(values, block: int, threshold: float, min_blocks: int):
    """Collapse consecutive high-entropy blocks into (start, end, mean) runs."""
    out, start, run = [], None, []
    for index, value in enumerate(values):
        if value >= threshold:
            if start is None:
                start, run = index, []
            run.append(value)
        elif start is not None:
            if index - start >= min_blocks:
                out.append((start * block, index * block, sum(run) / len(run)))
            start = None
    if start is not None and len(values) - start >= min_blocks:
        out.append((start * block, len(values) * block, sum(run) / len(run)))
    return out

def render(values, block: int, width: int):
    """One sparkline row per `width` blocks, prefixed with the byte offset."""
    rows = []
    for row in range(0, len(values), width):
        chunk = values[row:row + width]
        rows.append(f"0x{row * block:012x} |{''.join(map(spark, chunk)):<{width}s}| "
                    f"min={min(chunk):.2f} max={max(chunk):.2f}")
    return rows

def selftest() -> int:
    import os, tempfile, zlib
    assert block_entropy(b"") == 0.0 and block_entropy(b"\x00" * 4096) == 0.0
    assert abs(block_entropy(b"AB" * 2048) - 1.0) < 1e-9            # 2 symbols = 1 bit
    assert abs(block_entropy(bytes(range(256)) * 16) - 8.0) < 1e-9  # uniform = 8 bits
    assert spark(0.0) == SPARK[0] and spark(8.0) == SPARK[-1]
    zeros, rand = b"\x00" * 8192, os.urandom(32768)
    text = (b"the quick brown fox jumps over the lazy dog. " * 200)[:8192]
    blob = zeros + text + rand + zeros
    fd, path = tempfile.mkstemp(prefix="entropytest-")
    os.write(fd, blob)
    os.close(fd)
    try:
        block = 4096
        values = [block_entropy(b) for _, b in iter_blocks(path, block)]
        assert len(values) == len(blob) // block and values[0] == 0.0
        hot = regions(values, block, 7.5, 2)
        assert hot, "the random region should be flagged"
        start, end, mean = hot[0]
        assert (start, end) == (16384, 49152) and mean > 7.9, (start, end, mean)
        assert block_entropy(zlib.compress(os.urandom(8192))) > 7.8
        assert render(values, block, 16)[0].startswith("0x000000000000")
        print(f"selftest OK - high-entropy region 0x{start:x}..0x{end:x} (mean {mean:.3f})")
    finally:
        os.unlink(path)
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default="image.dd")
    ap.add_argument("--block", type=int, default=65536)
    ap.add_argument("--threshold", type=float, default=7.5,
                    help="bits/byte above which a block counts as high entropy")
    ap.add_argument("--min-blocks", type=int, default=2)
    ap.add_argument("--width", type=int, default=64, help="sparkline chars per row")
    ap.add_argument("--no-map", action="store_true", help="only print the regions")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    try:
        values = [block_entropy(b) for _, b in iter_blocks(args.path, args.block)]
    except FileNotFoundError:
        print(f"no such file: {args.path}", file=sys.stderr)
        return 1
    if not values:
        print("empty file", file=sys.stderr)
        return 1
    print(f"ramp: low [{SPARK}] high   block={args.block}  blocks={len(values)}")
    if not args.no_map:
        print("\n".join(render(values, args.block, args.width)))
    print(f"\nmean entropy {sum(values) / len(values):.3f} bits/byte")
    hot = regions(values, args.block, args.threshold, args.min_blocks)
    if not hot:
        print(f"no region >= {args.threshold} bits/byte for {args.min_blocks}+ blocks")
        return 0
    for start, end, mean in hot:
        flat = "  <- FLAT: looks like a container" if mean > 7.95 else ""
        print(f"  0x{start:012x}-0x{end:012x}  {end - start:>12d} bytes  mean={mean:.3f}{flat}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- `blkls -s` outputs slack **only**, so offsets in it mean nothing until you map them back with
  `blkcalc -u`. Record that mapping before you report a finding.
- On ext4 with extents, file slack is more often zeroed by the allocator; NTFS and FAT images
  are far richer slack targets. SSDs with TRIM return zeros for freed blocks, so unallocated
  recovery from a live SSD is usually futile -- a CTF's virtual disk is not TRIMmed and is fine.
- **A logical image never contains an HPA/DCO region.** If you were handed `image.dd` and cannot
  run `disk_stat`, look instead for a mismatch between the partition table's claimed last sector
  and the actual file size.
- GPT: a wiped primary header at LBA 1 usually leaves the backup at the last LBA intact
  (`gdisk` -> `r` -> `b`); a wiped backup is repaired by `sgdisk -e`.
- `mmls` failing does not mean "no partitions", it means "no *table*". Go straight to `gpart`,
  `sigfind` and signature grepping.
- High entropy alone does not prove encryption -- JPEG, PNG, ZIP, MP4 and every compressed
  stream sit above 7.9. What distinguishes a container is that entropy is high **and** there is
  no header, no footer and no internal structure anywhere in the file.
- You cannot prove a hidden volume exists from the container alone; that is the whole point of
  plausible deniability. Evidence comes from a mount record, a recent-files entry, a shell
  history line, or the key in RAM.
- Never mount the outer volume read-write while looking for a hidden one: use
  `--mount-options=ro` or `--protect-hidden=yes`. A wrong VeraCrypt **PIM** fails exactly like a
  wrong password, so if the challenge mentions a number beside the password, try it as the PIM.
- Journals and wear-levelling can hold plaintext copies of data that a "secure delete"
  overwrote in place. Try `jls`/`jcat` before giving up.

## Tools

`sleuthkit` (`mmls`, `blkls`, `blkcalc`, `blkstat`, `ifind`, `ffind`, `sigfind`, `fsstat`,
`disk_stat`), `testdisk`, `gpart`, `gdisk`/`sgdisk`, `hdparm`, `binwalk`, `ent`, `veracrypt`,
`cryptsetup`, `dislocker`, `john` (`veracrypt2john`, `truecrypt2john`, `luks2john`,
`bitlocker2john`), `hashcat`, `aeskeyfind`, `bulk_extractor`, `volatility`, `autopsy`.

## References

- `man blkls`, `man blkcalc`, `man sigfind`, `man ifind`, `man ffind` (The Sleuth Kit), and
  `man hdparm` for `-N`, `--dco-identify` and `--dco-restore`.
- `man cryptsetup` covers `luksDump` and the `tcrypt` type with its `--veracrypt`,
  `--tcrypt-hidden` and `--tcrypt-system` options.
- `hashcat --help` is the authoritative list of VeraCrypt (`137xx`) and LUKS mode numbers for
  your build -- they have been renumbered across releases.
