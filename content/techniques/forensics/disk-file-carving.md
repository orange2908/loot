---
title: "File Carving and Recovery - binwalk, foremost, scalpel, photorec, testdisk"
category: forensics
subcategory: carving
type: technique
tags: [carving, file-carving, binwalk, foremost, scalpel, photorec, testdisk, bulk-extractor, tsk-recover, sleuthkit, icat, magic-bytes, file-signatures, header-footer, fragmentation, entropy, dd, xxd, recovery, dfir]
difficulty: easy
summary: "Recover embedded and deleted files from any blob: signature carving with binwalk/foremost/scalpel, filesystem-aware recovery with photorec/tsk_recover, and repairing what comes out broken."
when_to_use:
  - "You have a disk image, a firmware dump, a memory dump or an unknown binary blob"
  - "file(1) says 'data' but strings shows PNG/ZIP/PDF fragments inside"
  - "A challenge says 'a file was deleted' and the filesystem metadata is gone"
  - "Something is appended after the end of a valid image or archive"
tools: [binwalk, foremost, scalpel, photorec, testdisk, bulk-extractor, sleuthkit, pngcheck]
related: [disk-image-triage, disk-linux-forensics, disk-hidden-data, memory-linux-and-carving]
---

## TL;DR

Run `binwalk file` first -- it says what is inside and where, without extracting anything.
If the blob is a filesystem, prefer **filesystem-aware** recovery (`tsk_recover`, `fls`+`icat`,
testdisk's Undelete) because you get real names and sizes. Fall back to blind **signature
carving** only when the metadata is gone, and budget time for repairing what comes out.

## Recognise it

- `file blob` -> `data`, but `binwalk blob` lists `PNG image, Zip archive` at offsets.
- `xxd blob | head` shows a valid header and the file is far larger than the format needs, or
  `fls -rpd -o 2048 image.dd` lists entries prefixed with `*` (deleted).
- `binwalk -E blob` shows a flat high-entropy plateau -> embedded compressed/encrypted payload.

## Theory

Three strategies, in increasing order of cleverness:

1. **Header/footer carving.** Find a signature, then scan for the matching footer or take a
   fixed maximum number of bytes. Cheap, works on contiguous data, and is what `foremost` and
   `scalpel` do. Formats with no footer (ELF, MP3, raw formats) only get a size guess.
2. **File-structure (semantic) carving.** Parse the format's own length fields to find the real
   end: PNG chunk lengths, the ZIP end-of-central-directory, TAR's 512-byte block arithmetic,
   PE `SizeOfImage`. Much more accurate, and what a hand-written carver should do.
3. **Fragmentation handling.** A file split across non-adjacent runs will not carve. The classic
   answer is **bifragment gap carving**: assume two fragments, fix the header and footer blocks,
   then brute-force the gap size and split point, validating each candidate by decoding it. It
   is O(n^2) in blocks, so it is only practical on one small file -- which is why
   filesystem-aware recovery beats carving whenever the metadata still exists.

Carved output is broken more often than not: the footer belongs to another file, the tail picks
up slack garbage, the middle holds an unrelated fragment. Decoders forgive **trailing** junk and
never forgive a **missing tail**.

## Workflow: binwalk

```sh
# signature scan - offset, hex offset and description. Do this first, always.
binwalk file.bin
# extract into _file.bin.extracted/ (newer binwalk refuses as root); -M recurses, --depth bounds
binwalk -e --run-as=root file.bin; binwalk -M -e --depth=4 file.bin
# extract only PNGs with --dd='<type>:<extension>[:<cmd>]', or match a raw byte string
binwalk --dd='png image:png' file.bin; binwalk --raw='\x89PNG\r\n\x1a\n' file.bin
# entropy graph (writes file.bin.png) or --nplot for a text rising/falling edge report; then
# an architecture guess for unknown firmware, and a bounded scan window
binwalk -E file.bin; binwalk -E --nplot file.bin; binwalk -A file.bin
binwalk --offset=0x100000 --length=0x10000 file.bin
```

`binwalk -e` false-positives constantly (any random `1F 8B` looks like gzip). Read the plain
`binwalk` listing before trusting an extraction, and check free disk space before `-M -e`.

## Workflow: foremost and scalpel

```sh
# carve every built-in type into ./out (foremost refuses a non-empty -o), or just the types
# you want - far less noise; audit.txt in -o records every carve with its offset
foremost -t all -i image.dd -o out; foremost -t jpg,png,pdf,zip,gif -i image.dd -o out
# use a custom config, quietly, and carve straight from a device
foremost -c foremost.conf -Q -i image.dd -o out; foremost -t all -i /dev/sdb -o out
# scalpel is the faster fork; -b flattens the output tree, -v is verbose
scalpel -c scalpel.conf -o out image.dd; scalpel -b -v -c scalpel.conf -o out image.dd
```

A `foremost.conf` line is `extension case size header footer [options]`:

```text
png     y   20000000   \x89PNG\x0d\x0a\x1a\x0a   \x49\x45\x4e\x44\xae\x42\x60\x82
jpg     y   20000000   \xff\xd8\xff\xe0          \xff\xd9
gif     y    5000000   \x47\x49\x46\x38\x37\x61  \x00\x3b
pdf     y   10000000   %PDF                      %%EOF     REVERSE
```

`scalpel.conf` uses the same columns with two extra footer flags:

```text
#  ext  case(y/n)  max-carve-size  header  footer  [REVERSE|NEXT]
#  REVERSE = search backwards from max size for the LAST footer (right for PDF/ZIP)
#  NEXT    = stop at the next header of the same type instead of at a footer
#  an omitted footer means "always carve exactly max-carve-size bytes"
jpg     y     20000000    \xff\xd8\xff\xe0\x00\x10   \xff\xd9
pdf     y     50000000    %PDF                       %%EOF       REVERSE
zip     y     50000000    PK\x03\x04                 PK\x05\x06  REVERSE
docx    y     50000000    PK\x03\x04                             NEXT
elf     y     20000000    \x7fELF
```

## Workflow: photorec, testdisk, bulk_extractor

```sh
# fully non-interactive photorec: recover everything from image.dd into ./out
photorec /d out /cmd image.dd search
# restrict the filetype set (options/fileopt are the interactive sub-menus, driven by name);
# against a live device photorec needs root; testdisk on an image is interactive
photorec /d out /cmd image.dd partition_none,fileopt,everything,disable,png,enable,search
photorec /d out /cmd /dev/sdb search; testdisk image.dd
# bulk_extractor: feature extraction, not carving - emails, URLs, CCNs, EXIF, PII, zip members
bulk_extractor -o out image.dd; head out/url.txt out/email.txt out/zip.txt out/exif.txt
```

testdisk menu flow for "the partition table is gone": `[No Log]` -> pick the disk -> table type
(`Intel` for MBR, `EFI GPT` for GPT) -> **Analyse** -> **Quick Search** (scans for partition boot
sectors; press `P` on a hit to *list its files* without writing anything, `c` to copy one out) ->
**Deeper Search** if that missed it -> mark partitions `P`/`*`/`L` -> **Write** and confirm, on a
copy. `[Advanced]` -> `[Undelete]` lists deleted files per partition and, being metadata-aware,
beats carving whenever it works.

## Filesystem-aware recovery (prefer this)

```sh
# the partition offset, in SECTORS, for every -o below
mmls image.dd
# recover ALL files (-e = allocated + deleted) with real paths, or only the deleted ones
tsk_recover -e -o 2048 image.dd out; tsk_recover -o 2048 image.dd out
# list everything recursively (deleted entries prefixed *), then pull one out by inode number
fls -rpd -o 2048 image.dd; icat -o 2048 image.dd 1337 > recovered.bin
# which inode owns an interesting data block, and which path points at that inode?
ifind -d 98765 -o 2048 image.dd; ffind -o 2048 image.dd 1337
```

## Manual carving by offset

```sh
# grep for a header printing BYTE offsets -- -a (as text), -o (only match), -b (offset) --
# then confirm it before carving
grep -aob $'PK\x03\x04' image.dd | head; grep -aob $'\x89PNG' image.dd | head
xxd -s 0x1000 -l 64 image.dd
# carve LEN bytes from byte OFFSET (bs=1 is exact but slow over large ranges)
dd if=image.dd bs=1 skip=$OFFSET count=$LEN of=out.bin status=none
# faster when OFFSET is 4096-aligned, and the pure-coreutils form (tail counts from byte N,
# 1-based, and head takes LEN bytes)
dd if=image.dd bs=4096 skip=$((OFFSET/4096)) count=$((LEN/4096 + 1)) of=out.bin
tail -c +$((OFFSET+1)) image.dd | head -c $LEN > out.bin
# verify head and tail of what you carved
file out.bin; xxd -l 32 out.bin; xxd -s -16 out.bin
```

## Magic bytes reference

| Format | Header (hex) | Footer / end marker | Notes |
|---|---|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` | `IEND` + its CRC; chunk-length parseable |
| JPEG/JFIF | `FF D8 FF E0` | `FF D9` | also `FF D8 FF E1` (Exif), `FF D8 FF DB` |
| GIF | `47 49 46 38 37/39 61` | `00 3B` | trailer byte `0x3B` |
| PDF | `25 50 44 46` (`%PDF`) | `25 25 45 4F 46` (`%%EOF`) | carve to the **last** `%%EOF` |
| ZIP | `50 4B 03 04` | `50 4B 05 06` (EOCD) | EOCD is the real end; also DOCX/JAR/APK/ODT |
| RAR v4 / v5 | `52 61 72 21 1A 07 00` / `...07 01 00` | -- | `Rar!\x1a\x07` |
| 7-Zip | `37 7A BC AF 27 1C` | -- | `7z\xbc\xaf\x27\x1c` |
| GZIP | `1F 8B 08` | -- | last 4 bytes = uncompressed size mod 2^32 |
| BZIP2 | `42 5A 68` (`BZh`) | `17 72 45 38 50 90` | the end magic is bit-aligned, not byte-aligned |
| ELF | `7F 45 4C 46` | -- | end = `e_shoff + e_shnum*e_shentsize` |
| PE/EXE/DLL | `4D 5A` (`MZ`) | -- | `PE\0\0` at the offset stored at `0x3C` |
| SQLite 3 | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | -- | `SQLite format 3\0` |
| OLE2 (doc/xls/msi) | `D0 CF 11 E0 A1 B1 1A E1` | -- | compound file binary format |
| RIFF (wav/avi/webp) | `52 49 46 46` + size + `WAVE`/`AVI `/`WEBP` | -- | size at offset 4, LE u32, excludes 8 |
| MP3 / MP4 | `49 44 33` (`ID3`) / `ftyp` at offset 4 | -- | frameless MP3 starts `FF FB`/`FF F3` |
| TAR | `75 73 74 61 72` (`ustar`) at **offset 257** | two 512-byte zero blocks | header per 512B block |
| PCAP | `D4 C3 B2 A1` / `A1 B2 C3 D4` | -- | LE / BE; `0A 0D 0D 0A` = pcapng |

## Repair

```sh
# zip: -F is the gentle fix, -FF rebuilds the central directory from surviving local headers
zip -F broken.zip --out fixed.zip; zip -FF broken.zip --out fixed.zip; unzip -t fixed.zip
# if ONLY the EOCD is missing, appending an empty-archive EOCD sometimes suffices
printf 'PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> broken.zip
# png: -v prints every chunk with length and CRC, so a bad CRC points at the broken chunk
pngcheck -v carved.png; pngcheck -q out/png/* 2>&1 | grep -v OK
# jpeg: rewrite the stream keeping all markers (drops trailing junk), then decode strictly
jpegtran -copy all -optimize -outfile fixed.jpg broken.jpg; djpeg -outfile /dev/null broken.jpg
# fix a clobbered magic in place without changing the length, or strip the junk before it
printf '\x89PNG\x0d\x0a\x1a\x0a' | dd of=carved.png bs=1 seek=0 conv=notrunc
dd if=carved.bin bs=1 skip=$OFFSET of=fixed.bin
# pdf / gzip / sqlite / tar salvage
qpdf --qdf --object-streams=disable broken.pdf fixed.pdf; gzip -dc broken.gz > out 2>/dev/null
sqlite3 broken.db ".recover" > recovered.sql; tar -xvf broken.tar --ignore-zeros
```

## Code

```python
#!/usr/bin/env python3
"""A signature carver with a real footer/length table and a built-in self-test.

Each hit is bounded by (a) a format-specific length parser, (b) the matching
footer, or (c) the signature's max_len; every carve is written out and its
offset printed.

    python3 carve.py image.dd -o out --min-size 64
    python3 carve.py --selftest
"""
import argparse, os, struct, sys

def png_length(buf: bytes, start: int):
    """Walk PNG chunks from `start`; return the exact file length or None."""
    pos = start + 8
    while pos + 8 <= len(buf):
        (size,) = struct.unpack_from(">I", buf, pos)
        ctype, end = buf[pos + 4:pos + 8], pos + 12 + size
        if size > 0x7FFFFFFF or end > len(buf):
            return None
        if ctype == b"IEND":
            return end - start
        pos = end
    return None

def gif_length(buf: bytes, start: int):
    """GIF ends at the first 0x3B trailer after the 13-byte header."""
    idx = buf.find(b"\x3b", start + 13)
    return (idx + 1 - start) if idx != -1 else None

def zip_length(buf: bytes, start: int):
    """Find the LAST end-of-central-directory record and include its comment."""
    idx = buf.rfind(b"PK\x05\x06")
    if idx < start or idx + 22 > len(buf):
        return None
    (clen,) = struct.unpack_from("<H", buf, idx + 20)
    end = idx + 22 + clen
    return (end - start) if end <= len(buf) else (idx + 22 - start)

class Sig:
    """One carve signature: header, optional footer/length parser, max length."""

    def __init__(self, name, ext, header, footer=None, max_len=16 << 20,
                 length_fn=None, last_footer=False):
        self.name, self.ext, self.header = name, ext, header
        self.footer, self.max_len = footer, max_len
        self.length_fn, self.last_footer = length_fn, last_footer

    def carve(self, buf: bytes, start: int):
        if self.length_fn is not None:
            size = self.length_fn(buf, start)
            if size is not None:
                return buf[start:start + size]
        window = buf[start:start + self.max_len]
        if self.footer is None:
            return window
        idx = (window.rfind(self.footer) if self.last_footer
               else window.find(self.footer, len(self.header)))
        return window[:idx + len(self.footer)] if idx != -1 else None

SIGNATURES = [
    Sig("png", "png", b"\x89PNG\r\n\x1a\n", b"IEND\xae\x42\x60\x82", 64 << 20, png_length),
    Sig("jpeg", "jpg", b"\xff\xd8\xff", b"\xff\xd9", 64 << 20),
    Sig("gif", "gif", b"GIF89a", b"\x00\x3b", 32 << 20, gif_length),
    Sig("pdf", "pdf", b"%PDF-", b"%%EOF", 128 << 20, last_footer=True),
    Sig("zip", "zip", b"PK\x03\x04", b"PK\x05\x06", 256 << 20, zip_length, True),
    Sig("gzip", "gz", b"\x1f\x8b\x08", None, 64 << 20),
    Sig("bzip2", "bz2", b"BZh", None, 64 << 20),
    Sig("sevenzip", "7z", b"7z\xbc\xaf\x27\x1c", None, 256 << 20),
    Sig("rar", "rar", b"Rar!\x1a\x07", None, 256 << 20),
    Sig("elf", "elf", b"\x7fELF", None, 64 << 20),
    Sig("pe", "exe", b"MZ\x90\x00", None, 64 << 20),
    Sig("sqlite", "sqlite", b"SQLite format 3\x00", None, 256 << 20),
    Sig("ole2", "ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", None, 128 << 20),
    Sig("riff", "riff", b"RIFF", None, 256 << 20),
    Sig("id3", "mp3", b"ID3", None, 64 << 20),
    Sig("pcap", "pcap", b"\xd4\xc3\xb2\xa1", None, 256 << 20),
]
def scan(data: bytes, sigs):
    """Return every (offset, signature) header hit, sorted by offset."""
    hits = []
    for sig in sigs:
        pos = data.find(sig.header)
        while pos != -1:
            hits.append((pos, sig))
            pos = data.find(sig.header, pos + 1)
    hits.sort(key=lambda h: (h[0], h[1].name))
    return hits

def carve_bytes(data: bytes, outdir: str, sigs, min_size: int, quiet: bool = False):
    """Carve `data` into `outdir`; return [(offset, name, path, size), ...]."""
    os.makedirs(outdir, exist_ok=True)
    results = []
    for index, (offset, sig) in enumerate(scan(data, sigs)):
        blob = sig.carve(data, offset)
        if blob is None or len(blob) < min_size:
            continue
        out = os.path.join(outdir, f"{index:06d}_{offset:012x}.{sig.ext}")
        with open(out, "wb") as fh:
            fh.write(blob)
        results.append((offset, sig.name, out, len(blob)))
        if not quiet:
            print(f"0x{offset:012x}  {sig.name:<9s} {len(blob):>12d} bytes  -> {out}")
    return results

def selftest() -> int:
    """Build a blob holding a real PNG, GZIP and ZIP, then carve them back out."""
    import gzip, io, shutil, tempfile, zipfile, zlib

    def chunk(ctype, payload):
        body = ctype + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))
    gz = gzip.compress(b"flag{carved_from_gzip}" * 4)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("secret.txt", "flag{carved_from_zip}")
    zp = buf.getvalue()
    blob = b"\x00" * 1024 + png + b"JUNK" * 32 + gz + b"\xde\xad" * 64 + zp + b"\x00" * 512

    tmp = tempfile.mkdtemp(prefix="carvetest-")
    try:
        results = carve_bytes(blob, tmp, SIGNATURES, min_size=16, quiet=True)
        found = {name: (off, path) for off, name, path, _ in results}
        for want in ("png", "gzip", "zip"):
            assert want in found, f"{want} not carved: {sorted(found)}"
        assert found["png"][0] == 1024
        with open(found["png"][1], "rb") as fh:
            assert fh.read() == png, "png carve is not byte-identical"
        with open(found["gzip"][1], "rb") as fh:
            assert gzip.decompress(fh.read()[:len(gz)]).startswith(b"flag{")
        with zipfile.ZipFile(found["zip"][1]) as zf:
            assert zf.read("secret.txt") == b"flag{carved_from_zip}"
        print(f"selftest OK - {len(results)} carved; png@{found['png'][0]} zip@{found['zip'][0]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", nargs="?", default="image.dd")
    ap.add_argument("-o", "--outdir", default="carved")
    ap.add_argument("--only", help="comma-separated signature names, e.g. png,zip,pdf")
    ap.add_argument("--min-size", type=int, default=32)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    wanted = {w.strip() for w in (args.only or "").split(",") if w.strip()}
    sigs = [s for s in SIGNATURES if s.name in wanted] if wanted else SIGNATURES
    if not sigs:
        print(f"no signature matched {sorted(wanted)}", file=sys.stderr)
        return 2
    try:
        with open(args.image, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        print(f"no such file: {args.image}", file=sys.stderr)
        return 1
    results = carve_bytes(data, args.outdir, sigs, args.min_size)
    print(f"\n{len(results)} object(s) carved into {args.outdir}/", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Whole disk vs partition**: `foremost`/`scalpel` carve a whole-disk image fine, but
  `tsk_recover`/`fls` need `-o <start sector>` from `mmls`.
- **`JFIF` vs `Exif`**: carving only `FF D8 FF E0` misses every phone photo (`FF D8 FF E1`).
  Use the 3-byte `FF D8 FF` and accept a few false positives. A `FF D9` inside entropy-coded
  data is escaped as `FF 00`, but Exif thumbnails carry their own `FF D8`/`FF D9` pair, which
  is why carvers often emit a tiny thumbnail *and* the real photo.
- **ZIP must be carved to the EOCD**, not to the first `PK\x05\x06`-looking bytes; use `REVERSE`
  in scalpel or `rfind` in code, or it unzips with "unexpected end of archive".
- **Appended data** is the most common CTF trick -- a valid PNG followed by a ZIP. `binwalk`
  finds it, `unzip file.png` often just works, `7z x file.png` works more often still.
- Deleted-then-partly-overwritten blocks decode halfway, then produce garbage; compare the
  carved size against the size `fls`/`istat` reports for the original inode.
- `photorec` ignores filesystem metadata, so you get `f0123456.png` names -- run `tsk_recover -e`
  first if you want paths. Entropy near 8.0 bits/byte means compressed or encrypted, so nothing
  will carve out of it: run `binwalk -E` first. Slack space is not covered by carving a whole
  file either; extract it with `blkls -s` and carve that separately.

## Tools

`binwalk`, `foremost`, `scalpel`, `photorec`, `testdisk`, `bulk_extractor`, `sleuthkit`
(`tsk_recover`, `fls`, `icat`, `ifind`, `ffind`, `blkls`), `autopsy`, `ext4magic`, `extundelete`,
`pngcheck`, `jpegtran`, `qpdf`, `zip -FF`, `7z`, `unblob`, `stegseek`.

## References

- `binwalk --help` lists every `--dd`, `--raw`, `-M`, `-E` flag used above; `man foremost`,
  `man scalpel` and the shipped `/etc/scalpel/scalpel.conf` document the config columns and the
  `REVERSE` / `NEXT` options; `man photorec` documents the `/d` and `/cmd` syntax. The PNG,
  JPEG, ZIP (APPNOTE) and POSIX tar specs define the header/footer bytes in the table.
