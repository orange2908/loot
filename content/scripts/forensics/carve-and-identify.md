---
title: "Carve and Identify - Magic-Byte Scanner and Extractor"
category: forensics
subcategory: carving
type: script
tags: [carving, file-carving, magic-bytes, file-signature, binwalk, foremost, scalpel, recovery, disk-image, memory-dump, python, dfir, entropy, sha256, file-magic]
summary: "Stdlib-only binwalk replacement: scans a blob for 55+ signatures, works out a real length per hit, carves, verifies and hashes each one."
tools: [python3, binwalk, foremost, scalpel, file, xxd]
related: [disk-file-carving, file-magic-bytes, disk-image-triage, memory-linux-and-carving, pcap-extractor]
---

## What it does

`binwalk -e` when there is no binwalk, and a better answer than `foremost` when the embedded
file's length matters. It streams the blob in overlapping chunks, matches a table of 55+
signatures (including anchored ones: `ustar` at +257, `CD001` at +32769, `ftyp` at +4), then
computes a length per hit instead of guessing: a footer search where the format has one, a
real header parser where it is cheap (PNG chunk walk, ZIP end-of-central-directory, SQLite
`page_size * page_count`, gzip member, ELF section table, PE section table, RIFF size field,
MP4 box walk), a cap otherwise. Each carve is verified, sha256'd and written out.

## Usage

```bash
# full pass over a disk image: writes carved/<offset>_<ext>
python3 carve.py disk.img --outdir carved
# see what is in there before writing 4 GB of carves to disk
python3 carve.py memory.raw --list-only
# only the formats you care about, skipping tiny false positives
python3 carve.py memory.raw --types png,zip,pdf,sqlite --min-size 512 --outdir loot
# also pull out files embedded INSIDE another carve (zip in a png, png in a pcap)
python3 carve.py chal.png --nested --list-only
# where is the encrypted/compressed blob hiding?
python3 carve.py firmware.bin --entropy --list-only
# no input file needed: builds a blob with a real png/zip/gzip/pdf and asserts
python3 carve.py --selftest
# cross-check the carves the usual way
file carved/* && for f in carved/*_zip; do unzip -l "$f"; done
```

## Script

```python
#!/usr/bin/env python3
"""Magic-byte scanner and carver for an arbitrary blob.

Streams the input in overlapping chunks, matches a table of 55+ file signatures,
works out a real length per hit (footer search, format-specific parser, or a cap),
de-duplicates nested hits, writes each carve out, sanity-checks it and hashes it.
Pure stdlib - it is meant to run on a locked-down box with no binwalk.
"""
from __future__ import annotations

import argparse, bz2, gzip, hashlib, io, lzma, math, os, struct, zipfile, zlib
from collections import Counter

CHUNK = 4 << 20
DEFAULT_CAP = 16 << 20
SCAN_CAP = 64 << 20

# ext, magic, anchor (bytes of the file that precede the magic), footer or None
SIGS: list[tuple[str, bytes, int, bytes | None]] = [
    ("png", b"\x89PNG\r\n\x1a\n", 0, b"IEND\xaeB`\x82"),
    ("jpg", b"\xff\xd8\xff", 0, b"\xff\xd9"),
    ("gif", b"GIF87a", 0, b"\x00\x3b"), ("gif", b"GIF89a", 0, b"\x00\x3b"),
    ("bmp", b"BM", 0, None), ("tiff", b"II*\x00", 0, None), ("tiff", b"MM\x00*", 0, None),
    ("riff", b"RIFF", 0, None), ("ico", b"\x00\x00\x01\x00", 0, None),
    ("psd", b"8BPS", 0, None), ("pdf", b"%PDF-", 0, b"%%EOF"),
    ("ole2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, None),
    ("zip", b"PK\x03\x04", 0, None), ("rar4", b"Rar!\x1a\x07\x00", 0, None),
    ("rar5", b"Rar!\x1a\x07\x01\x00", 0, None), ("7z", b"7z\xbc\xaf\x27\x1c", 0, None),
    ("gz", b"\x1f\x8b\x08", 0, None), ("bz2", b"BZh", 0, None),
    ("xz", b"\xfd7zXZ\x00", 0, None), ("zst", b"\x28\xb5\x2f\xfd", 0, None),
    ("tar", b"ustar", 257, None), ("cab", b"MSCF", 0, None),
    ("elf", b"\x7fELF", 0, None), ("exe", b"MZ", 0, None),
    ("macho32", b"\xce\xfa\xed\xfe", 0, None), ("macho64", b"\xcf\xfa\xed\xfe", 0, None),
    ("macho-be", b"\xfe\xed\xfa\xcf", 0, None), ("fat-or-class", b"\xca\xfe\xba\xbe", 0, None),
    ("dex", b"dex\n03", 0, None), ("wasm", b"\x00asm", 0, None),
    ("sqlite", b"SQLite format 3\x00", 0, None),
    ("pcap", b"\xd4\xc3\xb2\xa1", 0, None), ("pcap", b"\xa1\xb2\xc3\xd4", 0, None),
    ("pcapng", b"\x0a\x0d\x0d\x0a", 0, None), ("lime", b"EMiL", 0, None),
    ("evtx", b"ElfFile\x00", 0, None), ("esedb", b"\xef\xcd\xab\x89", 4, None),
    ("regf", b"regf", 0, None), ("pf", b"SCCA", 4, None), ("pf-mam", b"MAM\x04", 0, None),
    ("lnk", b"L\x00\x00\x00\x01\x14\x02\x00", 0, None), ("bplist", b"bplist00", 0, None),
    ("pem", b"-----BEGIN ", 0, None), ("ssh-key", b"openssh-key-v1\x00", 0, None),
    ("mp3", b"ID3", 0, None), ("flac", b"fLaC", 0, None), ("ogg", b"OggS", 0, None),
    ("mp4", b"ftyp", 4, None), ("mkv", b"\x1a\x45\xdf\xa3", 0, None),
    ("iso", b"CD001", 32769, None), ("vhd", b"conectix", 0, None),
    ("qcow", b"QFI\xfb", 0, None), ("vmdk", b"KDMV", 0, None),
    ("squashfs", b"hsqs", 0, None), ("cpio", b"070701", 0, None), ("deb", b"!<arch>\n", 0, None),
]

class Blob:
    """Random access over a path or an in-memory buffer, without slurping the file."""
    def __init__(self, src) -> None:
        if isinstance(src, (bytes, bytearray)):
            self.data, self.fh, self.size = bytes(src), None, len(src)
        else:
            self.data = None
            self.fh = open(src, "rb")
            self.size = os.fstat(self.fh.fileno()).st_size

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or off >= self.size or n <= 0:
            return b""
        if self.data is not None:
            return self.data[off:off + n]
        self.fh.seek(off)
        return self.fh.read(n)

    def close(self) -> None:
        if self.fh:
            self.fh.close()

# --- per-format length parsers ----------------------------------------------
def png_len(blob: Blob, start: int) -> int | None:
    pos = 8
    while pos < SCAN_CAP:
        head = blob.read(start + pos, 8)
        if len(head) < 8:
            return None
        size, kind = struct.unpack(">I", head[:4])[0], head[4:8]
        pos += 12 + size
        if kind == b"IEND":
            return pos
    return None

def zip_len(blob: Blob, start: int) -> int | None:
    window = blob.read(start, min(SCAN_CAP, blob.size - start))
    idx = window.find(b"PK\x05\x06")
    while idx >= 0:
        if idx + 22 <= len(window):
            return idx + 22 + struct.unpack("<H", window[idx + 20:idx + 22])[0]
        idx = window.find(b"PK\x05\x06", idx + 1)
    return None

def sqlite_len(blob: Blob, start: int) -> int | None:
    head = blob.read(start, 100)
    if len(head) < 100:
        return None
    page_size = struct.unpack(">H", head[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    pages = struct.unpack(">I", head[28:32])[0]
    if page_size & (page_size - 1) or page_size < 512 or not pages:
        return None
    return page_size * pages

def gzip_len(blob: Blob, start: int) -> int | None:
    obj, pos = zlib.decompressobj(31), 0
    while pos < SCAN_CAP:
        chunk = blob.read(start + pos, 1 << 16)
        if not chunk:
            return None
        try:
            obj.decompress(chunk)
        except zlib.error:
            return None
        pos += len(chunk)
        if obj.eof:
            return pos - len(obj.unused_data)
    return None

def elf_len(blob: Blob, start: int) -> int | None:
    head = blob.read(start, 64)
    if len(head) < 64:
        return None
    end = "<" if head[5] == 1 else ">"
    if head[4] == 2:
        shoff = struct.unpack(end + "Q", head[0x28:0x30])[0]
        size, num = struct.unpack(end + "HH", head[0x3A:0x3E])
    else:
        shoff = struct.unpack(end + "I", head[0x20:0x24])[0]
        size, num = struct.unpack(end + "HH", head[0x2E:0x32])
    return (shoff + size * num) or None

def pe_len(blob: Blob, start: int) -> int | None:
    head = blob.read(start, 0x1000)
    if len(head) < 0x40:
        return None
    nt = struct.unpack("<I", head[0x3C:0x40])[0]
    if nt + 24 > len(head) or head[nt:nt + 4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack("<H", head[nt + 6:nt + 8])[0]
    table = nt + 24 + struct.unpack("<H", head[nt + 20:nt + 22])[0]
    end = 0
    for i in range(nsec):
        entry = table + i * 40
        if entry + 24 > len(head):
            break
        raw_size, raw_ptr = struct.unpack("<II", head[entry + 16:entry + 24])
        end = max(end, raw_ptr + raw_size)
    return end or None

def riff_len(blob: Blob, start: int) -> int | None:
    head = blob.read(start, 12)
    return struct.unpack("<I", head[4:8])[0] + 8 if len(head) == 12 else None

def bmp_len(blob: Blob, start: int) -> int | None:
    head = blob.read(start, 14)
    if len(head) < 14:
        return None
    size = struct.unpack("<I", head[2:6])[0]
    return size if 26 <= size <= blob.size - start else None

def mp4_len(blob: Blob, start: int) -> int | None:
    pos = 0
    while pos < SCAN_CAP:
        head = blob.read(start + pos, 16)
        if len(head) < 8:
            break
        size, kind = struct.unpack(">I", head[:4])[0], head[4:8]
        if not all(32 <= c < 127 for c in kind):
            break
        if size == 1:
            if len(head) < 16:
                break
            size = struct.unpack(">Q", head[8:16])[0]
        if size < 8:
            break
        pos += size
    return pos or None

LENGTH = {"png": png_len, "zip": zip_len, "sqlite": sqlite_len, "gz": gzip_len,
          "elf": elf_len, "exe": pe_len, "riff": riff_len, "bmp": bmp_len, "mp4": mp4_len}

def _ok(fn):
    def wrapper(data: bytes) -> bool:
        try:
            return bool(fn(data))
        except Exception:
            return False
    return wrapper

VERIFY = {
    "zip": _ok(lambda d: zipfile.is_zipfile(io.BytesIO(d))),
    "gz": _ok(lambda d: gzip.decompress(d) is not None),
    "bz2": _ok(lambda d: bz2.decompress(d) is not None),
    "xz": _ok(lambda d: lzma.decompress(d) is not None),
    "png": _ok(lambda d: d.endswith(b"IEND\xaeB`\x82")),
    "jpg": _ok(lambda d: d.endswith(b"\xff\xd9")),
    "pdf": _ok(lambda d: b"%%EOF" in d[-4096:]),
    "tar": _ok(lambda d: d[257:262] == b"ustar"),
    "elf": _ok(lambda d: d[:4] == b"\x7fELF" and d[4] in (1, 2)),
    "sqlite": _ok(lambda d: sqlite3_header_ok(d)),
    "riff": _ok(lambda d: len(d) >= struct.unpack("<I", d[4:8])[0] + 8),
}

def sqlite3_header_ok(data: bytes) -> bool:
    page = struct.unpack(">H", data[16:18])[0]
    page = 65536 if page == 1 else page
    return len(data) >= 100 and page >= 512 and not page & (page - 1)

def scan(blob: Blob, sigs) -> list[tuple[int, str]]:
    """Overlapping-chunk magic scan. Returns sorted, de-duplicated (offset, ext)."""
    overlap = max(len(m) for _, m, _, _ in sigs)
    seen, off = set(), 0
    while off < blob.size:
        data = blob.read(off, CHUNK + overlap)
        if not data:
            break
        for ext, magic, anchor, _footer in sigs:
            pos = data.find(magic)
            while pos >= 0:
                start = off + pos - anchor
                if start >= 0:
                    seen.add((start, ext))
                pos = data.find(magic, pos + 1)
        off += CHUNK
    return sorted(seen)

def length_of(blob: Blob, start: int, ext: str, footer: bytes | None) -> tuple[int, str]:
    parser = LENGTH.get(ext)
    if parser:
        got = parser(blob, start)
        if got and 0 < got <= blob.size - start:
            return got, "parsed"
    if footer:
        window = blob.read(start, min(SCAN_CAP, blob.size - start))
        idx = window.find(footer, 1)
        if idx > 0:
            return idx + len(footer), "footer"
    return min(DEFAULT_CAP, blob.size - start), "capped"

def entropy_regions(blob: Blob, block: int = 4096, threshold: float = 7.5):
    regions, run = [], None
    for off in range(0, blob.size, block):
        data = blob.read(off, block)
        if len(data) < block:
            break
        counts = Counter(data)
        ent = -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())
        if ent >= threshold:
            run = (run[0], off + block, max(run[2], ent)) if run else (off, off + block, ent)
        elif run:
            regions.append(run)
            run = None
    if run:
        regions.append(run)
    return regions

def carve(src, outdir: str = "carved", types=None, nested: bool = False,
          min_size: int = 32, max_size: int = 1 << 30, list_only: bool = False,
          quiet: bool = False) -> list[dict]:
    sigs = [s for s in SIGS if not types or s[0] in types]
    footers = {s[0]: s[3] for s in sigs}
    blob = Blob(src)
    results, covered = [], 0
    try:
        for start, ext in scan(blob, sigs):
            if not nested and start < covered:
                continue
            length, how = length_of(blob, start, ext, footers.get(ext))
            if not min_size <= length <= max_size:
                continue
            data = blob.read(start, min(length, SCAN_CAP))
            verified = VERIFY[ext](data) if ext in VERIFY else None
            row = {"offset": start, "length": length, "ext": ext, "how": how,
                   "verified": verified, "sha256": hashlib.sha256(data).hexdigest()}
            if not list_only:
                os.makedirs(outdir, exist_ok=True)
                row["path"] = os.path.join(outdir, f"{start:010d}_{ext}")
                with open(row["path"], "wb") as fh:
                    fh.write(data)
            results.append(row)
            covered = max(covered, start + length)
    finally:
        blob.close()
    if not quiet:
        print(f"{'OFFSET':>12}  {'LENGTH':>10}  {'TYPE':<13} {'HOW':<7} {'OK':<5} SHA256")
        for row in results:
            ok = {True: "yes", False: "NO", None: "-"}[row["verified"]]
            print(f"{row['offset']:>12}  {row['length']:>10}  {row['ext']:<13} "
                  f"{row['how']:<7} {ok:<5} {row['sha256'][:16]}")
        print(f"[+] {len(results)} carves" + ("" if list_only else f" -> {outdir}/"))
    return results

# --- selftest ---------------------------------------------------------------
def tiny_png() -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))

def tiny_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("flag.txt", "flag{carved_from_the_middle}\n")
    return buf.getvalue()

def selftest() -> int:
    pad = b"PAD!" * 64                                  # 256 bytes of inert filler
    png, zp = tiny_png(), tiny_zip()
    gz = gzip.compress(b"the quick brown fox " * 20)
    pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
    parts, blob, offsets = [pad, png, pad, zp, pad, gz, pad, pdf, pad], b"", {}
    names = [None, "png", None, "zip", None, "gz", None, "pdf", None]
    for part, name in zip(parts, names):
        if name:
            offsets[name] = len(blob)
        blob += part
    rows = {r["ext"]: r for r in carve(blob, types=None, list_only=True, quiet=True)}
    for name, raw in (("png", png), ("zip", zp), ("gz", gz), ("pdf", pdf)):
        assert name in rows, f"{name} not carved: {sorted(rows)}"
        assert rows[name]["offset"] == offsets[name], (name, rows[name]["offset"], offsets[name])
        # exact, except that a PDF carve stops at %%EOF and drops the trailing newline
        assert len(raw) - 1 <= rows[name]["length"] <= len(raw), (name, rows[name], len(raw))
        assert rows[name]["verified"] is True, (name, rows[name])
    assert rows["png"]["sha256"] == hashlib.sha256(png).hexdigest()
    assert len(entropy_regions(Blob(b"\x00" * 65536))) == 0
    assert len(entropy_regions(Blob(os.urandom(65536)))) == 1
    print(f"selftest ok: png/zip/gz/pdf carved at {[offsets[k] for k in ('png','zip','gz','pdf')]}"
          f" with exact lengths and all four verified")
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="Scan a blob for file signatures and carve them out.")
    ap.add_argument("blob", nargs="?", help="disk image, memory dump, pcap or unknown file")
    ap.add_argument("--outdir", default="carved", help="where carves are written (default: carved)")
    ap.add_argument("--list-only", action="store_true", help="report hits, write nothing")
    ap.add_argument("--nested", action="store_true", help="also report hits inside another carve")
    ap.add_argument("--types", help="comma list of extensions to look for, e.g. png,zip,pdf")
    ap.add_argument("--min-size", type=int, default=32, help="skip carves smaller than this")
    ap.add_argument("--max-size", type=int, default=1 << 30, help="skip carves larger than this")
    ap.add_argument("--entropy", action="store_true", help="also report high-entropy regions")
    ap.add_argument("--selftest", action="store_true", help="carve a synthetic blob and assert")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.blob:
        ap.error("a blob path is required (or use --selftest)")
    types = set(args.types.split(",")) if args.types else None
    if types:
        unknown = types - {s[0] for s in SIGS}
        if unknown:
            ap.error(f"unknown types: {','.join(sorted(unknown))}")
    carve(args.blob, args.outdir, types, args.nested, args.min_size, args.max_size,
          args.list_only)
    if args.entropy:
        blob = Blob(args.blob)
        print(f"{'START':>12}  {'END':>12}  ENTROPY")
        for begin, end, ent in entropy_regions(blob):
            print(f"{begin:>12}  {end:>12}  {ent:.2f}")
        blob.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Notes

- The `HOW` column is the honest part of the report: `parsed` means a header field gave the
  length, `footer` means an end marker was found, `capped` means neither and the carve is
  `--max-size`/16 MiB of whatever followed. Only `parsed` and `footer` rows are trustworthy.
- `OK` is a cheap per-format check: `zipfile.is_zipfile`, a `gzip`/`bz2`/`lzma` decompress
  trial, PNG/JPEG end markers, `%%EOF` in the PDF tail, `ustar` at +257, the SQLite page-size
  power-of-two. `-` means the format has no cheap check, not that the carve is bad.
- De-duplication is offset-ordered: a hit that starts inside the previous carve is dropped
  unless `--nested`. That is what stops one Mach-O fat binary from hiding everything after it.
- Short magics lie. `ico` (`00 00 01 00`), `bmp` (`BM`), `cpio` and `exe` (`MZ`) fire on
  ordinary binary noise. Filter with `--types` and `--min-size`, and trust the `OK` column.
- `--entropy` reports 4 KiB blocks scoring >= 7.5 bits/byte, merged into runs. A high-entropy
  region with no signature at its start is encrypted, packed, or a headerless compressed blob.

## Extending it

- **New format**: append `(ext, magic, anchor, footer)` to `SIGS`. `anchor` is how many bytes
  of the file precede the magic, so `("tar", b"ustar", 257, None)` carves from `pos - 257`.
- **New length parser**: write `def foo_len(blob, start) -> int | None` using `blob.read`
  (never slurp), and register it in `LENGTH`. It wins over the footer search.
- **Recursive carving**: run the script over its own output directory until no new files
  appear - a ZIP inside a PNG inside a pcap needs three passes, or one pass with `--nested`.
- **Known-file filtering**: feed the report's sha256 column to a hash set to drop known files.

## Troubleshooting

- Hundreds of `ico`/`bmp`/`exe` rows: that is signal-free noise. Re-run with
  `--types png,jpg,zip,pdf,sqlite,gz --min-size 1024`.
- One giant `capped` carve swallows the file: the first hit had no parseable length. Use
  `--nested` to see what is inside it, or `--types` to exclude the greedy format.
- A carved ZIP will not open but `OK` says `yes`: `is_zipfile` only checks the central
  directory. Try `zip -FF broken.zip --out fixed.zip`, or `7z x` which is more forgiving.
- Nothing found at all in a disk image: the data may be in a filesystem the carver never sees
  as a signature. Run `mmls image.dd` and `fls -o <offset> -r image.dd` first.
- The blob is a memory dump: carve it, but prefer `vol3 -f mem.raw windows.dumpfiles` when
  Volatility has a profile for it; carving is the fallback, not the first move.
