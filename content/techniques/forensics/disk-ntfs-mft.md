---
title: "NTFS - $MFT, $LogFile, $UsnJrnl, ADS and Timestomping"
category: forensics
subcategory: ntfs
type: technique
tags: [ntfs, mft, master-file-table, standard-information, logfile, usnjrnl, usn-journal, ads, alternate-data-stream, zone-identifier, mark-of-the-web, timestomp, timestomping, mftecmd, analyzemft, sleuthkit, icat, istat, filetime, dfir]
difficulty: medium
summary: "Read the NTFS master file table by hand: record anatomy, fixups, $SI vs $FN timestamps, alternate data streams, and the USN journal that proves what really happened."
when_to_use:
  - "You have an NTFS image or a bare $MFT file and need a filesystem timeline"
  - "A file's Modified time is before its Created time, or all four times are identical"
  - "The challenge mentions hidden data, ADS, 'the file looks empty', or Zone.Identifier"
  - "Something was deleted and you need to prove it existed"
  - "You must show execution or rename activity and the event logs were cleared"
tools: [sleuthkit, mftecmd, analyzemft, mft_dump, ntfs-3g, streams, bulk-extractor]
related: [disk-image-triage, disk-windows-registry, disk-windows-execution-artifacts]
---

## TL;DR

Everything on an NTFS volume is a file, including the metadata. `$MFT` (inode 0) holds one
1024-byte record per file, each carrying two independent timestamp sets - `$STANDARD_INFORMATION`
(what Explorer shows, trivially forgeable) and `$FILE_NAME` (written by the kernel on
create/rename, much harder to forge). Compare them and timestomping falls out. Pull the MFT with
`icat -o 2048 disk.dd 0 > MFT`, parse it with `MFTECmd`/`analyzeMFT`, and cross-check against
`$UsnJrnl:$J` for the operation log.

## Recognise it

- `fsstat -o 2048 disk.dd` prints `File System Type: NTFS` and `$MFT Starting Cluster`.
- `fls -o 2048 disk.dd` lists `0-128-1 $MFT`, `2-128-1 $LogFile`, `$UsnJrnl` under `$Extend`.
- `xxd -l 4 MFT` shows `FILE` (`46 49 4C 45`). `BAAD` means the fixup check already failed.
- A file whose `$SI` created time is *later* than its `$FN` created time.
- Timestamps with `.0000000` sub-second precision on files that were not copied by an installer.
- `dir /r` shows `file.txt:hidden:$DATA` with a non-zero size while the file itself is 0 bytes.

## Artifact anatomy

### MFT record

Records are **1024 bytes** by default (`fsstat` prints the real value; 4096 exists on some
volumes). Record number == Sleuthkit inode number.

```
offset  size  field
0x00    4     signature: "FILE" (0x454C4946 LE) or "BAAD" if the fixup check failed
0x04    2     offset to the update sequence (fixup) array
0x06    2     number of 2-byte entries in that array (= sectors_per_record + 1)
0x08    8     $LogFile sequence number (LSN) of the last change
0x10    2     sequence number (incremented when the record is reused - deletion detection)
0x12    2     hard link count
0x14    2     offset to the first attribute
0x16    2     flags: 0x01 = in use, 0x02 = directory
0x18    4     used size of this record
0x1C    4     allocated size (1024)
0x20    8     file reference to the base record (0 for a base record)
0x28    2     next attribute id
0x2C    4     this record's MFT record number (on XP+ )
```

**Fixups / update sequence array.** NTFS overwrites the last two bytes of every 512-byte sector in
the record with a check value, and stashes the originals in the fixup array. Before parsing you
must: read the USN (array entry 0), verify the last 2 bytes of each sector equal it, then write
back entries 1..n. Skip this and every attribute that crosses a sector boundary parses as garbage.
The same scheme applies to `$LogFile` pages and INDX buffers.

### Attributes

```
0x00  4  type id
0x04  4  total attribute length
0x08  1  non-resident flag (0 = data is inside the record)
0x09  1  name length in UTF-16 chars
0x0A  2  offset to the name
0x0C  2  flags (0x0001 compressed, 0x4000 encrypted, 0x8000 sparse)
0x0E  2  attribute id
--- resident only ---
0x10  4  content length
0x14  2  content offset
--- non-resident only ---
0x10  8  starting VCN
0x18  8  last VCN
0x20  2  offset to the runlist
0x28  8  allocated size
0x30  8  real size
0x38  8  initialised size
```

| Type | Name | What it holds |
| --- | --- | --- |
| 0x10 | `$STANDARD_INFORMATION` | 4 timestamps, DOS attributes, SID/quota/USN. Always resident. |
| 0x20 | `$ATTRIBUTE_LIST` | Pointers to extension records when attributes outgrow 1024 bytes |
| 0x30 | `$FILE_NAME` | Parent reference + 4 more timestamps + the name. One per namespace. |
| 0x40 | `$OBJECT_ID` | 16-byte GUID; the birth volume/object id survives copies |
| 0x50 | `$SECURITY_DESCRIPTOR` | Legacy; modern volumes point into `$Secure` |
| 0x60 | `$VOLUME_NAME` | Only in record 3 |
| 0x70 | `$VOLUME_INFORMATION` | NTFS version, dirty flag |
| 0x80 | `$DATA` | The content. Unnamed = the file; **named = an ADS**. |
| 0x90 | `$INDEX_ROOT` | Directory B-tree root; small dirs live entirely here |
| 0xA0 | `$INDEX_ALLOCATION` | INDX buffers for large dirs - holds slack copies of `$FN` |
| 0xB0 | `$BITMAP` | Allocation bitmap for the index / for `$MFT` itself |
| 0x100 | `$LOGGED_UTILITY_STREAM` | `$EFS`, and `$TXF_DATA` |

**Resident vs non-resident.** Data <= ~700 bytes lives inside the MFT record itself. That means
small deleted files can be fully recovered from `$MFT` alone even after the clusters are reused.
Larger data is a **runlist**: a packed sequence of `(length, offset)` pairs where the first nibble
of the header byte is the byte-count of the length field and the second is the byte-count of the
signed, *relative* cluster offset. A run with offset 0 is sparse.

**Sequence numbers.** Incremented each time a record is reused. A file reference is
`(sequence << 48) | record_number`. If a directory index entry's sequence does not match the target
record's, the entry is stale - the file was deleted and the record recycled.

### The fixed system files

| Inode | Name | Use |
| --- | --- | --- |
| 0 | `$MFT` | The table itself |
| 1 | `$MFTMirr` | First 4 records, backup copy |
| 2 | `$LogFile` | Transaction log, ~64 MB, circular |
| 3 | `$Volume` | Volume name, NTFS version, dirty bit |
| 5 | `.` | The root directory |
| 6 | `$Bitmap` | Cluster allocation bitmap |
| 8 | `$BadClus` | Bad cluster list; `$BadClus:$Bad` is a classic hiding spot |
| 9 | `$Secure` | Security descriptors (`$SDS`, `$SDH`, `$SII`) |
| 11 | `$Extend` | Directory holding `$UsnJrnl`, `$Quota`, `$ObjId`, `$Reparse` |

## Workflow

### Extract the metadata files

```sh
# the whole MFT. Inode 0 is always $MFT; -o is the partition START SECTOR
icat -o 2048 disk.dd 0 > MFT
# same for the transaction log
icat -o 2048 disk.dd 2 > LogFile
# find $UsnJrnl and note its inode + attribute ids
fls -o 2048 -p -r disk.dd | grep -i usnjrnl
# the $J stream is sparse and huge; icat with the attribute id from fls
icat -o 2048 disk.dd 60-128-3 > usnjrnl_J
# from a MOUNTED ntfs-3g volume (needs show_sys_files)
cp '/mnt/img/$MFT' ./MFT
cp '/mnt/img/$Extend/$UsnJrnl:$J' ./usnjrnl_J
# full recursive listing with deleted entries marked '*'
fls -o 2048 -r -p disk.dd
# everything about one record: attributes, runlist, all 8 timestamps
istat -o 2048 disk.dd 42
# read a file's data by inode
icat -o 2048 disk.dd 42 > file.bin
```

### Parse it

```sh
# Eric Zimmerman's parser - the reference implementation, CSV or JSON out
MFTECmd.exe -f C:\temp\$MFT --csv C:\temp\out --csvf mft.csv
# include the $FN timestamps and every attribute in the body output
MFTECmd.exe -f $MFT --body C:\temp\out --bodyf mft.body --blf
# cross-platform python parser
analyzeMFT.py -f $MFT -o mft.csv
analyzeMFT.py -f $MFT --bodyfile -o mft.body
# rust parser, fast, JSON lines
mft_dump -o json $MFT > mft.jsonl
mft_dump -o csv $MFT > mft.csv
# sleuthkit straight to a bodyfile, then mactime
fls -o 2048 -m /C -r disk.dd > bodyfile
mactime -b bodyfile -d -z UTC 2024-01-01..2024-12-31 > timeline.csv
# plaso will parse MFT, USN, registry, evtx, prefetch in one pass
log2timeline.py --parsers 'mft,usnjrnl' plaso.db disk.dd
psort.py -o dynamic plaso.db > super_timeline.csv
```

### $LogFile and $UsnJrnl

`$LogFile` is the low-level redo/undo log: it contains the *contents* of changed MFT records and
index entries, so deleted filenames and even small resident file data survive in it. It is circular
and typically only covers hours of activity.

`$UsnJrnl:$J` is the high-level change journal: one variable-length record per change, with the
file reference, parent reference, name, timestamp and a **reason** bitmask. It is sparse - the
leading zeros are a hole, so copy it with a sparse-aware tool or you will get a 100 GB file.

```sh
# parse the change journal
MFTECmd.exe -f 'C:\temp\$J' --csv C:\temp\out
# python parsers
usn.py -f usnjrnl_J -o usn.csv
UsnJrnl2Csv.exe -f $J
# strip the sparse leading zeros before parsing if your tool chokes
python3 -c "import sys;d=open(sys.argv[1],'rb').read();i=d.find(b'\x00\x00\x00\x00\x02\x00\x00\x00');print(i)" usnjrnl_J
# carve $LogFile for deleted filenames the MFT no longer has
strings -a -el LogFile | grep -iE '\.(ps1|bat|exe|zip|docx|txt)$' | sort -u
# LogFileParser / ntfs-log-tracker are the dedicated tools
LogFileParser.exe /LogFile:LogFile /MFT:MFT
```

USN **reason flags** (the ones that matter):

| Flag | Value | Meaning |
| --- | --- | --- |
| `USN_REASON_DATA_OVERWRITE` | 0x00000001 | Existing bytes replaced |
| `USN_REASON_DATA_EXTEND` | 0x00000002 | File grew (a write/download in progress) |
| `USN_REASON_DATA_TRUNCATION` | 0x00000004 | File shrank |
| `USN_REASON_NAMED_DATA_OVERWRITE` | 0x00000010 | ADS content changed |
| `USN_REASON_NAMED_DATA_EXTEND` | 0x00000020 | ADS grew |
| `USN_REASON_FILE_CREATE` | 0x00000100 | File/dir created |
| `USN_REASON_FILE_DELETE` | 0x00000200 | File/dir deleted |
| `USN_REASON_EA_CHANGE` | 0x00000400 | Extended attributes changed |
| `USN_REASON_SECURITY_CHANGE` | 0x00000800 | ACL/owner changed |
| `USN_REASON_RENAME_OLD_NAME` | 0x00001000 | Rename, name before |
| `USN_REASON_RENAME_NEW_NAME` | 0x00002000 | Rename, name after |
| `USN_REASON_INDEXABLE_CHANGE` | 0x00004000 | Indexing attribute flipped |
| `USN_REASON_BASIC_INFO_CHANGE` | 0x00008000 | **Timestamps or attributes changed** |
| `USN_REASON_HARD_LINK_CHANGE` | 0x00010000 | Hard link added/removed |
| `USN_REASON_COMPRESSION_CHANGE` | 0x00020000 | Compression toggled |
| `USN_REASON_ENCRYPTION_CHANGE` | 0x00040000 | EFS toggled |
| `USN_REASON_OBJECT_ID_CHANGE` | 0x00080000 | Object id set |
| `USN_REASON_REPARSE_POINT_CHANGE` | 0x00100000 | Junction/symlink changed |
| `USN_REASON_STREAM_CHANGE` | 0x00200000 | **ADS added or removed** |
| `USN_REASON_CLOSE` | 0x80000000 | Last handle closed - the operation finished |

The classic malware fingerprint in the journal is
`FILE_CREATE` -> `DATA_EXTEND` -> `CLOSE` on `C:\Users\x\AppData\Local\Temp\a.exe`, immediately
followed by `BASIC_INFO_CHANGE` (the timestomp) and then `FILE_DELETE|CLOSE`.

### Alternate data streams

Any file can carry extra named `$DATA` attributes. They are invisible to `dir`, to Explorer, and to
most copy operations (copying to FAT/exFAT/a zip strips them).

```powershell
# Windows: /r lists streams next to each file
dir /r C:\Users\bob\Desktop
# Sysinternals
streams.exe -s C:\Users\bob
# PowerShell, the one worth memorising
Get-Item -Path .\notes.txt -Stream *
Get-Content -Path .\notes.txt -Stream hidden
# find every ADS under a tree, ignoring the benign Zone.Identifier
Get-ChildItem -Recurse -File | ForEach-Object { Get-Item $_.FullName -Stream * } |
  Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
# write one (this is how the flag gets hidden)
Set-Content -Path .\notes.txt -Stream secret -Value 'flag{...}'
```

```sh
# Sleuthkit shows ADS as separate entries "file.txt:hidden"
fls -o 2048 -r -p disk.dd | grep ':'
# the inode syntax is  <record>-<attr type>-<attr id>
# 128 = 0x80 = $DATA; attr id 5 is the named stream, id 1 is usually the main one
icat -o 2048 disk.dd 1234-128-5 > hidden_stream.bin
# istat lists every attribute with its type and id so you know which one to icat
istat -o 2048 disk.dd 1234
# from an ntfs-3g mount with streams_interface=windows
cat '/mnt/img/Users/bob/notes.txt:hidden'
getfattr -n 'user.hidden' /mnt/img/Users/bob/notes.txt
```

**Zone.Identifier / mark-of-the-web.** Anything downloaded by a browser, Outlook or a mail client
gets a `:Zone.Identifier` ADS. It is an INI file:

```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.invalid/page
HostUrl=https://cdn.example.invalid/payload.zip
```

`ZoneId` values: 0 local machine, 1 local intranet, 2 trusted, **3 internet**, 4 restricted.
`HostUrl` is the direct download URL and `ReferrerUrl` the page that linked it - often the entire
answer to "where did this file come from". Grep the whole image for it:

```sh
# every mark-of-the-web on the volume, with the URL
grep -a -r -A3 'ZoneTransfer' /mnt/img/Users/ 2>/dev/null
# or from the raw image
strings -a disk.dd | grep -E '^(HostUrl|ReferrerUrl)='
```

## Timestomping detection

Windows exposes only the four `$SI` timestamps. `SetFileTime()` and every timestomp tool writes
those. `$FN` timestamps are written by the kernel when the *name* is created or moved and there is
no user-mode API to set them, so they usually stay truthful.

Signals, strongest first:

1. **`$SI` earlier than `$FN`.** A file cannot have been created before its name existed. This is
   the single highest-confidence indicator.
2. **Zeroed sub-second fields.** FILETIME has 100-ns resolution. Real file operations produce
   values like `2024-03-11 09:14:22.3417659`. Timestomped ones show `.0000000` because the tool
   took a `time_t` or a "YYYY-MM-DD HH:MM:SS" string. Four identical `.0000000` values on a user
   file is a giveaway.
3. **Dates before the OS install** (compare against `SOFTWARE\Microsoft\Windows NT\CurrentVersion
   \InstallDate`) or in the future.
4. **MFT record number vs creation time.** Records are allocated roughly in order. A high record
   number with a 2009 creation date, sandwiched between records created last week, is stomped.
   Sort by record number and plot creation time - the stomped entry breaks the monotonic trend.
5. **`$UsnJrnl` shows `BASIC_INFO_CHANGE`** on the file shortly after `FILE_CREATE`.
6. **`$SI` modified < `$SI` created** on a file that was never copied.
7. Directory INDX slack holds an older `$FN` copy that disagrees with the live record.

```sh
# istat prints BOTH sets side by side - the quickest manual check
istat -o 2048 disk.dd 42
# MFTECmd emits SI and FN columns; diff them in a spreadsheet or with awk
MFTECmd.exe -f $MFT --csv . --csvf mft.csv
awk -F, 'NR>1 && $0 ~ /0000000/' mft.csv | head
```

## Code

```python
#!/usr/bin/env python3
"""mft_parse.py - a dependency-free $MFT parser.

Walks fixed-size MFT records, applies the update sequence (fixup) array, decodes the
record header, parses $STANDARD_INFORMATION (0x10) and $FILE_NAME (0x30), converts
Windows FILETIME to datetime, prints CSV of the filename plus all 8 timestamps, and
flags records where $SI is older than $FN (classic timestomping).

Usage:
    python3 mft_parse.py [MFT] [record_size]

Defaults to ./MFT and 1024. Get the file with:
    icat -o 2048 disk.dd 0 > MFT
"""
from __future__ import annotations

import csv
import datetime as dt
import struct
import sys

SIG_FILE = b"FILE"
SIG_BAAD = b"BAAD"
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
NAMESPACE = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}


def filetime(raw: int) -> dt.datetime | None:
    """Windows FILETIME (100-ns ticks since 1601-01-01 UTC) -> aware datetime."""
    if raw <= 0 or raw > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=raw // 10)
    except OverflowError:
        return None


def fmt(ts: dt.datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f") if ts else ""


def subsecond_zero(raw: int) -> bool:
    """True when the 100-ns remainder is exactly zero - a timestomp smell."""
    return raw > 0 and raw % 10_000_000 == 0


def apply_fixup(rec: bytearray, sector_size: int = 512) -> bool:
    """Undo the update sequence array in place. Returns False if the record is torn."""
    usa_off, usa_count = struct.unpack_from("<HH", rec, 0x04)
    if usa_count < 1 or usa_off + usa_count * 2 > len(rec):
        return False
    usn = rec[usa_off:usa_off + 2]
    for i in range(1, usa_count):
        sector_end = i * sector_size - 2
        if sector_end + 2 > len(rec):
            return False
        if rec[sector_end:sector_end + 2] != usn:
            return False  # torn write / wrong sector size
        orig = rec[usa_off + i * 2: usa_off + i * 2 + 2]
        rec[sector_end:sector_end + 2] = orig
    return True


def parse_standard_information(buf: bytes) -> dict:
    if len(buf) < 0x30:
        return {}
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, 0)
    flags = struct.unpack_from("<I", buf, 0x20)[0]
    return {
        "si_created_raw": created,
        "si_modified_raw": modified,
        "si_mft_raw": mft_modified,
        "si_accessed_raw": accessed,
        "si_flags": flags,
    }


def parse_file_name(buf: bytes) -> dict:
    if len(buf) < 0x42:
        return {}
    parent_ref = struct.unpack_from("<Q", buf, 0)[0]
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", buf, 0x08)
    alloc_size, real_size, fn_flags = struct.unpack_from("<QQI", buf, 0x28)
    name_len = buf[0x40]
    namespace = buf[0x41]
    name_bytes = buf[0x42:0x42 + name_len * 2]
    try:
        name = name_bytes.decode("utf-16-le", errors="replace")
    except Exception:
        name = ""
    return {
        "parent": parent_ref & 0x0000FFFFFFFFFFFF,
        "parent_seq": parent_ref >> 48,
        "fn_created_raw": created,
        "fn_modified_raw": modified,
        "fn_mft_raw": mft_modified,
        "fn_accessed_raw": accessed,
        "alloc_size": alloc_size,
        "real_size": real_size,
        "fn_flags": fn_flags,
        "name": name,
        "namespace": NAMESPACE.get(namespace, str(namespace)),
    }


def iter_attributes(rec: bytes, first_attr_off: int, used_size: int):
    """Yield (type_id, attr_name, content_bytes, attr_id, non_resident)."""
    off = first_attr_off
    limit = min(used_size, len(rec))
    while off + 4 <= limit:
        (atype,) = struct.unpack_from("<I", rec, off)
        if atype == ATTR_END or atype == 0:
            return
        if off + 16 > limit:
            return
        (alen,) = struct.unpack_from("<I", rec, off + 4)
        if alen < 16 or off + alen > limit:
            return
        non_resident = rec[off + 8]
        name_len = rec[off + 9]
        (name_off,) = struct.unpack_from("<H", rec, off + 0x0A)
        (attr_id,) = struct.unpack_from("<H", rec, off + 0x0E)
        aname = ""
        if name_len:
            raw = rec[off + name_off: off + name_off + name_len * 2]
            aname = raw.decode("utf-16-le", errors="replace")
        content = b""
        if not non_resident:
            (clen,) = struct.unpack_from("<I", rec, off + 0x10)
            (coff,) = struct.unpack_from("<H", rec, off + 0x14)
            start = off + coff
            content = bytes(rec[start:start + clen])
        yield atype, aname, content, attr_id, bool(non_resident)
        off += alen


def parse_record(raw: bytes, index: int, sector_size: int = 512) -> dict | None:
    if len(raw) < 48:
        return None
    sig = bytes(raw[0:4])
    if sig not in (SIG_FILE, SIG_BAAD):
        return None
    rec = bytearray(raw)
    fixed = apply_fixup(rec, sector_size)
    seq, link_count = struct.unpack_from("<HH", rec, 0x10)
    first_attr, flags = struct.unpack_from("<HH", rec, 0x14)
    used_size, alloc_size = struct.unpack_from("<II", rec, 0x18)
    base_ref = struct.unpack_from("<Q", rec, 0x20)[0]
    try:
        (self_num,) = struct.unpack_from("<I", rec, 0x2C)
    except struct.error:
        self_num = index

    out: dict = {
        "record": index,
        "self_record": self_num,
        "signature": sig.decode("ascii", "replace"),
        "fixup_ok": fixed,
        "sequence": seq,
        "links": link_count,
        "in_use": bool(flags & 0x01),
        "is_dir": bool(flags & 0x02),
        "base_record": base_ref & 0x0000FFFFFFFFFFFF,
        "streams": [],
        "name": "",
        "namespace": "",
        "parent": "",
    }
    if sig == SIG_BAAD or not fixed:
        return out
    if first_attr < 0x30 or first_attr >= len(rec):
        return out

    best_fn: dict = {}
    for atype, aname, content, attr_id, non_res in iter_attributes(bytes(rec), first_attr, used_size):
        if atype == ATTR_STANDARD_INFORMATION and content:
            out.update(parse_standard_information(content))
        elif atype == ATTR_FILE_NAME and content:
            fn = parse_file_name(content)
            if not fn:
                continue
            # prefer a Win32 name over the 8.3 DOS name
            if not best_fn or fn["namespace"] != "DOS":
                if not best_fn or best_fn.get("namespace") == "DOS" or fn["namespace"] != "DOS":
                    best_fn = fn
        elif atype == ATTR_DATA and aname:
            out["streams"].append(f"{aname}:$DATA(id={attr_id})")
    if best_fn:
        out.update(best_fn)
    return out


def timestomp_flags(rec: dict) -> list[str]:
    reasons: list[str] = []
    si_c = rec.get("si_created_raw", 0)
    fn_c = rec.get("fn_created_raw", 0)
    si_m = rec.get("si_modified_raw", 0)
    fn_m = rec.get("fn_modified_raw", 0)
    if si_c and fn_c and si_c < fn_c:
        reasons.append("SI_CREATED<FN_CREATED")
    if si_m and fn_m and si_m < fn_m:
        reasons.append("SI_MODIFIED<FN_MODIFIED")
    if si_c and si_m and si_m < si_c:
        reasons.append("MODIFIED<CREATED")
    zeros = sum(1 for k in ("si_created_raw", "si_modified_raw", "si_mft_raw", "si_accessed_raw")
                if subsecond_zero(rec.get(k, 0)))
    if zeros >= 3:
        reasons.append(f"ZERO_SUBSECOND x{zeros}")
    return reasons


COLUMNS = [
    "record", "seq", "in_use", "is_dir", "name", "parent", "namespace", "size",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
    "streams", "suspicious",
]


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "MFT"
    rec_size = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
    writer = csv.writer(sys.stdout)
    writer.writerow(COLUMNS)
    parsed = 0
    stomped = 0
    with open(path, "rb") as fh:
        index = 0
        while True:
            raw = fh.read(rec_size)
            if len(raw) < rec_size:
                break
            rec = parse_record(raw, index, 512)
            index += 1
            if rec is None:
                continue
            parsed += 1
            reasons = timestomp_flags(rec)
            if reasons:
                stomped += 1
            writer.writerow([
                rec["record"], rec["sequence"], int(rec["in_use"]), int(rec["is_dir"]),
                rec.get("name", ""), rec.get("parent", ""), rec.get("namespace", ""),
                rec.get("real_size", ""),
                fmt(filetime(rec.get("si_created_raw", 0))),
                fmt(filetime(rec.get("si_modified_raw", 0))),
                fmt(filetime(rec.get("si_mft_raw", 0))),
                fmt(filetime(rec.get("si_accessed_raw", 0))),
                fmt(filetime(rec.get("fn_created_raw", 0))),
                fmt(filetime(rec.get("fn_modified_raw", 0))),
                fmt(filetime(rec.get("fn_mft_raw", 0))),
                fmt(filetime(rec.get("fn_accessed_raw", 0))),
                ";".join(rec.get("streams", [])),
                ";".join(reasons),
            ])
    print(f"# parsed {parsed} records, {stomped} suspicious", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run it and triage straight away:

```sh
# full CSV
python3 mft_parse.py MFT > mft.csv
# only the timestomped records
python3 mft_parse.py MFT | awk -F, 'NR==1 || $NF != ""'
# only records carrying an alternate data stream
python3 mft_parse.py MFT | awk -F, '$(NF-1) != ""'
# deleted entries (in_use == 0) that still have a name
python3 mft_parse.py MFT | awk -F, 'NR>1 && $3==0 && $5!=""'
```

## Variants & pitfalls

- **Record size is not always 1024.** `fsstat -o 2048 disk.dd | grep -i 'MFT Entry Size'`. Pass it
  as the second argument to the parser above.
- **`$MFT` is fragmented.** `icat` follows the runlist for you; carving `FILE` signatures out of
  the raw image does not preserve order, but it does recover records the live MFT has overwritten.
- **`$ATTRIBUTE_LIST` records** (type 0x20) mean the file's attributes live in other records. The
  parser above will show those extension records with `base_record != 0` and no name.
- **8.3 DOS names.** Every record can hold several `$FILE_NAME` attributes. Prefer the Win32 one;
  the DOS one (`PROGRA~1`) is a different namespace, not a different file.
- **`$FN` is not unforgeable.** Moving a file within the same volume updates `$FN` from `$SI`, so a
  timestomp followed by a rename launders the timestamps. Cross-check `$UsnJrnl` and `$LogFile`.
- **Copying a file** resets `$SI` created to now but keeps modified. Downloading sets both to now.
- **exFAT/FAT** have none of this. Check `fsstat` before you spend 20 minutes looking for `$MFT`.
- **INDX slack**: `INDXParse.py`, or `bulk_extractor` `-x all -e ntfsindx`, recovers `$FN` entries
  for files deleted long ago. Look at `$INDEX_ALLOCATION` of the parent directory.
- **`$BadClus:$Bad`** is a sparse stream the size of the volume. Data hidden there is invisible to
  everything except `icat <inode>-128-<id>`.
- **Compressed and sparse `$DATA`** need the runlist decoder plus LZNT1; use `ntfs-3g` or
  `tsk_recover` rather than doing it yourself.

## Tools

`sleuthkit` (`fls`, `icat`, `istat`, `ifind`, `ffind`, `blkcat`, `tsk_recover`, `mactime`),
`MFTECmd`, `analyzeMFT.py`, `mft_dump` (Rust `mft` crate), `INDXParse.py`, `LogFileParser`,
`NTFS Log Tracker`, `UsnJrnl2Csv`, `plaso`/`log2timeline`, `ntfs-3g`, Sysinternals `streams.exe`,
`AlternateStreamView`, `bulk_extractor`, `Autopsy`.

## References

- Sleuthkit `man istat` documents the `inode-type-id` addressing used for ADS.
- Microsoft's `USN_RECORD_V2`/`USN_RECORD_V3` and `FILE_BASIC_INFORMATION` structure docs define
  the reason flags and the FILETIME semantics used above.
- `MFTECmd.exe --help` lists the CSV/body/JSON switches for your build.
