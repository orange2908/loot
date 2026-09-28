---
title: "Windows Execution Artifacts - Prefetch, ShimCache, LNK, Jump Lists, Recycle Bin"
category: forensics
subcategory: windows-artifacts
type: technique
tags: [prefetch, scca, pecmd, shimcache, appcompatcache, amcache, lnk, lecmd, lnkparse3, jumplist, jlecmd, destlist, recycle-bin, rifiuti2, bam, activitiescache, windows-timeline, sysmon, filetime, dfir]
difficulty: medium
summary: "Prove a program ran and a file was opened: prefetch run counts, ShimCache entries, LNK volume serials, Jump List DestLists and $I Recycle Bin metadata."
when_to_use:
  - "You must prove a binary executed, and when, and how many times"
  - "You need the original path and deletion time of something in the Recycle Bin"
  - "A .lnk file is the only evidence of a removable drive or a deleted file"
  - "Event logs are missing or cleared and you need a second execution source"
  - "The challenge asks which files the user opened, or from which USB"
tools: [pecmd, lecmd, jlecmd, rifiuti2, appcompatcacheparser, amcacheparser, lnkparse3, libscca, exiftool]
related: [disk-windows-registry, disk-ntfs-mft, disk-image-triage]
---

## TL;DR

**Prefetch** proves execution (8 timestamps + a run count). **ShimCache** proves the file existed
(on Win7 only, that it ran). **LNK** carries the target path, size, three timestamps, the volume
serial and a MAC address. **Jump Lists** are per-app MRU lists in an OLE compound file. **$I**
files give the original path and deletion time. `PECmd`, `AppCompatCacheParser`, `LECmd`, `JLECmd`
and `rifiuti-vista` over a mounted image give you a timeline in five minutes.

## Recognise it

- `C:\Windows\Prefetch\*.pf` exists and is non-empty (empty on Server, some SSD Win10 builds).
- `xxd -l 8 X.pf` shows `MAM\x04` (compressed, Win8+) or `SCCA` at offset 4.
- `file x.lnk` says `MS Windows shortcut`; bytes 0-3 are `4C 00 00 00`.
- `$Recycle.Bin\S-1-5-21-...\` holds pairs of `$I<id><ext>` and `$R<id><ext>`.
- `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`.

## Prefetch

Path: `C:\Windows\Prefetch\<UPPERCASE NAME>-<8 hex hash>.pf`. The hash covers the full path (and
for some launch types the command line), so `CMD.EXE-12345678.pf` and `CMD.EXE-ABCDEF12.pf` mean
the same binary ran from two directories. `NTOSBOOT-B00DFAAD.pf` is the boot trace. SCCA header
versions: **17** (0x11) XP/2003, **23** (0x17) Vista/7/2008 - both with a single last-run time;
**26** (0x1A) Win8/8.1/2012 and **30** (0x1E) Win10/11 - eight last-run times, MAM-compressed,
with two sub-variants of 30 (v2 = 1809+).

After decompression: `version` DWORD at 0, `SCCA` at 4, file size at 12, the executable name as 60
UTF-16 chars at 16, the path hash at 76, then a version-dependent file-information section. You
want the **run count**; up to **8 last-run FILETIMEs**; the **referenced file list** (every file
and DLL touched in the first 10 seconds, as `\VOLUME{01d...}\WINDOWS\...`) plus the **directory
strings**; and the **volume creation time and serial number** - a serial that is not the system
volume means it ran off a USB.

```sh
# Eric Zimmerman's parser: CSV plus all 8 run times per file
PECmd.exe -d C:\Windows\Prefetch --csv C:\out --csvf pf.csv
PECmd.exe -f C:\Windows\Prefetch\POWERSHELL.EXE-022B9F3E.pf
# libscca on linux (pip install libscca-python)
python3 -c "import pyscca;f=pyscca.open('CMD.EXE-4A81B364.pf');print(f.executable_filename,f.run_count)"
scca_info CMD.EXE-4A81B364.pf
# pure-python alternative, whole directory to CSV
python3 prefetch.py -d /mnt/img/Windows/Prefetch -c > prefetch.csv
# the MAM header by hand: 'MAM\x04' then a DWORD with the decompressed size
xxd -l 16 CMD.EXE-4A81B364.pf
# referenced paths survive as UTF-16LE strings once decompressed
strings -a -el decompressed.pf | grep -i '\\VOLUME'
# a near-empty directory means prefetch was disabled, not that nothing ran
ls -1 /mnt/img/Windows/Prefetch/*.pf | wc -l
```

MAM compression is Xpress Huffman (`COMPRESSION_FORMAT_XPRESS_HUFF`): `4D 41 4D 04`, a DWORD
decompressed size, then the stream. `PECmd` and recent `libscca` handle it; `RtlDecompressBufferEx`
on Windows or `libmsxpressdecompress` on Linux does it manually. The switch is
`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`
(`EnablePrefetcher`/`EnableSuperfetch`: 0 off, 1 app, 2 boot, 3 both).

**Prefetch proves** this executable name, with this path hash, ran at these times, this many times,
touching these files. **It does not prove** *which* binary (copy a file to a new name and you get a
new `.pf`), and records neither the command line nor the user. A missing `.pf` proves nothing:
prefetch is off by default on Server, may be off on SSDs, holds 128 entries on Win7 / 1024 on
Win8+ (oldest evicted), and anti-forensics tools wipe the directory.

## ShimCache / AppCompatCache

```
SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache    value: AppCompatCache
```

Up to 1024 entries (96 on XP, 512 on Win7-32) of **full path** + the file's **$SI last-modified
time**, plus size and an executed flag on some versions. Written to the registry **only at
shutdown**, so take the hive from the image; entries are **most-recently-inserted first**.

```sh
# Zimmerman's parser; -c selects the control set
AppCompatCacheParser.exe -f C:\hives\SYSTEM --csv C:\out
AppCompatCacheParser.exe -f SYSTEM -c 1 --csv .
# the Mandiant python original; -t sorts by last-modified
python3 ShimCacheParser.py -i SYSTEM -o shimcache.csv
python3 ShimCacheParser.py -i SYSTEM -t
# regripper equivalent
rip.pl -r SYSTEM -p shimcache
# amcache is the better companion - it carries a SHA1
AmcacheParser.exe -f C:\hives\Amcache.hve --csv C:\out
```

**The Win10 caveat.** XP/Vista/7 entries carry an `InsertFlag`/`Execute` bit meaning the file went
through the shim engine, i.e. it ran. Win8+ removed it: an entry means only that **the file existed
and the shell or loader enumerated it** - a directory listing in Explorer is enough. Presence !=
execution; pair it with Amcache (SHA1), prefetch, BAM or Sysmon. The timestamp is the file's mtime,
not a run time, and is trivially timestomped - but the *ordering* is real, so entry N was inserted
before entry N-1 even when every timestamp lies.

## LNK shortcut files

Every double-clicked document leaves a `.lnk` in
`C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\` (also Desktop, Start Menu,
`Office\Recent\`). They survive the target being deleted or the USB removed.

```
0x00  4    HeaderSize = 0x0000004C
0x04  16   LinkCLSID = 00021401-0000-0000-C000-000000000046
0x14  4    LinkFlags        0x18 4 FileAttributes (of the TARGET)
0x1C  8    CreationTime  |  0x24 8 AccessTime  |  0x2C 8 WriteTime  (FILETIME, of the TARGET)
0x34  4    FileSize (low 32 bits)   0x38 4 IconIndex   0x3C 4 ShowCommand
0x40  2    HotKey     0x42 10 Reserved
--- then, in order, each only if its LinkFlag is set ---
      2+   LinkTargetIDList (HasLinkTargetIDList 0x1) - a shell item ID list
      var  LinkInfo (HasLinkInfo 0x2)
      var  NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
      var  ExtraData blocks, terminated by a 4-byte 0
```

LinkFlags worth knowing: `HasLinkTargetIDList 0x1`, `HasLinkInfo 0x2`, `HasName 0x4`,
`HasRelativePath 0x8`, `HasWorkingDir 0x10`, `HasArguments 0x20`, `HasIconLocation 0x40`,
`IsUnicode 0x80`, `ForceNoLinkInfo 0x100`, `RunAsUser 0x2000`, `RunWithShimLayer 0x40000`.

`LinkInfo` gives the **LocalBasePath** (e.g. `E:\tools\mimikatz.exe`) and, in its `VolumeID`, the
**DriveType** (2 removable, 3 fixed, 4 remote, 5 CD-ROM), the **DriveSerialNumber** and the volume
label. DriveType 2 plus a serial you can match in `USBSTOR`/`MountedDevices` ties a file to one USB
stick. The **TrackerDataBlock** (`0xA0000003`, 0x60 bytes) holds distributed link tracking: a
16-byte ASCII **NetBIOS machine name** and two GUIDs. Those are UUID **version 1**, so their last 6
bytes are the **MAC address** of the machine that made the shortcut - direct evidence of where the
file came from. Other blocks: `0xA0000001` EnvironmentVariableData, `0xA0000002` Console,
`0xA0000005` SpecialFolder, `0xA0000006` Darwin (MSI product code), `0xA000000C` VistaAndAboveIDList.

```sh
# liblnk
lnkinfo /mnt/img/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/report.lnk
# Zimmerman: single file or a whole tree to CSV
LECmd.exe -f C:\Users\bob\AppData\Roaming\Microsoft\Windows\Recent\report.lnk
LECmd.exe -d C:\Users --csv C:\out --csvf lnk.csv -q
# python (pip install LnkParse3)
lnkparse report.lnk
# exiftool understands LNK and prints the machine id and target
exiftool report.lnk
# sweep every lnk for removable-drive targets
find /mnt/img/Users -name '*.lnk' -exec lnkinfo {} \; 2>/dev/null | grep -B4 -i 'removable'
```

## Jump Lists

```
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms
%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\<AppID>.customDestinations-ms
```

`AutomaticDestinations` is an **OLE compound file**: each numbered stream is a complete LNK, and a
`DestList` stream is the MRU index. A `DestList` entry carries the entry id, the target's volume
birth/object GUIDs (same MAC-bearing UUIDv1), the **NetBIOS name**, an **access count**, a
**FILETIME** and the path as UTF-16LE. `CustomDestinations` is concatenated LNK structures ending
in a `0xBABFFBAB` footer. The filename is the **AppID**, a 16-hex-char CRC64 of the application
path: `1b4dd67f29cb1962` Explorer, `5f7b5f1e01b83767` Quick Access, `9b9cdc69c1c24e2b` Notepad.
JLECmd ships the table; an unknown AppID for a binary in `\Temp\` is itself a finding.

```sh
# Zimmerman handles both types and dumps the embedded LNKs
JLECmd.exe -d "C:\Users\bob\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\out
JLECmd.exe -f 1b4dd67f29cb1962.automaticDestinations-ms --dumpTo C:\out\lnks
# it is an OLE file, so olefile lists the streams
python3 -c "import olefile,sys;o=olefile.OleFileIO(sys.argv[1]);print(o.listdir())" jl.automaticDestinations-ms
# pull one embedded LNK stream out and parse it as a normal shortcut
python3 -c "import olefile,sys;o=olefile.OleFileIO(sys.argv[1]);open('1.lnk','wb').write(o.openstream('1').read())" jl.automaticDestinations-ms
# the DestList paths, fast
strings -a -el 1b4dd67f29cb1962.automaticDestinations-ms | grep -iE '^[a-z]:\\|^\\\\'
```

## Recycle Bin

Vista+: `C:\$Recycle.Bin\<SID>\`. Each deleted item becomes two files sharing a random 6-character
id - `$I<id><ext>` (metadata) and `$R<id><ext>` (the content).

```
0x00  8   version: 1 = Vista/7/8 (fixed 260-char path), 2 = Windows 10+ (length-prefixed)
0x08  8   original file size in bytes
0x10  8   deletion time (FILETIME, UTC)
--- v1 ---  0x18  520  original full path, UTF-16LE, NUL-padded to 260 chars. File = 544 bytes.
--- v2 ---  0x18    4  path length in UTF-16 CHARACTERS (incl. terminating NUL)
            0x1C  var  original full path, UTF-16LE
```

XP/2003 instead used one `C:\RECYCLER\<SID>\INFO2` database of 800-byte records (ASCII path,
Unicode path, record index, drive number, delete FILETIME, size), content as `D<drive><n>.<ext>`.

```sh
# rifiuti-vista handles the $I format
rifiuti-vista -f ',' '/mnt/img/$Recycle.Bin/S-1-5-21-1111111111-2222222222-3333333333-1001' > recycle.csv
# the XP INFO2 format needs the other binary from the same project
rifiuti -f ',' /mnt/img/RECYCLER/S-1-5-21-.../INFO2
# Zimmerman equivalent
RBCmd.exe -d "C:\$Recycle.Bin" --csv C:\out
# map the SID back to a username
rip.pl -r SOFTWARE -p profilelist
# $R<id> IS the file: copy it out and rename
cp '/mnt/img/$Recycle.Bin/S-1-5-21-.../$RXYZ123.zip' ./recovered.zip
```

## Also worth grabbing

- **BAM / DAM** - `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (and `dam\`).
  Value name is an executable's NT path, data is an 8-byte FILETIME of its **last execution**, per
  user. About a week of history, but it ties execution to a SID, which prefetch does not.
  `rip.pl -r SYSTEM -p bam`.
- **Windows Timeline** - `%LOCALAPPDATA%\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`
  (SQLite, Win10 1803-2004). `Activity` holds `AppId` (JSON array of app paths), `Payload` (JSON
  with displayed text and target file), `StartTime`, `EndTime`, `LastModifiedTime`.
  `WxTCmd.exe -f ActivitiesCache.db --csv .` or `sqlite3 ActivitiesCache.db 'select * from Activity;'`.
- **Sysmon** - `Microsoft-Windows-Sysmon/Operational.evtx`. Event 1 has the full command line,
  parent, SHA256 and user; cross-check every prefetch/ShimCache hit against it.
- **UserAssist, Amcache, SRUM** (registry file) and **`$LogFile`/`$UsnJrnl`** (NTFS file) are the
  other half of this picture.

## Code

### (a) `$I` Recycle Bin metadata parser (v1 and v2)

```python
#!/usr/bin/env python3
"""recycle_i.py - parse Windows $I Recycle Bin metadata (version 1 and version 2).

v1 (Vista/7/8): 544 bytes, fixed 260-char UTF-16LE path at 0x18.
v2 (Windows 10+): 4-byte character count at 0x18, then the path.

Usage: python3 recycle_i.py '<$Recycle.Bin/SID dir or one $I file>'
"""
from __future__ import annotations
import datetime as dt
import os
import struct
import sys

EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


def filetime(raw: int) -> dt.datetime | None:
    """100-ns ticks since 1601-01-01 UTC -> aware datetime."""
    if raw <= 0 or raw > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH + dt.timedelta(microseconds=raw // 10)
    except OverflowError:
        return None


def parse_i(data: bytes) -> dict:
    """Decode a $I blob; raises ValueError on anything that is not one."""
    if len(data) < 0x18:
        raise ValueError(f"too short: {len(data)} bytes")
    version, size, deleted = struct.unpack_from("<QQQ", data, 0)
    if version == 1:                              # fixed 260-char path
        raw = data[0x18:0x18 + 520]
    elif version == 2:                            # length-prefixed path
        if len(data) < 0x1C:
            raise ValueError("v2 header truncated")
        (chars,) = struct.unpack_from("<I", data, 0x18)
        if not 0 < chars <= 0x8000:
            raise ValueError(f"implausible path length {chars}")
        raw = data[0x1C:0x1C + chars * 2]
    else:
        raise ValueError(f"unknown $I version {version}")
    return {"version": version, "size": size, "deleted": filetime(deleted),
            "path": raw.decode("utf-16-le", "replace").split("\x00", 1)[0]}


def r_partner(p: str) -> str:
    """The $R file holding the content sits beside the $I with the same id."""
    d, n = os.path.split(p)
    return os.path.join(d, "$R" + n[2:]) if n.startswith("$I") else ""


def collect(target: str) -> list[str]:
    if os.path.isfile(target):
        return [target]
    return sorted(os.path.join(r, f) for r, _d, fs in os.walk(target)
                  for f in fs if f.startswith("$I"))


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    print("deleted_utc,size,version,original_path,i_file,r_file")
    for p in collect(sys.argv[1]):
        try:
            with open(p, "rb") as fh:
                rec = parse_i(fh.read())
        except (OSError, ValueError) as exc:
            print(f"[!] {p}: {exc}", file=sys.stderr)
            continue
        when = rec["deleted"].strftime("%Y-%m-%d %H:%M:%S") if rec["deleted"] else ""
        print(f'{when},{rec["size"]},{rec["version"]},"{rec["path"]}",{p},{r_partner(p)}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### (b) LNK parser

```python
#!/usr/bin/env python3
"""lnk_parse.py - a dependency-free .lnk parser.

Prints the decoded LinkFlags, the three target FILETIMEs, the LinkInfo local base
path, the volume serial number / drive type, the string data, and the tracker
block's NetBIOS name plus the MAC address inside its UUIDv1 droid GUIDs.

Usage: python3 lnk_parse.py file.lnk [more.lnk ...]
"""
from __future__ import annotations
import datetime as dt
import struct
import sys
import uuid

EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
LNK_CLSID = uuid.UUID("00021401-0000-0000-C000-000000000046")
LINK_FLAGS = [
    (0x1, "HasLinkTargetIDList"), (0x2, "HasLinkInfo"), (0x4, "HasName"),
    (0x8, "HasRelativePath"), (0x10, "HasWorkingDir"), (0x20, "HasArguments"),
    (0x40, "HasIconLocation"), (0x80, "IsUnicode"), (0x100, "ForceNoLinkInfo"),
    (0x200, "HasExpString"), (0x400, "RunInSeparateProcess"), (0x1000, "HasDarwinID"),
    (0x2000, "RunAsUser"), (0x4000, "HasExpIcon"), (0x8000, "NoPidlAlias"),
    (0x20000, "RunWithShimLayer"), (0x40000, "ForceNoLinkTrack"),
]
DRIVE_TYPE = {0: "UNKNOWN", 1: "NO_ROOT_DIR", 2: "REMOVABLE", 3: "FIXED",
              4: "REMOTE", 5: "CDROM", 6: "RAMDISK"}
STRINGS = [(0x4, "name_string"), (0x8, "relative_path"), (0x10, "working_dir"),
           (0x20, "command_line_arguments"), (0x40, "icon_location")]


def filetime(raw: int) -> dt.datetime | None:
    if raw <= 0 or raw > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH + dt.timedelta(microseconds=raw // 10)
    except OverflowError:
        return None


def cstring(data: bytes, off: int, wide: bool) -> str:
    if wide:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[off:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", off)
    return data[off:end if end >= 0 else len(data)].decode("cp1252", "replace")


def parse_link_info(data: bytes, off: int) -> dict:
    """Volume id (serial, drive type, label) plus the local base path."""
    out: dict = {}
    if off + 4 > len(data):
        return out
    (size,) = struct.unpack_from("<I", data, off)
    if size < 0x1C or off + size > len(data):
        return out
    blob = data[off:off + size]
    hdr, flags, vol_off, lbp_off, _net, cps_off = struct.unpack_from("<IIIIII", blob, 4)
    out["_size"] = size
    if flags & 0x1 and 0 < vol_off < len(blob):
        _vs, dtype, serial, label_off = struct.unpack_from("<IIII", blob, vol_off)
        out["drive_type"] = DRIVE_TYPE.get(dtype, str(dtype))
        out["volume_serial"] = f"{serial:08X}"
        if label_off == 0x14 and vol_off + 0x14 <= len(blob):
            (label_u,) = struct.unpack_from("<I", blob, vol_off + 0x10)
            out["volume_label"] = cstring(blob, vol_off + label_u, True)
        elif label_off:
            out["volume_label"] = cstring(blob, vol_off + label_off, False)
    if lbp_off:
        out["local_base_path"] = cstring(blob, lbp_off, False)
    if hdr >= 0x24:                               # unicode variants override
        lbp_u, cps_u = struct.unpack_from("<II", blob, 0x1C)
        if lbp_u:
            out["local_base_path"] = cstring(blob, lbp_u, True)
        if cps_u:
            out["common_path_suffix"] = cstring(blob, cps_u, True)
    elif cps_off:
        out["common_path_suffix"] = cstring(blob, cps_off, False)
    return out


def parse_extra(data: bytes, off: int) -> dict:
    """Walk the ExtraData chain; decode the TrackerDataBlock (0xA0000003)."""
    out: dict = {}
    while off + 8 <= len(data):
        block_size, sig = struct.unpack_from("<II", data, off)
        if block_size < 4:
            break
        if sig == 0xA0000003 and off + 0x40 <= len(data):
            out["machine_id"] = data[off + 16:off + 32].split(b"\x00", 1)[0].decode("cp1252", "replace")
            for label, start in (("droid_volume", off + 32), ("droid_file", off + 48)):
                g = uuid.UUID(bytes_le=bytes(data[start:start + 16]))
                out[label] = str(g)
                if g.version == 1:                # UUIDv1 node == MAC address
                    out[label + "_mac"] = ":".join(
                        f"{(g.node >> s) & 0xFF:02X}" for s in (40, 32, 24, 16, 8, 0))
        off += block_size
    return out


def parse_lnk(data: bytes) -> dict:
    if len(data) < 0x4C:
        raise ValueError("shorter than a LNK header")
    (hdr_size,) = struct.unpack_from("<I", data, 0)
    if hdr_size != 0x4C:
        raise ValueError(f"bad HeaderSize 0x{hdr_size:X} (expected 0x4C)")
    clsid = uuid.UUID(bytes_le=bytes(data[4:20]))
    if clsid != LNK_CLSID:
        raise ValueError(f"bad LinkCLSID {clsid}")
    flags, attrs = struct.unpack_from("<II", data, 0x14)
    ctime, atime, wtime = struct.unpack_from("<QQQ", data, 0x1C)
    size, icon, show = struct.unpack_from("<III", data, 0x34)
    out: dict = {
        "link_flags": flags,
        "link_flags_decoded": [n for bit, n in LINK_FLAGS if flags & bit],
        "file_attributes": f"0x{attrs:08X}", "target_created": filetime(ctime),
        "target_accessed": filetime(atime), "target_written": filetime(wtime),
        "target_size": size, "icon_index": icon, "show_command": show,
    }
    off = 0x4C
    if flags & 0x1 and off + 2 <= len(data):      # skip the shell item ID list
        (idlist,) = struct.unpack_from("<H", data, off)
        out["idlist_size"] = idlist
        off += 2 + idlist
    if flags & 0x2 and not flags & 0x100:         # ForceNoLinkInfo wins
        info = parse_link_info(data, off)
        off += info.pop("_size", 0)
        out.update(info)
    wide = bool(flags & 0x80)
    for bit, name in STRINGS:
        if not flags & bit or off + 2 > len(data):
            continue
        (count,) = struct.unpack_from("<H", data, off)
        off += 2
        nbytes = count * 2 if wide else count
        out[name] = data[off:off + nbytes].decode("utf-16-le" if wide else "cp1252", "replace")
        off += nbytes
    out.update(parse_extra(data, off))
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    for path in sys.argv[1:]:
        try:
            with open(path, "rb") as fh:
                rec = parse_lnk(fh.read())
        except (OSError, ValueError) as exc:
            print(f"[!] {path}: {exc}", file=sys.stderr)
            continue
        print(f"== {path} ==")
        print(f"  LinkFlags      : 0x{rec['link_flags']:08X} "
              f"{' | '.join(rec['link_flags_decoded'])}")
        print(f"  Target created : {rec['target_created']}")
        print(f"  Target written : {rec['target_written']}")
        print(f"  Target accessed: {rec['target_accessed']}")
        print(f"  Target size    : {rec['target_size']}")
        for key in ("local_base_path", "common_path_suffix", "relative_path", "working_dir",
                    "command_line_arguments", "name_string", "drive_type", "volume_serial",
                    "volume_label", "machine_id", "droid_file", "droid_file_mac"):
            if rec.get(key):
                print(f"  {key:16s}: {rec[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Prefetch absence is not evidence of absence.** Check `EnablePrefetcher`, the file count and
  whether the box is Windows Server. Hash collisions happen, and `svchost.exe` produces many `.pf`.
- **ShimCache on Win10 is existence, not execution**, and it is only flushed at shutdown - a box
  that never rebooted has an empty-looking cache in the hive while the data sits in kernel memory,
  so pull it from a RAM dump instead.
- **Amcache's `FileId`** is `0000` + SHA1 of the first 30 MB. Strip the leading zeros.
- **LNK timestamps are the TARGET's**, captured when the shortcut was written; the `.lnk` file's
  own MFT timestamps say when the user opened it. Two independent time sources.
- **`ForceNoLinkInfo` (0x100)** means the LinkInfo block is absent even when `HasLinkInfo` is set;
  the parser above honours it.
- **Jump List `DestList` layout differs** between Win7 and Win10 (entry size 0x70 vs 0x82). Use
  JLECmd rather than hand-rolling it.
- **`$I` v1 files are exactly 544 bytes**; v2 is variable, typically 80-120. A "corrupt" parse
  usually means you assumed the wrong version.
- **Emptying the Recycle Bin** removes both `$I` and `$R`, but the MFT records and `$UsnJrnl`
  entries survive - go back to the NTFS artifacts. `$R` files keep the original extension, so
  `file` and `binwalk` work on them directly.
- **Time zones**: prefetch, LNK, `$I` and BAM store UTC FILETIMEs; shellbag/FAT timestamps are
  local. Read `TimeZoneInformation` before merging them into one timeline.

## Tools

`PECmd`, `AppCompatCacheParser`, `AmcacheParser`, `LECmd`, `JLECmd`, `RBCmd`, `WxTCmd`, `SBECmd`
(Eric Zimmerman); `libscca`/`scca_info`, `liblnk`/`lnkinfo`, `LnkParse3`, `olefile`, `rifiuti2`
(`rifiuti`, `rifiuti-vista`), `ShimCacheParser.py`, `python-evtx`/`evtx_dump`,
`plaso`/`log2timeline`, `exiftool`, `Autopsy`, `KAPE` for collection.

## References

- `[MS-SHLLINK]` specifies the LNK header, LinkInfo, string data and ExtraData blocks used above.
- `libscca` and `liblnk` ship format documentation in their `documentation/` directories.
- `PECmd.exe --help`, `LECmd.exe --help`, `JLECmd.exe --help` for your build's switches.
