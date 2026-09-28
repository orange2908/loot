---
title: "File Signatures Reference - Magic Bytes, Footers, Repair"
category: forensics
subcategory: file-formats
type: reference
tags: [magic-bytes, file-signature, file-header, footer, carving, binwalk, foremost, scalpel, hexedit, file-format, polyglot, corrupted-header, xxd, dfir]
summary: "Header and footer signatures for 130+ formats, plus how to find, carve, repair and detect polyglot files."
tools: [file, binwalk, foremost, scalpel, trid, xxd, hexedit, bgrep, photorec]
related: [forensics-triage-cheatsheet, windows-artifacts-cheatsheet, disk-forensics-cheatsheet]
---

`Offset` is where the header sits. `0` unless noted. ASCII column uses `\xNN` for
non-printables so everything here is copy-pasteable into `printf` and `grep -P`.
Footers are only reliable for formats that actually have one - most do not.

## Images

| Ext | Hex header | ASCII | Offset | Footer | Notes |
|---|---|---|---|---|---|
| png | `89 50 4E 47 0D 0A 1A 0A` | `\x89PNG\r\n\x1a\n` | 0 | `49 45 4E 44 AE 42 60 82` | Footer is the IEND chunk CRC; chunks are len+type+data+crc |
| jpg | `FF D8 FF E0` | `\xff\xd8\xff\xe0` | 0 | `FF D9` | JFIF; `FF D8 FF E1` = Exif, `FF D8 FF DB` = raw, `FF D8 FF EE` = Adobe |
| gif89a | `47 49 46 38 39 61` | `GIF89a` | 0 | `00 3B` | Animated; frames after the trailer are a classic hiding spot |
| bmp | `42 4D` | `BM` | 0 | none | Bytes 2-5 are the little-endian file size |
| tiff | `49 49 2A 00` or `4D 4D 00 2A` | `II*\x00` / `MM\x00*` | 0 | none | II = little-endian, MM = big-endian |
| webp | `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` | `RIFF....WEBP` | 0 | none | RIFF container, size at offset 4 |
| ico | `00 00 01 00` | - | 0 | none | `00 00 02 00` = cur |
| icns | `69 63 6E 73` | `icns` | 0 | none | Big-endian size at offset 4 |
| psd | `38 42 50 53` | `8BPS` | 0 | none | Photoshop; layers often hold the flag |
| svg | `3C 73 76 67` or `3C 3F 78 6D 6C` | `<svg` / `<?xml` | 0 | `</svg>` | Text; `file` may say HTML |
| heic | `?? ?? ?? ?? 66 74 79 70 68 65 69 63` | `....ftypheic` | 4 | none | ISOBMFF brand; also `heix`, `mif1` |
| avif | `?? ?? ?? ?? 66 74 79 70 61 76 69 66` | `....ftypavif` | 4 | none | ISOBMFF brand `avif`/`avis` |
| jp2 | `00 00 00 0C 6A 50 20 20 0D 0A 87 0A` | `\x00\x00\x00\x0cjP  ` | 0 | none | Raw codestream is `FF 4F FF 51` |
| pcx | `0A ?? 01` | - | 0 | none | Byte 1 is the version (0,2,3,4,5) |
| tga | none at 0 | `TRUEVISION-XFILE` | -18 | `TRUEVISION-XFILE\x2e\x00` | Only v2 has the footer; header is unmagic |
| xcf | `67 69 6D 70 20 78 63 66` | `gimp xcf` | 0 | none | GIMP native, layers preserved |
| dds | `44 44 53 20` | `DDS ` | 0 | none | DirectDraw surface |
| cr2 | `49 49 2A 00 10 00 00 00 43 52` | `II*\x00....CR` | 0 | none | Canon raw, TIFF-based |
| nef | `4D 4D 00 2A` | `MM\x00*` | 0 | none | Nikon raw, TIFF-based; check `Make` tag |
| dng | `49 49 2A 00` | `II*\x00` | 0 | none | Adobe DNG, TIFF-based |

## Audio and video

| Ext | Hex header | ASCII | Offset | Footer | Notes |
|---|---|---|---|---|---|
| riff | `52 49 46 46` | `RIFF` | 0 | none | Generic container; type tag at offset 8 |
| wav | `52 49 46 46 ?? ?? ?? ?? 57 41 56 45` | `RIFF....WAVE` | 0 | none | LSB stego lives in the `data` chunk |
| avi | `52 49 46 46 ?? ?? ?? ?? 41 56 49 20` | `RIFF....AVI ` | 0 | none | `idx1` index near the end |
| mp3 | `FF FB` / `FF F3` / `FF F2` | - | 0 | none | Bare MPEG frame sync `FF Ex/Fx` |
| id3 | `49 44 33` | `ID3` | 0 | `54 41 47` (`TAG`) at -128 | ID3v2 header; ID3v1 is the last 128 bytes |
| flac | `66 4C 61 43` | `fLaC` | 0 | none | Metadata blocks follow immediately |
| ogg | `4F 67 67 53` | `OggS` | 0 | none | Page header; codec name in the first page |
| opus | `4F 67 67 53` then `OpusHead` | `OggS` | 0 | none | Look for `OpusHead` at ~0x1C |
| m4a | `?? ?? ?? ?? 66 74 79 70 4D 34 41 20` | `....ftypM4A ` | 4 | none | ISOBMFF |
| mp4 | `?? ?? ?? ?? 66 74 79 70` | `....ftyp` | 4 | none | Brands: `isom`, `mp42`, `dash`, `avc1` |
| mov | `?? ?? ?? ?? 66 74 79 70 71 74 20 20` | `....ftypqt  ` | 4 | none | Also bare `moov`/`mdat` atoms |
| mkv | `1A 45 DF A3` | - | 0 | none | EBML header, shared with webm |
| webm | `1A 45 DF A3` | - | 0 | none | EBML DocType is `webm` |
| asf/wmv/wma | `30 26 B2 75 8E 66 CF 11` | - | 0 | none | ASF GUID header object |
| midi | `4D 54 68 64` | `MThd` | 0 | none | Track chunks are `MTrk` |
| aiff | `46 4F 52 4D ?? ?? ?? ?? 41 49 46 46` | `FORM....AIFF` | 0 | none | IFF container, big-endian |
| 3gp | `?? ?? ?? ?? 66 74 79 70 33 67 70` | `....ftyp3gp` | 4 | none | ISOBMFF brand `3gp4`..`3gp6` |
| flv | `46 4C 56 01` | `FLV\x01` | 0 | none | Byte 4 flags audio/video presence |
| swf | `46 57 53` / `43 57 53` / `5A 57 53` | `FWS` / `CWS` / `ZWS` | 0 | none | CWS = zlib body, ZWS = LZMA body |

## Archives and compression

| Ext | Hex header | ASCII | Offset | Footer | Notes |
|---|---|---|---|---|---|
| zip | `50 4B 03 04` | `PK\x03\x04` | 0 | `50 4B 05 06` + 18 bytes | EOCD `PK\x05\x06`; `PK\x01\x02` = central dir entry |
| rar4 | `52 61 72 21 1A 07 00` | `Rar!\x1a\x07\x00` | 0 | none | RAR 1.5-4.x |
| rar5 | `52 61 72 21 1A 07 01 00` | `Rar!\x1a\x07\x01\x00` | 0 | none | RAR 5.0+ |
| 7z | `37 7A BC AF 27 1C` | `7z\xbc\xaf\x27\x1c` | 0 | none | Header may be at the end (encrypted names) |
| gzip | `1F 8B 08` | `\x1f\x8b\x08` | 0 | none | Last 8 bytes are CRC32 + ISIZE |
| bzip2 | `42 5A 68` | `BZh` | 0 | `17 72 45 38 50 90` | Byte 3 is the block-size digit `1`-`9` |
| xz | `FD 37 7A 58 5A 00` | `\xfd7zXZ\x00` | 0 | `59 5A` (`YZ`) | - |
| lzma | `5D 00 00` | - | 0 | none | Raw alone stream, weak magic |
| zstd | `28 B5 2F FD` | - | 0 | none | Skippable frames are `50 2A 4D 18` |
| lz4 | `04 22 4D 18` | - | 0 | none | Frame format |
| tar | `75 73 74 61 72` | `ustar` | 257 | 1024 zero bytes | Header magic is NOT at offset 0 |
| cab | `4D 53 43 46` | `MSCF` | 0 | none | Microsoft cabinet |
| arj | `60 EA` | - | 0 | none | Very weak magic |
| lzh/lha | `2D 6C 68` | `-lh` | 2 | none | `-lh0-` .. `-lh7-` at offset 2 |
| ar | `21 3C 61 72 63 68 3E 0A` | `!<arch>\n` | 0 | none | Unix archive, also .a and .deb |
| deb | `21 3C 61 72 63 68 3E 0A` + `debian-binary` | `!<arch>\n` | 0 | none | ar with a `debian-binary` member |
| rpm | `ED AB EE DB` | - | 0 | none | Payload is usually cpio+xz |
| cpio-ascii | `30 37 30 37 30` | `07070` | 0 | `TRAILER!!!` | `070701` = newc, `070707` = odc |
| iso9660 | `43 44 30 30 31` | `CD001` | 32769 | none | Also at 0x8801 and 0x9001 for other sector sizes |
| udf | `4E 53 52 30` | `NSR0` | 32769+ | none | `NSR02`/`NSR03` |
| dmg | `6B 6F 6C 79` | `koly` | -512 | `koly` | Trailer, not header |
| squashfs-le | `68 73 71 73` | `hsqs` | 0 | none | `sqsh` = big-endian |
| cramfs | `45 3D CD 28` | - | 0 | none | Also `Compressed ROMFS` string |
| jffs2 | `19 85` / `85 19` | - | 0 | none | Node magic, repeats throughout |
| ubifs | `31 18 10 06` | - | 0 | none | UBI superblock is `55 42 49 23` (`UBI#`) |

## Documents

| Ext | Hex header | ASCII | Offset | Footer | Notes |
|---|---|---|---|---|---|
| pdf | `25 50 44 46 2D` | `%PDF-` | 0 | `25 25 45 4F 46` (`%%EOF`) | Multiple `%%EOF` = incremental updates = deleted content |
| ole2 | `D0 CF 11 E0 A1 B1 1A E1` | - | 0 | none | doc, xls, ppt, msg, msi; CFBF compound file |
| ooxml | `50 4B 03 04` | `PK\x03\x04` | 0 | EOCD | docx/xlsx/pptx; `[Content_Types].xml` is the first entry |
| rtf | `7B 5C 72 74 66 31` | `{\rtf1` | 0 | `7D` (`}`) | `\objdata` hex blobs hide OLE payloads |
| ps | `25 21 50 53` | `%!PS` | 0 | none | PostScript |
| eps | `C5 D0 D3 C6` or `%!PS-Adobe` | - | 0 | none | Binary EPS has the DOS preview header |
| djvu | `41 54 26 54 46 4F 52 4D` | `AT&TFORM` | 0 | none | Then `DJVU` or `DJVM` at offset 12 |
| epub | `50 4B 03 04` + `mimetype` | `PK\x03\x04` | 0 | EOCD | First entry is stored `mimetype` = `application/epub+zip` |
| mobi | `42 4F 4F 4B 4D 4F 42 49` | `BOOKMOBI` | 60 | none | PalmDOC container |
| chm | `49 54 53 46` | `ITSF` | 0 | none | Compiled HTML help |
| one | `E4 52 5C 7B 8C D8 A7 4D` | - | 0 | none | OneNote section, GUID header |

## Executables and binaries

| Ext | Hex header | ASCII | Offset | Footer | Notes |
|---|---|---|---|---|---|
| elf | `7F 45 4C 46` | `\x7fELF` | 0 | none | Byte 4: 1=32bit 2=64bit; byte 5: 1=LE 2=BE |
| pe/exe | `4D 5A` | `MZ` | 0 | none | `PE\x00\x00` at the offset stored in the LE dword at 0x3C |
| macho-32 | `FE ED FA CE` | - | 0 | none | Big-endian order; `CE FA ED FE` is LE 32-bit |
| macho-64 | `FE ED FA CF` | - | 0 | none | `CF FA ED FE` is the common LE 64-bit form |
| fat-macho | `CA FE BA BE` | - | 0 | none | Universal binary; collides with Java class magic |
| class | `CA FE BA BE` | - | 0 | none | Java; next 4 bytes are minor+major version |
| dex | `64 65 78 0A 30 33 35 00` | `dex\n035\x00` | 0 | none | Android Dalvik, version varies (035/037/038/039) |
| odex | `64 65 79 0A` | `dey\n` | 0 | none | Optimized dex |
| wasm | `00 61 73 6D 01 00 00 00` | `\x00asm` | 0 | none | Version 1 |
| pyc | `?? ?? 0D 0A` | - | 0 | none | 2-byte magic + `\r\n`; 3.7+ adds flags+size, body at 16 |
| lua | `1B 4C 75 61` | `\x1bLua` | 0 | none | Byte 4 is version: `51`, `52`, `53`, `54` |
| dotnet-il | `4D 5A` + `BSJB` | `MZ` / `BSJB` | 0 / varies | none | `BSJB` marks the CLI metadata root |
| com | none | - | - | none | Raw 16-bit code, no magic; identify by context |
| sys/efi | `4D 5A` | `MZ` | 0 | none | PE subsystem field distinguishes driver/EFI |

## Filesystems and disk images

| Ext | Hex header | ASCII | Offset | Notes |
|---|---|---|---|---|
| mbr | `55 AA` | - | 510 | Partition table entries at 446, 16 bytes each |
| gpt | `45 46 49 20 50 41 52 54` | `EFI PART` | 512 | LBA1; protective MBR at LBA0 |
| ntfs | `EB 52 90 4E 54 46 53 20 20 20 20` | `.R.NTFS    ` | 0 | OEM ID `NTFS    ` at offset 3 |
| fat32 | `EB 58 90` + `FAT32   ` | - | 0 / 82 | FSInfo sector magic `52 52 61 41` |
| exfat | `EB 76 90 45 58 46 41 54 20 20 20` | `.v.EXFAT   ` | 0 | - |
| ext2/3/4 | `53 EF` | - | 1080 | Superblock magic at 0x438 |
| hfs+ | `48 2B` | `H+` | 1024 | `HX` = HFSX |
| apfs | `4E 58 53 42` | `NXSB` | 32 | Container superblock; `APSB` for volumes |
| xfs | `58 46 53 42` | `XFSB` | 0 | - |
| btrfs | `5F 42 48 52 66 53 5F 4D` | `_BHRfS_M` | 65600 | 0x10040 |
| vmdk | `4B 44 4D 56` | `KDMV` | 0 | Sparse extent; descriptor-only files start `# Disk` |
| vdi | `3C 3C 3C 20` + `Oracle VM VirtualBox` | `<<< ` | 0 | Magic dword `7F 10 DA BE` at 0x40 |
| vhd | `63 6F 6E 65 63 74 69 78` | `conectix` | 0 or -512 | Fixed VHD has the footer only |
| vhdx | `76 68 64 78 66 69 6C 65` | `vhdxfile` | 0 | - |
| qcow2 | `51 46 49 FB` | `QFI\xfb` | 0 | Version dword at offset 4 |
| e01 | `45 56 46 09 0D 0A FF 00` | `EVF\x09\r\n\xff\x00` | 0 | EnCase; `LVF` for logical, `EVF2` for Ex01 |
| lime | `45 4D 69 4C` | `EMiL` | 0 | LiME memory dump header, little-endian |
| crashdump | `50 41 47 45 44 55 4D 50` | `PAGEDUMP` | 0 | `PAGEDU64` for x64; Windows kernel dump |

## Databases

| Ext | Hex header | ASCII | Offset | Notes |
|---|---|---|---|---|
| sqlite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | `SQLite format 3\x00` | 0 | Page size at 16; WAL file is `37 7F 06 82` |
| dbf | `03` / `04` / `05` / `30` | - | 0 | dBase; byte 0 is the version |
| mdb | `00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74` | `..\x00\x00Standard Jet` | 0 | Access 97-2003 |
| accdb | `00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45` | `..\x00\x00Standard ACE` | 0 | Access 2007+ |
| leveldb-ldb | `57 FB 80 8B 24 75 47 DB` | - | -8 | Table magic is a FOOTER; `.log` files have none |
| esedb | `EF CD AB 89` | - | 4 | `edb`, `SRUDB.dat`, `WebCacheV01.dat`, `Windows.edb` |
| pst | `21 42 44 4E` | `!BDN` | 0 | Also ost; version word at 0x0A |
| msf | `2F 2F 20 3C 21 2D 2D 20 3C 6D 64 62 3A` | `// <!-- <mdb:` | 0 | Thunderbird Mork index |
| berkeley-db | `00 05 31 62` / `62 31 05 00` | - | 12 | Btree magic `0x00053162` at offset 12 |

## Keys, certificates, crypto containers

| Ext | Hex header | ASCII | Offset | Notes |
|---|---|---|---|---|
| pem | `2D 2D 2D 2D 2D 42 45 47 49 4E` | `-----BEGIN` | 0 | Base64 body; label tells you the type |
| der | `30 82` | - | 0 | ASN.1 SEQUENCE, 2-byte length |
| pgp-pub | `99 01` / `98 8D` or `-----BEGIN PGP` | - | 0 | Binary packet tag or armored text |
| openssh-priv | `2D 2D 2D 2D 2D 42 45 47 49 4E 20 4F 50 45 4E 53 53 48` | `-----BEGIN OPENSSH` | 0 | Body decodes to `openssh-key-v1\x00` |
| putty-ppk | `50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79` | `PuTTY-User-Key` | 0 | Text format, MAC at the end |
| pkcs12 | `30 82` | - | 0 | DER; distinguish by parsing, not magic |
| jks | `FE ED FE ED` | - | 0 | Java keystore; `CE CH EC OD` `CE CE CE CE` = JCEKS |

## Network captures

| Ext | Hex header | ASCII | Offset | Notes |
|---|---|---|---|---|
| pcap-le | `D4 C3 B2 A1` | - | 0 | Microsecond resolution, little-endian |
| pcapng | `0A 0D 0D 0A` | - | 0 | Section Header Block; byte-order magic `1A 2B 3C 4D` at 8 |
| snoop | `73 6E 6F 6F 70 00 00 00` | `snoop\x00\x00\x00` | 0 | Solaris capture format |
| etl | `?? ?? ?? ?? 00 00 00 00 ...` | - | 0 | Windows ETW; identify with `tracerpt` / `etl2pcapng` |

## Misc and text-ish

| Ext | Hex header | ASCII | Offset | Notes |
|---|---|---|---|---|
| bplist | `62 70 6C 69 73 74 30 30` | `bplist00` | 0 | Binary plist; trailer holds the offset table |
| plist-xml | `3C 3F 78 6D 6C` + `<!DOCTYPE plist` | `<?xml` | 0 | - |
| cbor | `A1`..`BF` / `D9 D9 F7` | - | 0 | Self-describe tag is `D9 D9 F7` |
| msgpack | `82`..`8F` / `DE` / `DF` | - | 0 | Map headers; no strong magic |
| protobuf | none | - | - | Field 1 varint often makes byte 0 `08`; no magic |
| gimp-brush | `47 49 4D 50` | `GIMP` | 20 | GBR brush |
| torrent | `64 38 3A 61 6E 6E 6F 75 6E 63 65` | `d8:announce` | 0 | Bencoded dict |
| shebang | `23 21` | `#!` | 0 | Interpreter path follows to the first newline |
| utf8-bom | `EF BB BF` | - | 0 | Strip before parsing or JSON/XML loaders choke |
| utf16le-bom | `FF FE` | - | 0 | PowerShell/Windows exports; use `strings -el` |

## Identify

```bash
# First question always: what does libmagic think it is
file suspicious.bin
# Keep going past the first match - reveals appended or embedded data
file -k suspicious.bin
# Just the MIME type, for scripts and loops
file --mime-type -b suspicious.bin
# TrID scores thousands of signatures and beats file on ambiguous blobs
trid suspicious.bin
# The first 32 bytes identify almost any format by eye
xxd -l 32 suspicious.bin
# The LAST 32 bytes - footers, koly trailers, ID3v1 tags, leveldb magic
xxd -s -32 suspicious.bin
# binwalk scans for every known signature at every offset, not just offset 0
binwalk suspicious.bin
# Extract everything binwalk recognised into _suspicious.bin.extracted/
binwalk -e suspicious.bin
```

## Find every occurrence of a signature

```bash
# Byte offsets of every PNG header; -a treats binary as text, -b prints offsets
grep -aob $'\x89PNG\r\n\x1a\n' blob.bin
# Every ZIP local-file header, which is how you spot appended archives
grep -aob $'PK\x03\x04' blob.bin
# binwalk --raw searches for an arbitrary byte string at any offset
binwalk --raw='\x1f\x8b\x08' blob.bin
# bgrep is purpose-built for hex-pattern searching in binaries
bgrep 89504e470d0a1a0a blob.bin
```

```python
#!/usr/bin/env python3
"""Scan a file for known magic signatures at every offset.

Usage: python3 sigscan.py [file]   (default: blob.bin)
"""
import sys

SIGS: dict[str, bytes] = {
    "png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "gif": b"GIF8",
    "zip": b"PK\x03\x04", "zip_eocd": b"PK\x05\x06", "rar5": b"Rar!\x1a\x07\x01\x00",
    "7z": b"7z\xbc\xaf\x27\x1c", "gzip": b"\x1f\x8b\x08", "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00", "zstd": b"\x28\xb5\x2f\xfd", "pdf": b"%PDF-",
    "ole2": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "elf": b"\x7fELF",
    "sqlite": b"SQLite format 3\x00", "pcap_le": b"\xd4\xc3\xb2\xa1",
    "pcapng": b"\x0a\x0d\x0d\x0a", "bplist": b"bplist00", "regf": b"regf",
    "evtx": b"ElfFile\x00", "cab": b"MSCF", "flac": b"fLaC", "ogg": b"OggS",
    "matroska": b"\x1a\x45\xdf\xa3", "wasm": b"\x00asm",
}


def scan(data: bytes, min_offset: int = 0) -> list[tuple[int, str]]:
    """Return [(offset, name)] for every signature occurrence, sorted."""
    hits: list[tuple[int, str]] = []
    for name, sig in SIGS.items():
        start = min_offset
        while (idx := data.find(sig, start)) >= 0:
            hits.append((idx, name))
            start = idx + 1
    hits.sort()
    return hits


def main(path: str) -> int:
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        print(f"[!] cannot read {path}: {exc}", file=sys.stderr)
        return 1
    for off, name in scan(data):
        print(f"0x{off:08x}  {name:16s}  {data[off:off + 16].hex(' ')}")
    return 0


if __name__ == "__main__":
    demo = b"A" * 32 + b"\x89PNG\r\n\x1a\n" + b"B" * 16 + b"PK\x03\x04" + b"C" * 8
    assert scan(demo)[0] == (32, "png"), scan(demo)
    assert {n for _, n in scan(demo)} >= {"png", "zip"}
    sys.exit(main(sys.argv[1]) if len(sys.argv) > 1 else 0)
```

## Fix a corrupted header

```bash
# Confirm the damage: compare bytes 0..15 against the tables above
xxd -l 16 broken.png
# PNG worked example: overwrite the first 8 bytes with a correct signature
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' | dd of=broken.png bs=1 seek=0 conv=notrunc
# PNG worked example: verify chunk structure and CRCs after the patch
pngcheck -v broken.png
# PNG worked example: append a valid IEND if the file was also truncated
printf '\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82' >> broken.png
# ZIP worked example: restore a zeroed local-file header
printf '\x50\x4b\x03\x04' | dd of=broken.zip bs=1 seek=0 conv=notrunc
# ZIP worked example: rebuild the central directory from the local headers
zip -FF broken.zip --out repaired.zip
# ZIP worked example: confirm the repair and list the contents
unzip -l repaired.zip
# Patch any offset: seek is the byte offset, notrunc preserves the rest
printf '\xff\xd9' | dd of=broken.jpg bs=1 seek=$(( $(stat -c%s broken.jpg) - 2 )) conv=notrunc
# Round-trip through a full hex dump for bulk edits
xxd broken.bin > broken.hex && vi broken.hex && xxd -r broken.hex > fixed.bin
# Interactive byte editing when you need to eyeball the structure
hexedit broken.png
# Strip prepended junk by carving from the real SOI marker
dd if=broken.jpg of=fixed.jpg bs=1 skip=$(grep -aobP '\xff\xd8\xff' broken.jpg | head -1 | cut -d: -f1)
```

## Truncated files and zero-length footers

```bash
# Is the IEND footer present at all
python3 -c "d=open('t.png','rb').read();print(d[-12:].hex(), len(d))"
# A JPEG missing FF D9 usually still renders; append the EOI anyway
printf '\xff\xd9' >> t.jpg
# Declared RIFF size versus real size, for wav/avi/webp
python3 -c "import struct;d=open('t.wav','rb').read();print(struct.unpack('<I',d[4:8])[0]+8, len(d))"
# Truncated ZIP has no EOCD: find the last local header and carve from there
grep -aob $'PK\x03\x04' t.zip | tail -1
# Recover the readable prefix of a truncated gzip stream
gzip -dc broken.gz > partial.out 2>/dev/null || true
```

## Polyglots and appended data

```bash
# The classic: a ZIP appended to a PNG - both tools succeed on the same file
unzip -l cover.png
# Unzip ignores leading junk, so extraction works straight from the image
unzip cover.png -d out/
# Tell: a PK header appearing AFTER the IEND offset
grep -aob -e $'IEND' -e $'PK\x03\x04' cover.png
# Carve the appended part (the IEND chunk block is 12 bytes from its name)
dd if=cover.png of=hidden.zip bs=1 skip=$(( $(grep -aob IEND cover.png | head -1 | cut -d: -f1) + 8 ))
# GIF polyglot: anything after the 0x3B trailer is ignored by decoders
grep -aob $'\x3b' cover.gif | tail -3
# PDF polyglot: content after the final %%EOF or in unreferenced stream objects
grep -aob '%%EOF' poly.pdf
# Offset-tolerant formats that ignore leading bytes: zip, rar, 7z, tar, iso, pdf
binwalk poly.bin
```

## Signature config file syntax

`foremost.conf` columns: `extension  case  size  header  footer  [options]`.
`case` is `y`/`n`, `size` is the max carve length in bytes, `\x89` is a hex byte,
`\?` a wildcard byte, `REVERSE` uses the last footer, `NEXT` carves to the next header.

```text
# PNG: carve from the signature through the IEND footer, 20 MB cap
png    y    20000000    \x89PNG\x0d\x0a\x1a\x0a    \x49\x45\x4e\x44\xae\x42\x60\x82
# JPEG JFIF variant; footer is the EOI marker
jpg    y    20000000    \xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46    \xff\xd9
# ZIP: carve to the end-of-central-directory record
zip    y    10000000    PK\x03\x04    PK\x05\x06
# PDF: REVERSE picks the LAST %%EOF, keeping incremental updates
pdf    y    5000000     %PDF    %%EOF    REVERSE
# GZIP has no footer, so carve a fixed maximum
gz     y    5000000     \x1f\x8b\x08    NONE
```

`scalpel.conf` uses the same five fields, one rule per line, `#` for comments.

```text
# GIF89a with its explicit trailer byte
gif    y    5000000     \x47\x49\x46\x38\x39\x61    \x00\x3b
# SQLite database, no footer - carve a fixed maximum size
db     y    50000000    SQLite\x20format\x203\x00
# Windows registry hive
hve    y    100000000   regf
# EVTX event log
evtx   y    100000000   ElfFile\x00
```

```bash
# Run foremost with a custom config against a raw image
foremost -c ./foremost.conf -i disk.raw -o carved/
# scalpel with a custom config; -b keeps header and footer in the output
scalpel -c ./scalpel.conf -b -o carved_scalpel/ disk.raw
# Review what was carved and from which offsets
head -40 carved/audit.txt
```

## References

- Gary Kessler's File Signatures Table (offline copy ships with many distros)
- `/usr/share/misc/magic` and the `file`/libmagic source for authoritative patterns
- TrID definition package, binwalk `magic` signature files
- Format specifications: PNG (W3C), ZIP APPNOTE, ISO/IEC 14496-12 for ISOBMFF
