---
title: "Tool - ExifTool"
category: forensics
subcategory: metadata
type: tool
tags: [exiftool, metadata, exif, xmp, iptc, gps, thumbnail, image, pdf, office, video, geolocation, osint, stego, forensics, tags]
summary: "Read and write metadata in almost any file format; the second command to run on any image, document or media file."
related: [stego-triage, forensics-triage, unknown-file, binwalk]
---

## What it is

ExifTool reads, writes and edits metadata in over 100 file formats: images (EXIF, IPTC, XMP, MakerNotes), PDFs, Office documents, audio, video, and many more. In CTF it finds the flag hidden in a comment field, the GPS coordinates for an OSINT challenge, the embedded thumbnail that differs from the visible image, and the author/software fields that identify how a file was produced.

## Install

```sh
# macOS
brew install exiftool
# Debian/Ubuntu/Kali
sudo apt install libimage-exiftool-perl
# verify
exiftool -ver
```

## The invocations that matter

```sh
F=chal.jpg

# 1. everything, including duplicate and unknown tags, with group names
exiftool -a -u -G1 "$F"

# 2. the plain read (what you run first, every time)
exiftool "$F"

# 3. extract the embedded thumbnail / preview - it often differs from the visible image
exiftool -b -ThumbnailImage "$F" > thumb.jpg
exiftool -b -PreviewImage   "$F" > preview.jpg
exiftool -b -JpgFromRaw     "$F" > raw.jpg

# 4. dump one specific tag's raw bytes
exiftool -b -UserComment "$F"
exiftool -b -Comment "$F"
exiftool -b -XMP "$F" > xmp.xml

# 5. GPS coordinates for OSINT
exiftool -gps:all -c '%.8f' "$F"
exiftool -n -GPSLatitude -GPSLongitude "$F"

# 6. recurse a whole directory and grep
exiftool -r -a -u -G1 ./extracted/ | grep -iE 'flag|ctf|comment|author|creator|gps'

# 7. machine-readable output
exiftool -j "$F"                 # JSON
exiftool -csv -r ./dir/ > meta.csv
exiftool -X "$F"                 # XML

# 8. show only files that have a particular tag set
exiftool -r -if '$Comment' -filename -Comment ./dir/

# 9. write/strip metadata (useful when a challenge checks metadata)
exiftool -Comment='hello' out.jpg
exiftool -all= out.jpg                       # strip everything
exiftool -overwrite_original -Artist='x' out.jpg

# 10. compare two files' metadata
diff <(exiftool -a -u -G1 a.jpg) <(exiftool -a -u -G1 b.jpg)
```

Tags that hide flags, in rough order of frequency:

| Tag | Format |
|---|---|
| `Comment` / `UserComment` | JPEG, PNG |
| `XPComment`, `XPTitle`, `XPKeywords`, `XPSubject`, `XPAuthor` | Windows-written JPEGs (UTF-16LE) |
| `Artist`, `Copyright`, `ImageDescription`, `Software` | EXIF |
| `Description`, `Title`, `Creator`, `Subject`, `Rights` | XMP / PDF / Office |
| `Keywords`, `Caption-Abstract`, `Headline` | IPTC |
| `ThumbnailImage`, `PreviewImage` | the hidden second image |
| `GPSLatitude`, `GPSLongitude`, `GPSAltitude` | OSINT geolocation |
| `MakerNotes` (vendor-specific, huge) | camera-specific blobs |
| `DocumentID`, `InstanceID`, `OriginalDocumentID` | XMP provenance chains |
| `CreateDate`, `ModifyDate`, `FileModifyDate` | timeline correlation |
| `Producer`, `Creator` | PDF: names the generating tool |
| `Lyrics`, `Comment`, `Encoder` | MP3 ID3 |
| `Encoder`, `Title`, `Handler Description` | MP4/MKV |
| `Warning` | exiftool's own note that something is malformed - always read it |

## Gotchas

- **Always use `-a -u -G1`.** The default output hides duplicate tags, unknown tags, and which group each tag came from. Flags live in exactly those places.
- `-b` (binary) is required to extract a tag's raw value; without it you get a `(Binary data N bytes, use -b option to extract)` placeholder.
- Windows `XP*` tags are UTF-16LE; exiftool decodes them, but if you extract with `-b` you get raw UTF-16 - pipe through `iconv -f UTF-16LE` or `strings -e l`.
- Writing metadata creates a `_original` backup unless you pass `-overwrite_original`.
- exiftool **does not** find data appended after a file's logical end, or LSB stego. Run `binwalk` and `zsteg` too.
- It reports a `Warning` for malformed structures - a malformed structure is often deliberate. Do not ignore warnings.
- For PDFs, exiftool reads the document info dictionary but not object-level content; use `pdf-parser.py`/`peepdf` for that.
- Very large MakerNotes blobs can contain an entire second image; extract them and run `file` on the result.
- On a file with the wrong extension, exiftool identifies the real type in `FileType` - a cheap second opinion alongside `file`.
- Tag names are case-insensitive on the command line but exact in `-if` conditions.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Appended or embedded files | `binwalk -e`, `foremost` |
| LSB / pixel-level stego | `zsteg -a`, Stegsolve (`ctfbrain search stegsolve-zsteg`) |
| PNG chunk internals | `pngcheck -v` |
| PDF object contents | `pdf-parser.py`, `peepdf`, `qpdf --qdf` |
| Office document internals | `unzip` the docx, `olevba`, `oledump.py` |
| Media stream details | `ffprobe -show_streams`, `mediainfo` |
| Just want any text | `strings -a`, `strings -a -e l` |
| Bulk metadata across a disk image | `bulk_extractor`, or `exiftool -r` over the extracted tree |
