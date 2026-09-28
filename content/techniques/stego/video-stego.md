---
title: "Video Stego and Frame Extraction"
category: stego
subcategory: video
type: technique
tags: [video, ffmpeg, ffprobe, frames, mp4, mkv, avi, atoms, boxes, subtitles, attachments, frame-diff, qr-per-frame, apng, audio-track, stego]
difficulty: medium
summary: "A video is frames plus audio plus side data; split all three, then diff frames and look at the audio spectrogram."
when_to_use:
  - "The challenge file is .mp4, .mkv, .avi, .webm, .mov or .gif with many frames"
  - "Something flashes for one frame during playback"
  - "ffprobe lists more streams than you expected (subtitles, data, attachments)"
  - "The container is much bigger than the visible video quality justifies"
tools: [ffmpeg, ffprobe, mkvtoolnix, mp4box, exiftool, binwalk, python3, zbarimg, opencv]
related: [audio-stego, image-triage, lsb-extraction, other-image-formats, qr-barcode, stego-cheatsheet]
---

## TL;DR

Treat a video as three separate challenges: the **frames** (image stego, one frame at a time or
in difference), the **audio track** (see `audio-stego`), and the **container side-data**
(subtitles, chapters, attachments, metadata atoms). `ffprobe` tells you which of the three the
author actually used.

## Recognise it

- `ffprobe` reports a subtitle or data stream you did not expect.
- Frame count x resolution does not explain the file size.
- Playback shows a single-frame flash (24-60 ms) of text or a QR code.
- A `.mkv` with attachments (`ffmpeg -dump_attachment`).
- Metadata `comment`/`description` fields populated.
- The video is a still image for its whole duration (so the payload is in the audio or in the
  tiny per-frame differences).

## Attack

### 1. Inventory the container

```bash
# every stream, codec, duration, and all container/stream metadata
ffprobe -hide_banner -show_format -show_streams -show_chapters chal.mp4

# per-frame info: type (I/P/B), size, pts - spot the one anomalous frame
ffprobe -select_streams v -show_frames -show_entries frame=pkt_pts_time,pict_type,pkt_size \
        -of csv chal.mp4 | head -50

# container-level metadata and MP4 atom tree
exiftool -a -u -g1 chal.mp4
MP4Box -info chal.mp4
mkvinfo chal.mkv

# anything appended or embedded
binwalk chal.mp4
```

### 2. Extract everything

```bash
# all frames as lossless PNG (careful: 60s of 30fps = 1800 files)
mkdir -p frames && ffmpeg -i chal.mp4 -vsync 0 frames/%06d.png

# only keyframes - usually enough and 20x fewer files
ffmpeg -i chal.mp4 -vf "select=eq(pict_type\,I)" -vsync 0 keyframes/%04d.png

# one frame at an exact timestamp
ffmpeg -ss 00:00:12.500 -i chal.mp4 -frames:v 1 frame.png

# the audio track, as canonical PCM for the audio toolchain
ffmpeg -i chal.mp4 -vn -acodec pcm_s16le -ar 44100 audio.wav

# subtitles (embedded soft subs are plain text and a classic hiding place)
ffmpeg -i chal.mkv -map 0:s:0 subs.srt
mkvextract tracks chal.mkv 2:subs.srt

# mkv attachments (fonts... or a zip named like a font)
ffmpeg -dump_attachment:t "" -i chal.mkv
mkvextract attachments chal.mkv 1:out.bin

# data streams
ffmpeg -i chal.mp4 -map 0:d:0 -c copy data.bin
```

### 3. Analyse the frames

```bash
# contact sheet: 100 frames in one image, scan it by eye in seconds
ffmpeg -i chal.mp4 -vf "select=not(mod(n\,30)),scale=320:-1,tile=10x10" -vsync 0 sheet.png

# difference between consecutive frames, amplified
ffmpeg -i chal.mp4 -vf "tblend=all_mode=difference,eq=contrast=10" -vsync 0 diff/%06d.png

# per-frame QR decode
for f in frames/*.png; do zbarimg -q --raw "$f" && echo "  <- $f"; done

# LSB across frames
zsteg -a frames/000001.png
```

### 4. Container-specific notes

- **MP4/MOV (ISO BMFF)**: a tree of boxes `size(4) type(4) payload`. `free`, `skip` and `udta`
  boxes are ignored by players and hold arbitrary bytes. `moov` after `mdat` is normal, not
  suspicious. A box whose declared size overruns the file means hand-editing.
- **MKV (EBML)**: variable-length element IDs and sizes; `mkvinfo -v` walks the tree.
  Attachments and `Tags` elements carry payloads.
- **AVI (RIFF)**: `JUNK` chunks are literal padding - and a perfect hiding place. Same parsing
  approach as WEBP/WAV.

## Code

```python
#!/usr/bin/env python3
"""Video stego helper: stream inventory, frame extraction, frame differencing, MP4 box walk.

Requires ffmpeg/ffprobe on PATH for the extraction commands; the MP4 box walker is pure python.

Usage:
  python3 video_stego.py probe   chal.mp4
  python3 video_stego.py frames  chal.mp4 outdir
  python3 video_stego.py diff    framedir
  python3 video_stego.py boxes   chal.mp4
  python3 video_stego.py --selftest
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys

CONTAINER_BOXES_IGNORED_BY_PLAYERS = {b"free", b"skip", b"wide", b"udta", b"uuid"}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def probe(path: str) -> dict:
    if not have("ffprobe"):
        return {"error": "ffprobe not installed"}
    cmd = ["ffprobe", "-v", "quiet", "-print_format", "json",
           "-show_format", "-show_streams", "-show_chapters", path]
    p = subprocess.run(cmd, capture_output=True, timeout=300)
    try:
        return json.loads(p.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {"error": p.stderr.decode("utf-8", "replace")[:400]}


def summarise(info: dict) -> list[str]:
    out = []
    fmt = info.get("format", {})
    out.append(f"format: {fmt.get('format_name')} duration={fmt.get('duration')} size={fmt.get('size')}")
    for k, v in (fmt.get("tags") or {}).items():
        out.append(f"  container tag {k} = {v!r}")
    for s in info.get("streams", []):
        out.append(f"stream #{s.get('index')} {s.get('codec_type')} {s.get('codec_name')} "
                   f"{s.get('width', '')}x{s.get('height', '')} frames={s.get('nb_frames')}")
        for k, v in (s.get("tags") or {}).items():
            out.append(f"    tag {k} = {v!r}")
        if s.get("codec_type") not in ("video", "audio"):
            out.append("    !! non-AV stream: extract it with -map")
    for c in info.get("chapters", []):
        out.append(f"chapter {c.get('id')}: {(c.get('tags') or {}).get('title')!r}")
    return out


def extract_frames(path: str, outdir: str, every: int = 1) -> int:
    os.makedirs(outdir, exist_ok=True)
    vf = f"select=not(mod(n\\,{every}))" if every > 1 else None
    cmd = ["ffmpeg", "-y", "-v", "error", "-i", path]
    if vf:
        cmd += ["-vf", vf]
    cmd += ["-vsync", "0", os.path.join(outdir, "%06d.png")]
    subprocess.run(cmd, check=True, timeout=1800)
    return len([f for f in os.listdir(outdir) if f.endswith(".png")])


def extract_audio(path: str, outwav: str) -> bool:
    if not have("ffmpeg"):
        return False
    cmd = ["ffmpeg", "-y", "-v", "error", "-i", path, "-vn",
           "-acodec", "pcm_s16le", "-ar", "44100", outwav]
    return subprocess.run(cmd, timeout=1800).returncode == 0


def frame_diffs(framedir: str, top: int = 15) -> list[tuple[float, str, str]]:
    """Rank consecutive frame pairs by mean absolute difference (needs Pillow)."""
    from PIL import Image, ImageChops

    files = sorted(f for f in os.listdir(framedir) if f.lower().endswith((".png", ".jpg", ".bmp")))
    scores: list[tuple[float, str, str]] = []
    prev = None
    prev_name = ""
    for name in files:
        im = Image.open(os.path.join(framedir, name)).convert("L")
        if prev is not None:
            d = ImageChops.difference(prev, im)
            hist = d.histogram()
            total = sum(i * c for i, c in enumerate(hist))
            scores.append((total / max(1, sum(hist)), prev_name, name))
        prev, prev_name = im, name
    scores.sort(key=lambda t: -t[0])
    return scores[:top]


def walk_mp4(data: bytes, start: int = 0, end: int | None = None, depth: int = 0) -> list[str]:
    """Walk ISO BMFF boxes, flagging the ones players ignore."""
    if end is None:
        end = len(data)
    out: list[str] = []
    pos = start
    containers = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"moof", b"traf", b"edts"}
    while pos + 8 <= end:
        (size,) = struct.unpack(">I", data[pos:pos + 4])
        typ = data[pos + 4:pos + 8]
        hdr = 8
        if size == 1:  # 64-bit extended size
            if pos + 16 > end:
                break
            (size,) = struct.unpack(">Q", data[pos + 8:pos + 16])
            hdr = 16
        elif size == 0:  # runs to end of file
            size = end - pos
        if size < hdr or pos + size > end:
            out.append(f"{'  ' * depth}@0x{pos:x} {typ!r} BAD SIZE {size} (file has {end - pos} left)")
            break
        note = ""
        if typ in CONTAINER_BOXES_IGNORED_BY_PLAYERS:
            body = data[pos + hdr:pos + size]
            printable = sum(1 for b in body[:64] if 32 <= b < 127)
            note = f"  !! ignored-by-players box, {size - hdr} bytes, head={body[:32]!r} printable={printable}/64"
        out.append(f"{'  ' * depth}@0x{pos:x} {typ.decode('latin1', 'replace')} size={size}{note}")
        if typ in containers and typ != b"udta":
            out += walk_mp4(data, pos + hdr, pos + size, depth + 1)
        pos += size
    if pos < end:
        out.append(f"{'  ' * depth}!! {end - pos} trailing bytes after the last box")
    return out


def build_mp4_like(payload: bytes) -> bytes:
    """Minimal ISO BMFF-shaped file with an ftyp, a free box carrying a payload, and an mdat."""
    def box(typ: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body) + 8) + typ + body

    return (box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2avc1mp41")
            + box(b"free", payload)
            + box(b"mdat", b"\x00" * 32))


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    cmd = sys.argv[1]
    if cmd == "probe":
        for line in summarise(probe(sys.argv[2])):
            print(line)
    elif cmd == "frames":
        every = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        n = extract_frames(sys.argv[2], sys.argv[3], every)
        print(f"[+] {n} frames in {sys.argv[3]}")
    elif cmd == "diff":
        for score, a, b in frame_diffs(sys.argv[2]):
            print(f"{score:8.3f}  {a} -> {b}")
    elif cmd == "boxes":
        for line in walk_mp4(open(sys.argv[2], "rb").read()):
            print(line)
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    blob = build_mp4_like(b"flag{hidden_in_a_free_box}")
    lines = walk_mp4(blob)
    assert any("ftyp" in ln for ln in lines), lines
    assert any("ignored-by-players" in ln and "flag{hidden" in ln for ln in lines), lines
    assert any("mdat" in ln for ln in lines), lines

    trailing = blob + b"PK\x03\x04APPENDED"
    lines2 = walk_mp4(trailing)
    assert any("trailing bytes" in ln or "BAD SIZE" in ln for ln in lines2), lines2

    info = {"format": {"format_name": "mov,mp4", "duration": "3.0", "size": "1234",
                       "tags": {"comment": "look closer"}},
            "streams": [{"index": 0, "codec_type": "video", "codec_name": "h264",
                         "width": 8, "height": 8, "nb_frames": "3"},
                        {"index": 1, "codec_type": "subtitle", "codec_name": "subrip",
                         "tags": {"title": "secret"}}],
            "chapters": []}
    summary = summarise(info)
    assert any("non-AV stream" in ln for ln in summary), summary
    assert any("look closer" in ln for ln in summary), summary
    print("selftest ok: mp4 box walk found the free-box payload and the trailing data")


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **`-vsync 0` matters.** Without it ffmpeg duplicates/drops frames to hit a constant frame
  rate, so your extracted frame N is not the container's frame N.
- **Never extract frames as JPEG.** Use PNG or BMP, otherwise you re-encode and destroy any LSB.
- **The video may be a decoy.** If every frame is identical, the payload is in the audio or the
  container. Check `frame_diffs` - a mean difference of 0.0 everywhere tells you immediately.
- **One-frame flashes** are missed by eye. Use the contact sheet or `frame_diffs`; the flash
  frame will be the top difference score by a wide margin.
- **Subtitle streams** may be image-based (PGS/VOBSUB) rather than text; extract with
  `mkvextract` and OCR them.
- **`udta`/`free`/`skip` boxes in MP4** and `JUNK` chunks in AVI are the container equivalents
  of a PNG ancillary chunk.
- **Interlaced or telecined sources** produce combed frames; `-vf yadif` deinterlaces but also
  modifies pixels, so only do it for *viewing*.
- **Very high frame counts** will fill your disk. Extract keyframes first, then narrow down with
  `-ss`/`-t`.
- **Per-frame LSB with a rolling offset** (payload split across frames) needs you to
  concatenate the extracted bitstreams in frame order before packing to bytes.

## Tools

`ffmpeg`/`ffprobe`, `mkvtoolnix` (`mkvinfo`, `mkvextract`), `MP4Box` (GPAC), `exiftool`,
`binwalk`, `zbarimg`, OpenCV (`cv2.VideoCapture`), Pillow for differencing.

## References

- FFmpeg documentation for `select`, `tile`, `tblend`, `-map`, `-dump_attachment`.
- ISO/IEC 14496-12 (ISO base media file format) for the box header layout used above.
- Matroska specification for the EBML element tree and attachment elements.
