---
title: "Playbook - Steganography Triage: Image, Audio, Video, Archive"
category: stego
subcategory: triage
type: playbook
tags: [stego-triage, where-to-start, stuck, steganography, image, png, jpeg, lsb, zsteg, steghide, stegsolve, outguess, exiftool, binwalk, spectrogram, audio-stego, sonic-visualiser, video, zip, bkcrack]
summary: "Run the universal sweep, then branch by container: PNG/BMP, JPEG, GIF, audio, video, or archive. Every branch ends in a command."
when_to_use:
  - "The challenge is a single image/audio/video file with no other hint"
  - "You suspect data is hidden inside a media file"
  - "You have an archive that may hide data in comments, slack space, or a password"
related: [unknown-file, stegsolve-zsteg, exiftool, binwalk, bkcrack, forensics-triage]
---

## TL;DR - the universal sweep (run every single time, 2 minutes)

```sh
F=chal.png

file "$F"                                  # real type vs extension
exiftool -a -u -G1 "$F"                    # ALL metadata, including duplicates and unknown tags
strings -a -n 6 "$F" | grep -aiE 'flag|ctf\{|key|pass|http'
strings -a -e l "$F" | grep -aiE 'flag|ctf\{'     # UTF-16LE
binwalk "$F"                               # appended/embedded files
binwalk -e "$F"                            # extract them
xxd "$F" | tail -5                         # data after the real EOF marker
```
That sweep alone solves roughly half of all stego challenges. If it does not, branch below.

One-shot aggregator (runs zsteg, steghide, binwalk, exiftool, outguess, LSB planes together):
```sh
aperisolve "$F"        # or the web version; see `ctfbrain search aperisolve`
stegoveritas "$F"      # pip install stegoveritas; then stegoveritas_install_deps
```

---

## Section 1 - PNG / BMP / GIF (lossless -> LSB is possible)

```sh
# 1. THE tool for lossless images. Always run it with -a.
zsteg -a chal.png
zsteg -E 'b1,rgb,lsb,xy' chal.png > extracted.bin    # extract a specific channel it flagged

# 2. Structural integrity: wrong CRC / extra chunks / wrong dimensions
pngcheck -v chal.png

# 3. Visual/bit-plane inspection
stegsolve chal.png          # arrow through all planes and colour maps
# or headless:
python3 -c "
from PIL import Image
im = Image.open('chal.png').convert('RGB')
w,h = im.size
px = im.load()
for bit in range(3):
    out = Image.new('1', (w,h))
    o = out.load()
    for y in range(h):
        for x in range(w):
            o[x,y] = (px[x,y][0] >> bit) & 1
    out.save(f'plane_r{bit}.png')"

# 4. Alpha channel: fully transparent pixels can still carry colour
python3 -c "
from PIL import Image
im = Image.open('chal.png').convert('RGBA')
im.putalpha(255); im.save('opaque.png')"
```

| Signal | Meaning | Action |
|---|---|---|
| `pngcheck`: "CRC error" in IHDR | the width/height was edited to crop out the flag | recompute the IHDR CRC for larger heights and brute-force; `ctfbrain search png-dimension-recovery` |
| `pngcheck`: chunks after IEND | appended data | `binwalk -e`, or `dd` from the IEND offset |
| Unknown ancillary chunks (`tEXt`, `zTXt`, `iTXt`, or a made-up 4-letter chunk) | text payload | `pngcheck -v` prints them; `zlib.decompress` a `zTXt` |
| Palette image (PLTE) with odd colours | palette-index stego | `zsteg -a`, look at the palette itself |
| Image looks solid but is a PNG | the data is in the pixels | bit planes |
| File size much larger than the visual content justifies | appended/embedded | `binwalk` |
| Two near-identical images given | pixel diff | `compare a.png b.png diff.png` / numpy XOR |

Pixel-diff between two images:
```python
from PIL import Image, ImageChops
a, b = Image.open("a.png").convert("RGB"), Image.open("b.png").convert("RGB")
d = ImageChops.difference(a, b)
print(d.getbbox())
d.point(lambda p: 255 if p else 0).save("diff.png")
```

GIF specifics:
```sh
# frames can each carry a piece of the flag, or a single frame may flash by
convert chal.gif frame_%03d.png
identify -format '%s %T\n' chal.gif      # per-frame delay; a 1-frame 0-delay frame is suspicious
gifsicle --explode chal.gif
```

---

## Section 2 - JPEG (lossy -> LSB does NOT survive; different tools)

```sh
# 1. The classic JPEG stego tools. Try an empty password first.
steghide info chal.jpg
steghide extract -sf chal.jpg -p ''
outguess -r chal.jpg out.txt
jsteg reveal chal.jpg
stegseek chal.jpg /usr/share/wordlists/rockyou.txt      # fast steghide password cracker

# 2. Structure
exiftool -a -u -G1 chal.jpg
jpeginfo -c chal.jpg
# DCT coefficient histogram anomalies
stegdetect chal.jpg 2>/dev/null

# 3. Thumbnail can differ from the image (the classic "hidden in the EXIF thumbnail")
exiftool -b -ThumbnailImage chal.jpg > thumb.jpg && open thumb.jpg
exiftool -b -PreviewImage chal.jpg > prev.jpg
```

| Signal | Tool |
|---|---|
| `steghide info` says "embedded data" | `steghide extract -sf f -p <pass>`; crack with `stegseek` |
| EXIF `Comment`/`UserComment`/`XPComment` non-empty | read it; it may be base64 |
| Thumbnail differs from the image | `exiftool -b -ThumbnailImage` |
| `FFD9` (EOI) followed by more bytes | `binwalk -e`, or `dd bs=1 skip=<offset>` |
| Repeated identical `FFD8` markers | multiple JPEGs concatenated |
| `jphide`/`jphs` mentioned | `jphide`/`jpseek` |
| Nothing found and the image is a photo | try `zsteg` anyway (it will say "not a PNG"), then move to metadata/format tricks |

**Never run `zsteg` expecting LSB results on a JPEG** - JPEG is DCT-compressed, spatial LSB does not survive. `steghide` and `outguess` operate on DCT coefficients, which is why they work.

---

## Section 3 - Audio

```sh
F=chal.wav
# 1. Metadata and format
exiftool "$F"; ffprobe -hide_banner "$F"
# 2. THE first thing to look at: the spectrogram. Text is often drawn in it.
sox "$F" -n spectrogram -o spec.png -x 2000 -y 1000
# or: Audacity -> track dropdown -> Spectrogram; or Sonic Visualiser -> Layer -> Spectrogram
ffmpeg -i "$F" -lavfi showspectrumpic=s=2000x1000:legend=disabled spec.png
# 3. LSB in WAV samples (lossless only)
python3 -c "
import wave
w = wave.open('$F','rb'); d = w.readframes(w.getnframes())
bits = ''.join(str(b & 1) for b in d)
print(bytes(int(bits[i:i+8],2) for i in range(0, len(bits)//8*8, 8))[:300])"
# 4. Dedicated tools
stegolsb wavsteg -r -i "$F" -o out.txt -n 1 -b 1000
deepsound            # Windows GUI, for DeepSound-encrypted wavs
```

| What you hear/see | Technique |
|---|---|
| A visible shape/text in the spectrogram | that IS the flag; read it off the image |
| Beeps of two lengths | Morse: `ctfbrain search morse`, or `morse2ascii` |
| A modem/fax screech | SSTV (`qsstv`/`slowrx`) or a dial-up/DTMF encoding |
| Telephone tones | DTMF: `multimon-ng -a DTMF -t wav f.wav` |
| Speech played backwards | `sox in.wav out.wav reverse` |
| Speech at the wrong speed/pitch | `sox in.wav out.wav speed 0.5` / `pitch -500` |
| Two channels that sound identical | subtract them: `sox in.wav out.wav oops` (removes the centre) |
| A very short high-frequency burst | `sox in.wav out.wav sinc 15k-` to isolate |
| Silence at the start/end with nonzero samples | LSB or raw data |
| An MP3 given (lossy) | `mp3stego` (`Decode -X -P pass f.mp3`); LSB will not work |
| A FLAC/WAV with an odd chunk | `binwalk`, `xxd` the header |
| `.mid` | the note values encode bytes; parse with `mido` |

```sh
# Channel isolation / difference
sox stereo.wav left.wav remix 1
sox stereo.wav right.wav remix 2
# spectrogram of just one channel often reveals the hidden one
```

---

## Section 4 - Video

```sh
F=chal.mp4
ffprobe -hide_banner -show_streams "$F"       # extra streams? subtitles? attachments?
ffmpeg -i "$F" -vn -acodec copy audio.aac     # pull the audio -> go to Section 3
ffmpeg -i "$F" frames/%05d.png                # every frame -> go to Section 1
ffmpeg -i "$F" -vf "select='eq(pict_type,I)'" -vsync vfr key_%03d.png   # keyframes only
mkvextract attachments "$F" 1:out.bin         # MKV attachments
ffmpeg -i "$F" -map 0:s:0 subs.srt            # subtitles can hold the flag
binwalk -e "$F"
exiftool -a -u -G1 "$F"
```
Then: look for a single anomalous frame (`fdupes`/hash every frame and find the outlier), text drawn in one frame, QR codes across frames, or a message in the audio spectrogram.

```sh
# find the odd frame out of thousands
md5sum frames/*.png | awk '{print $1}' | sort | uniq -c | sort -n | head
```

---

## Section 5 - Archives

```sh
F=chal.zip
# 1. List first - names, sizes, and the comment field
unzip -l "$F"; unzip -z "$F"          # -z prints the archive comment
7z l -slt "$F"                        # per-entry metadata, encryption method
zipinfo -v "$F" | grep -iE 'comment|extra field|encrypt'

# 2. Is it encrypted, and with what?
7z l -slt "$F" | grep -i 'Encrypted\|Method'
#   ZipCrypto  -> known-plaintext attack (bkcrack) if you know 12+ bytes of any file
#   AES-256    -> password cracking only

# 3. Crack the password
zip2john "$F" > h.txt && john h.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 17200 h.txt rockyou.txt    # PKZIP compressed
hashcat -m 13600 h.txt rockyou.txt    # WinZip AES

# 4. Known-plaintext on ZipCrypto (needs 12 known bytes, ideally contiguous)
bkcrack -C "$F" -c secret.txt -p known_prefix.bin
bkcrack -C "$F" -k K0 K1 K2 -D out.zip       # then decrypt the whole archive
```

| Signal | Attack |
|---|---|
| A file in the archive is a known format (PNG/PDF/docx) | its header is your known plaintext -> `bkcrack` |
| Two archives, one encrypted, one not, same file | perfect known plaintext |
| ZipCrypto + any known file | `bkcrack` (seconds to minutes) |
| AES-256 | `john`/`hashcat` with a wordlist or a mask; no shortcut |
| The password hint is in the filename/comment | `unzip -z` |
| `unzip` says "need PK compat v??" | it may be a different archiver; try `7z x` |
| Nested archives, hundreds deep | script it: loop `7z x` until no archive remains |
| Filenames with `../` | zip slip; the flag may be the vulnerability itself |
| Extra data between entries | `binwalk` the archive itself |
| A RAR with a recovery record | `unrar r f.rar` to repair |
| Corrupted ZIP | `zip -FF broken.zip --out fixed.zip`; or fix the local header magic by hand |

Auto-unnest script:
```sh
# keep extracting until nothing is an archive any more
while true; do
  before=$(find . -type f | wc -l)
  find . -type f \( -name '*.zip' -o -name '*.gz' -o -name '*.bz2' -o -name '*.xz' -o -name '*.tar' -o -name '*.7z' -o -name '*.rar' \) \
    -exec 7z x -y -o{}_out {} \; -exec rm {} \;
  after=$(find . -type f | wc -l)
  [ "$before" = "$after" ] && break
done
grep -rniE 'flag\{|ctf\{' . | head
```

---

## Section 6 - Passwords to try before cracking

CTF stego tools usually take a password. Try, in order: (empty), the filename without extension, the challenge name, the CTF name, `password`, `secret`, `flag`, `stego`, any string in the image's EXIF `Comment`/`Artist`/`Copyright`, any word in the challenge description, and the alt text on the challenge page.

```sh
# then crack with a real list
stegseek chal.jpg /usr/share/wordlists/rockyou.txt          # steghide only, very fast
stegcracker chal.jpg /usr/share/wordlists/rockyou.txt       # slower fallback
```

---

## Section 7 - Decision summary

| Container | Try in this order |
|---|---|
| PNG/BMP | `zsteg -a` -> `pngcheck -v` -> bit planes -> `binwalk` -> chunk text |
| JPEG | `steghide`/`stegseek` -> `outguess` -> `exiftool` (thumbnail!) -> `binwalk` |
| GIF | frames -> per-frame diff -> `binwalk` -> comment extension |
| WAV/FLAC | spectrogram -> LSB -> channel difference -> `binwalk` |
| MP3 | `mp3stego` -> spectrogram -> ID3 tags -> `binwalk` |
| MP4/MKV | extract audio + frames + subtitles + attachments, then recurse |
| ZIP/RAR/7z | comment -> `bkcrack` -> `john` -> nested extraction |
| PDF/DOC | `ctfbrain search forensics-triage` section 4 |
| Anything | `strings`, `exiftool`, `binwalk`, and re-read the challenge description |

If all of it fails, the hint is in the challenge text. Re-read it word by word: stego challenge names almost always name the tool or the technique. `ctfbrain search stuck`
