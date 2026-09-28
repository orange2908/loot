---
title: "Steganography - Master Cheatsheet"
category: stego
subcategory: cheatsheet
type: cheatsheet
tags: [stego, zsteg, steghide, stegseek, outguess, stegsolve, binwalk, foremost, pngcheck, exiftool, sonic-visualiser, stegoveritas, aperisolve, lsb, spectrogram, zbarimg, bkcrack, cheatsheet]
summary: "Decision tree plus every tool invocation for image, audio, video, text and archive steganography."
tools: [file, exiftool, binwalk, foremost, zsteg, steghide, stegseek, outguess, stegsolve, pngcheck, ffmpeg, sox, zbarimg, bkcrack, stegoveritas]
related: [image-triage, png-structure-attacks, jpeg-structure-attacks, lsb-extraction, audio-stego, video-stego, text-unicode-stego, polyglot-files, archive-attacks, qr-barcode, stego-bruteforce, image-forensics-cheatsheet]
---

## Decision tree

```text
what did `file` say?
|
+- PNG / BMP / GIF / TIFF (lossless)
|    1. exiftool -a -u -g1          metadata, text chunks
|    2. pngcheck -vv                CRC, dimensions, chunks after IEND
|    3. binwalk -e                  appended/embedded files
|    4. zsteg -a                    every channel/bit/order
|    5. stegsolve / bit planes      visual
|    6. second image? -> compare -metric AE a b diff.png
|
+- JPEG (lossy)
|    1. exiftool -a -u -g1; exiftool -b -ThumbnailImage > thumb.jpg  <- LOOK AT IT
|    2. xxd | tail  (bytes after FFD9); binwalk -e
|    3. steghide info -p ''  then  stegseek FILE rockyou.txt
|    4. outguess -r ; jsteg reveal ; stegdetect -tjopi
|    (zsteg/LSB do NOT apply to JPEG)
|
+- WAV / MP3 / FLAC / OGG
|    1. ffmpeg -i f -lavfi showspectrumpic=s=1920x1080 spec.png   <- FIRST
|    2. exiftool; binwalk -e
|    3. steghide (WAV/AU only) + stegseek
|    4. LSB of samples; multimon-ng -a DTMF -a MORSE_CW
|    5. reverse / slow / channel subtraction
|
+- MP4 / MKV / AVI / WEBM
|    1. ffprobe -show_streams -show_format -show_chapters
|    2. extract audio -> audio branch; extract frames -> image branch
|    3. ffmpeg -dump_attachment ; subtitle streams ; udta/free boxes
|
+- TXT / source / PDF / DOCX
|    1. xxd | grep -E 'e280 8[bcd]|efbb bf'   zero-width
|    2. cat -A | head                         trailing whitespace
|    3. exiftool / docProps / pdf incremental updates
|
+- ZIP / RAR / 7z / unknown binary
     1. binwalk -e ; foremost ; 7z l ; unzip -l
     2. encrypted? ZipCrypto -> bkcrack ; AES -> zip2john + john/hashcat
     3. zip -FF broken.zip --out fixed.zip
```

## Identify

```bash
# real type from magic bytes
file -b chal.bin
# first and last 64 bytes (signature + terminator + appended data)
xxd chal.png | head -4; xxd chal.png | tail -4
# full image properties incl. bit depth, colour type, interlace
identify -verbose chal.png | head -40
# record the hash before you touch anything
sha256sum chal.png
# entropy graph: a flat high-entropy block inside a low-entropy file is a payload
binwalk -E chal.png
```

## Metadata

```bash
# every tag, grouped, including unknown and duplicated tags
exiftool -a -u -g1 chal.jpg
# machine readable
exiftool -json -a -u -g1 chal.jpg
# GPS as signed decimals
exiftool -n -GPSLatitude -GPSLongitude chal.jpg
# dump any binary tag
exiftool -b -ThumbnailImage chal.jpg > thumb.jpg
exiftool -b -PreviewImage chal.jpg > preview.jpg
exiftool -b -ICC_Profile chal.jpg > profile.icc
exiftool -b -UserComment chal.jpg > comment.bin
exiftool -b -MakerNotes chal.jpg > maker.bin
exiftool -xmp -b chal.jpg > packet.xmp
# PNG text chunks (tEXt/zTXt/iTXt)
exiftool -PNG:all -a -u chal.png
# write a tag (building your own test cases)
exiftool -Comment='flag{test}' out.jpg
# strip everything
exiftool -all= clean.jpg
```

## Appended / embedded data

```bash
# signature scan
binwalk chal.png
# extract everything binwalk recognises
binwalk -e --dd='.*' chal.png
# recursive (careful: can explode)
binwalk -Me chal.png
# header-based carving
foremost -i chal.png -o foremost_out
scalpel -c /etc/scalpel/scalpel.conf -o scalpel_out chal.png
# manual carve from an offset to EOF
dd if=chal.png bs=1 skip=54321 of=carved.bin
python3 -c "open('carved.bin','wb').write(open('chal.png','rb').read()[54321:])"
# archives hidden in images work directly
unzip -l chal.png; 7z l chal.png; 7z x chal.png -oout/
```

## PNG

```bash
# structure, CRCs, chunk offsets, data after IEND
pngcheck -vv chal.png
# fix a mangled signature
printf '\x89PNG\r\n\x1a\n' | dd of=chal.png bs=1 seek=0 conv=notrunc
# patch width (offset 16) and height (offset 20), big-endian
printf '\x00\x00\x02\x00' | dd of=chal.png bs=1 seek=16 conv=notrunc
printf '\x00\x00\x01\x80' | dd of=chal.png bs=1 seek=20 conv=notrunc
# re-render to confirm the fix
convert chal.png fixed.png
# inflate the IDAT stream by hand
python3 -c "import zlib,sys;d=open('idat.bin','rb').read();print(len(zlib.decompress(d)))"
```

## JPEG

```bash
# structure sanity
jpeginfo -c chal.jpg
djpeg -verbose chal.jpg > /dev/null
# markers and segment offsets
exiftool -v3 chal.jpg | head -60
# DCT-domain tools
steghide info -p '' chal.jpg
steghide extract -sf chal.jpg -p 'pass' -xf out.bin
stegseek --crack -f chal.jpg /usr/share/wordlists/rockyou.txt out.bin
stegseek --seed chal.jpg
outguess -r chal.jpg out.txt
outguess -k 'password' -r chal.jpg out.txt
jsteg reveal chal.jpg out.txt
stegdetect -tjopi chal.jpg
```

## LSB and bit planes

```bash
# the full standard grid (PNG/BMP only)
zsteg -a chal.png
# a specific combination, dumped to a file
zsteg -E 'b1,rgb,lsb,xy' chal.png > payload.bin
zsteg -E 'b1,r,msb,yx'  chal.png > payload2.bin
# 2 and 4 bits per sample
zsteg -a -b 2 chal.png
# BMP works too
zsteg -a chal.bmp
# GUI plane browser + Analyse > Data Extract
java -jar stegsolve.jar chal.png
# ImageMagick bit-plane isolation
convert chal.png -channel R -separate -fx '(floor(u*255)%2)' -normalize r_b0.png
convert chal.png -channel G -separate -fx '(floor(u*255)%2)' -normalize g_b0.png
convert chal.png -channel B -separate -fx '(floor(u*255)%2)' -normalize b_b0.png
convert chal.png -channel A -separate alpha.png
# does the alpha channel actually vary?
python3 -c "from PIL import Image;print(Image.open('chal.png').convert('RGBA').getchannel('A').getextrema())"
```

## Automated everything

```bash
# runs zsteg, steghide, binwalk, exiftool, colour transforms, and more
stegoveritas chal.png
stegoveritas chal.jpg -out results/
# aperisolve is the web equivalent (zsteg + steghide + outguess + binwalk + colour planes)
# one-shot sweep of the usual suspects
for t in "file" "exiftool -a -u -g1" "binwalk" "pngcheck -vv" "zsteg -a" "strings -n 8"; do
  echo "=== $t"; $t chal.png 2>&1 | head -30; done
```

## strings variants

```bash
strings -n 6 chal.png                   # default (7-bit ASCII), min length 6
strings -e l -n 6 chal.png              # 16-bit little-endian (UTF-16LE)
strings -e b -n 6 chal.png              # 16-bit big-endian
strings -e S -n 6 chal.png              # single-8-bit (latin1)
strings -a -t x chal.png                # scan the whole file, print hex offsets
strings chal.png | grep -aiE 'flag|ctf|key|pass|secret'
strings chal.png | grep -aoE '[A-Za-z0-9+/]{20,}={0,2}'   # base64 candidates
```

## Audio

```bash
# spectrogram (the single most valuable audio command)
ffmpeg -i chal.wav -lavfi showspectrumpic=s=1920x1080:mode=combined:legend=1 spec.png
ffmpeg -i chal.wav -lavfi showspectrumpic=s=2048x1024:mode=separate:scale=log sep.png
sox chal.wav -n spectrogram -o spec.png -x 2000 -y 1000
# waveform picture
ffmpeg -i chal.wav -lavfi showwavespic=s=1920x480 wave.png
# stream info
ffprobe -hide_banner -show_streams -show_format chal.wav
soxi chal.wav
# canonical PCM for the rest of the toolchain
ffmpeg -i chal.mp3 -acodec pcm_s16le -ar 44100 canon.wav
# reverse / slow / pitch
sox chal.wav rev.wav reverse
ffmpeg -i chal.wav -af areverse rev.wav
sox chal.wav slow.wav tempo 0.5
sox chal.wav pitched.wav pitch -500
# channel arithmetic
sox chal.wav -c 1 diff.wav remix 1v1,2v-1
ffmpeg -i chal.wav -af "pan=mono|c0=c0-c1" diff.wav
# tone decoding
multimon-ng -a DTMF -a MORSE_CW -a AFSK1200 -t wav chal.wav
# steghide on WAV/AU
steghide info -p '' chal.wav
stegseek chal.wav rockyou.txt
# DeepSound signature
strings -n 4 chal.wav | grep -i dscf
```

## Video

```bash
ffprobe -hide_banner -show_format -show_streams -show_chapters chal.mp4
# frames, lossless, no frame-rate resampling
ffmpeg -i chal.mp4 -vsync 0 frames/%06d.png
# keyframes only
ffmpeg -i chal.mp4 -vf "select=eq(pict_type\,I)" -vsync 0 key/%04d.png
# one frame at a timestamp
ffmpeg -ss 00:00:07.25 -i chal.mp4 -frames:v 1 f.png
# contact sheet
ffmpeg -i chal.mp4 -vf "select=not(mod(n\,30)),scale=320:-1,tile=10x10" -vsync 0 sheet.png
# frame differencing
ffmpeg -i chal.mp4 -vf "tblend=all_mode=difference,eq=contrast=10" -vsync 0 diff/%06d.png
# audio track out
ffmpeg -i chal.mp4 -vn -acodec pcm_s16le -ar 44100 audio.wav
# subtitles and attachments
ffmpeg -i chal.mkv -map 0:s:0 subs.srt
ffmpeg -dump_attachment:t "" -i chal.mkv
mkvinfo chal.mkv; mkvextract tracks chal.mkv 2:subs.srt
MP4Box -info chal.mp4
```

## GIF / animation

```bash
convert chal.gif -coalesce frames/%03d.png
gifsicle --explode chal.gif
gifsicle --info chal.gif
identify -verbose chal.gif | grep -E 'Delay|Dispose|Scene|Geometry'
exiftool -Comment chal.gif
ffmpeg -i chal.gif -vsync 0 f/%04d.png
```

## Text / unicode

```bash
cat -A chal.txt | head -40
grep -nP '[ \t]+$' chal.txt
LC_ALL=C grep -n '[^ -~\t]' chal.txt
xxd chal.txt | grep -E 'e280 8[bcd]|efbb bf|e280 ae|c2ad'
uniname chal.txt | head -40
stegsnow -C chal.txt
stegsnow -C -p password chal.txt
python3 -c "d=open('c.txt',encoding='utf-8').read();print([hex(ord(c)) for c in d if ord(c)>127][:40])"
```

## QR / barcode

```bash
zbarimg --raw -q chal.png
zbarimg --raw -q --set '*.enable=1' chal.png
dmtxread chal.png                                   # Data Matrix
python3 -c "import cv2;print(cv2.QRCodeDetector().detectAndDecode(cv2.imread('chal.png'))[0])"
# repair attempts
convert chal.png -negate inv.png
convert chal.png -bordercolor white -border 40 pad.png
convert chal.png -resize 800x800 -filter point big.png
convert chal.png -colorspace Gray -threshold 50% bw.png
convert chal.png -rotate 90 r90.png
convert chal.png -flop mirror.png
montage p1.png p2.png p3.png p4.png -tile 2x2 -geometry +0+0 joined.png
```

## Archives

```bash
7z l -slt chal.zip | grep -E 'Method|Encrypted'
zipdetails -v chal.zip | head -60
unzip -t chal.zip
unzip -P password chal.zip
# ZipCrypto known plaintext (no password needed)
bkcrack -L chal.zip
bkcrack -C chal.zip -c secret.txt -p plain.bin
bkcrack -C chal.zip -c secret.txt -p plain.bin -o 100
bkcrack -C chal.zip -c secret.txt -x 0 504b0304
bkcrack -C chal.zip -c secret.txt -k K0 K1 K2 -d out.bin
bkcrack -C chal.zip -k K0 K1 K2 -U cracked.zip newpass
bkcrack -k K0 K1 K2 -r 10 '?p'
# password cracking
zip2john chal.zip > h.txt && john --wordlist=rockyou.txt h.txt && john --show h.txt
rar2john chal.rar > h.txt; 7z2john.pl chal.7z > h.txt
hashcat -m 13600 h.txt rockyou.txt        # WinZip AES
hashcat -m 17200 h.txt rockyou.txt        # PKZIP compressed
hashcat -m 12500 h.txt rockyou.txt        # RAR3
hashcat -m 13000 h.txt rockyou.txt        # RAR5
hashcat -m 11600 h.txt rockyou.txt        # 7-Zip
fcrackzip -u -D -p rockyou.txt chal.zip
# repair
zip -FF broken.zip --out fixed.zip
zip -F broken.zip --out fixed.zip
7z x -y broken.zip
```

## Password brute forcing stego tools

```bash
stegseek --crack -f chal.jpg /usr/share/wordlists/rockyou.txt out.bin
stegseek chal.jpg rockyou.txt
stegcracker chal.jpg rockyou.txt
for p in $(cat words.txt); do steghide extract -sf chal.jpg -p "$p" -xf out.bin -f 2>/dev/null \
  && echo "HIT $p" && break; done
openstego extract -sf chal.png -p password -xd out/
jpseek chal.jpg out.bin
# build a challenge-specific wordlist
strings -n 4 chal.jpg | sort -u > words.txt
cewl -d 2 -m 4 -w site_words.txt https://target/
john --wordlist=words.txt --rules=Jumbo --stdout > mangled.txt
crunch 6 6 -t flag%% -o pat.txt
```

## Image comparison (two-file challenges)

```bash
compare -metric AE a.png b.png diff.png
convert a.png b.png -compose difference -composite -auto-level diff.png
convert a.png b.png -compose difference -composite -threshold 0 mask.png
python3 -c "
from PIL import Image, ImageChops
a=Image.open('a.png'); b=Image.open('b.png')
d=ImageChops.difference(a.convert('RGB'), b.convert('RGB'))
print(d.getbbox()); d.point(lambda v: 255 if v else 0).save('diff.png')"
```

## Quick checks worth running on anything

```bash
file chal; xxd chal | head; xxd chal | tail
strings -n 8 chal | grep -aiE 'flag|ctf\{|key'
binwalk chal; exiftool -a -u -g1 chal
base64 -d <<< "$(strings chal | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | head -1)" | file -
# does it decompress?
python3 -c "import zlib;print(zlib.decompress(open('chal','rb').read())[:200])"
python3 -c "import gzip;print(gzip.decompress(open('chal','rb').read())[:200])"
# is it a repeated-XOR ciphertext?
python3 -c "
d=open('chal','rb').read()
for k in range(1,256):
    x=bytes(b^k for b in d[:64])
    if sum(32<=c<127 for c in x)>60: print(k, x[:64])"
```

## Tool install quick reference

```bash
# debian/ubuntu
sudo apt install -y exiftool binwalk foremost pngcheck steghide outguess sox ffmpeg \
     zbar-tools imagemagick gifsicle mkvtoolnix libimage-exiftool-perl john
# ruby gem
gem install zsteg
# stegseek (release binary, .deb)
# stegoveritas
pip install stegoveritas && stegoveritas_install_deps
# bkcrack (build from source with cmake)
# stegsolve is a single stegsolve.jar, run with: java -jar stegsolve.jar
```
