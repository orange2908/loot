---
title: "Forensics Triage Cheatsheet - I Was Given a File of Type X"
category: forensics
subcategory: triage
type: cheatsheet
tags: [triage, forensics, pcap, memory-dump, disk-image, unknown-file, archive, document, image, binwalk, file, strings, exiftool, volatility3, tshark, sleuthkit, dfir]
summary: "Ordered first-20-minutes command list for every forensics input type, with a fallback for when the obvious pass finds nothing."
tools: [file, binwalk, strings, exiftool, volatility3, tshark, sleuthkit, oletools, bulk-extractor, plaso]
related: [file-magic-bytes, windows-artifacts-cheatsheet, volatility-cheatsheet, tshark-wireshark-cheatsheet, disk-forensics-cheatsheet]
---

## You were given: an unknown blob with no extension
```bash
# 1. Identify the container before doing anything else
file -k blob && xxd -l 64 blob
# 2. Scan every offset for embedded signatures, not just offset 0
binwalk blob
# 3. Extract everything binwalk recognised, recursively
binwalk -Me blob
# 4. Entropy profile: flat high entropy means encrypted or compressed
binwalk -E blob
# 5. Pull printable strings in ASCII and both UTF-16 endians at once
strings -a blob; strings -el blob; strings -eb blob
```
Fallback: run `bulk_extractor -o bx blob`, then `foremost -i blob -o carved/` and treat every carved file as a new unknown blob.

## You were given: a PCAP or PCAPNG
```bash
# 1. Protocol breakdown tells you which analysis path to take
capinfos capture.pcapng && tshark -r capture.pcapng -q -z io,phs
# 2. Conversations sorted by bytes - the exfil channel is usually the biggest
tshark -r capture.pcapng -q -z conv,tcp
# 3. Carve every transferred object out of HTTP, SMB, TFTP and FTP-DATA
for p in http smb tftp ftp-data imf; do tshark -r capture.pcapng --export-objects $p,obj_$p; done
# 4. Follow a specific stream once you know its index
tshark -r capture.pcapng -q -z follow,tcp,ascii,0
# 5. Grep the raw bytes for flag-shaped text across all packets
strings -a capture.pcapng | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
```
Fallback: check DNS TXT and subdomain labels (`tshark -r f -Y dns -T fields -e dns.qry.name`), ICMP payloads, and USB HID data (`usb.capdata`) for covert channels.

## You were given: a memory dump
```bash
# 1. Confirm it is really RAM and which OS it came from
file mem.raw && strings -a mem.raw | grep -m5 -iE 'linux version|windows nt'
# 2. Process tree first - parent/child anomalies jump out immediately
vol3 -f mem.raw windows.pstree
# 3. Command lines reveal downloaders, encoded PowerShell and the flag itself
vol3 -f mem.raw windows.cmdline
# 4. Network sockets tie processes to C2 addresses
vol3 -f mem.raw windows.netscan
# 5. Injected or unbacked executable memory is where shellcode hides
vol3 -f mem.raw windows.malfind --dump
```
Fallback: `vol3 -f mem.raw windows.filescan | grep -i flag`, then `windows.dumpfiles --virtaddr`; for Linux use `vol3 -f mem.raw banners.Banners` to pick the right symbol table first.

## You were given: a disk image
```bash
# 1. Partition layout and the sector offsets you will need for every later command
mmls disk.raw && fsstat -o 2048 disk.raw
# 2. Full file listing including deleted entries, marked with an asterisk
fls -r -p -o 2048 disk.raw | head -100
# 3. Build a MAC-time timeline of the whole volume
fls -r -m C: -o 2048 disk.raw > body && mactime -b body -d -z UTC > timeline.csv
# 4. Mount read-only to browse normally, with NTFS system files exposed
mount -o ro,loop,offset=$((2048*512)),show_sys_files disk.raw /mnt/img
# 5. Recover deleted content from unallocated space
tsk_recover -o 2048 -e disk.raw recovered/
```
Fallback: `strings -a disk.raw | grep -aoE 'flag\{[^}]+\}'` over raw unallocated space, then `photorec` and `bulk_extractor` on the whole image.

## You were given: an archive (zip/rar/7z/tar)
```bash
# 1. List contents without extracting - catches path traversal and huge ratios
7z l -slt archive.zip
# 2. Compare compressed vs uncompressed totals to spot a zip bomb before extracting
unzip -l archive.zip | tail -3
# 3. Extract into a dedicated directory so a bomb or ../ cannot escape
mkdir -p ex && 7z x -oex -y archive.zip
# 4. Check whether it is encrypted, and whether only data or also filenames
7z l -slt archive.zip | grep -i encrypted
# 5. Crack the password with a wordlist if it is protected
zip2john archive.zip > h.txt && john --wordlist=rockyou.txt h.txt
```
Fallback: look for extra data after the end-of-central-directory (`binwalk archive.zip`), try `zip -FF` on a truncated archive, and test known-plaintext with `bkcrack` for legacy ZipCrypto.

## You were given: an Office document
```bash
# 1. Is it OLE2 or OOXML - it decides every following tool
file doc.docx && oleid doc.docx
# 2. Dump and deobfuscate VBA macros in one pass
olevba --decode --deobf doc.docx
# 3. List streams and embedded objects in an OLE2 container
oledump.py doc.doc
# 4. OOXML is a zip: unpack it and read the XML and relationships directly
mkdir x && (cd x && unzip -o ../doc.docx) && grep -ria 'http\|cmd\|powershell' x/
```
Fallback: check `docProps/app.xml` and `core.xml` for author and template paths, look for remote-template injection in `word/_rels/settings.xml.rels`, and run `rtfobj` if it is really an RTF.

## You were given: a PDF
```bash
# 1. Object and keyword census - /JS, /OpenAction and /Launch are the red flags
pdfid.py suspicious.pdf
# 2. Search objects by keyword and decompress the stream you care about
pdf-parser.py --search JavaScript --raw suspicious.pdf
# 3. Extract all embedded files and images
pdfdetach -saveall suspicious.pdf && pdfimages -all suspicious.pdf img
# 4. Text layer, preserving layout, which often holds white-on-white text
pdftotext -layout suspicious.pdf - | less
```
Fallback: `qpdf --qdf --object-streams=disable in.pdf out.pdf` to expand every stream, then grep the result; multiple `%%EOF` markers mean earlier revisions with removed content.

## You were given: an image (png/jpg/gif)
```bash
# 1. Metadata first - GPS, comments and thumbnails solve many challenges outright
exiftool -a -u -g1 pic.png
# 2. Structural validation catches appended data and broken chunk lengths
pngcheck -v pic.png
# 3. Look for appended archives or a second image inside
binwalk -Me pic.png
# 4. LSB, colour-plane and stereogram views in one automated sweep
zsteg -a pic.png || stegoveritas pic.jpg
```
Fallback: for JPEG try `steghide extract -sf pic.jpg` with an empty and a guessed passphrase, `stegseek pic.jpg rockyou.txt`, and compare against the original if one is provided.

## You were given: an audio file
```bash
# 1. Container, codec, duration and any tags
ffprobe -hide_banner -show_format -show_streams song.wav
# 2. Metadata and embedded artwork
exiftool -a -u song.wav && ffmpeg -i song.wav -an -vcodec copy art.jpg
# 3. Spectrogram - hidden text is usually visible as drawn pixels
sox song.wav -n spectrogram -o spec.png -x 2000 -y 800
# 4. LSB extraction from PCM samples
python3 -c "import wave;w=wave.open('song.wav');d=w.readframes(w.getnframes());print(bytes(int(''.join(str(b&1) for b in d[i:i+8]),2) for i in range(0,len(d)-8,8))[:200])"
```
Fallback: decode DTMF or SSTV with `multimon-ng -a DTMF -t wav song.wav` and `qsstv`, check for a second channel (`ffmpeg -af channelsplit`), and inspect slowed or reversed playback.

## You were given: a video file
```bash
# 1. Streams, codecs and any extra data tracks
ffprobe -hide_banner -show_streams clip.mp4
# 2. Container metadata, including subtitle and attachment tracks
exiftool -a -u clip.mp4 && mkvinfo clip.mkv
# 3. Split into frames so you can grep or eyeball individual images
ffmpeg -i clip.mp4 -vsync 0 frames/%06d.png
# 4. Extract every attachment and subtitle stream
ffmpeg -i clip.mkv -map 0:s -c copy subs.srt && mkvextract attachments clip.mkv 1:att.bin
```
Fallback: `binwalk -Me clip.mp4` for appended payloads, check the audio track separately as an audio challenge, and look for an oversized `mdat` atom relative to the frame count.

## You were given: an executable (PE/ELF/Mach-O) as an artefact
```bash
# 1. Format, architecture, linkage and build id
file bin.exe && rabin2 -I bin.exe
# 2. Hashes for reputation lookup and to match against Amcache or Prefetch
sha256sum bin.exe && ssdeep bin.exe
# 3. Imports, sections and overlay - a fat overlay means an embedded payload
rabin2 -i bin.exe && rabin2 -S bin.exe
# 4. Compile timestamp, version resources and any signature
exiftool bin.exe && osslsigncode verify bin.exe
```
Fallback: `capa bin.exe` for behaviour, `floss bin.exe` for stack and obfuscated strings, and `binwalk -Me` to pull a packed second stage out of the overlay.

## You were given: a SQLite database
```bash
# 1. Schema tells you what the application stored and where to look
sqlite3 db.sqlite '.schema'
# 2. Always grab the -wal and -shm files: uncommitted rows live there
ls -l db.sqlite* && sqlite3 db.sqlite 'PRAGMA wal_checkpoint(FULL);'
# 3. Dump every table to text in one pass for grepping
sqlite3 db.sqlite .dump > dump.sql && grep -iE 'flag|passw|token' dump.sql
# 4. Recover deleted records from freelist pages and unallocated space
strings -a db.sqlite | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
```
Fallback: run `sqlite3 db.sqlite 'PRAGMA integrity_check;'`, carve with `undark -i db.sqlite -f` or `sqlparse`, and remember Chrome/Firefox timestamps need epoch conversion.

## You were given: a log file bundle
```bash
# 1. Inventory: what logs exist, how big, and what time range they cover
find . -type f -printf '%s\t%p\n' | sort -rn | head -30
# 2. Normalise every compressed and plain log into one grep-able stream
zgrep -ah '' $(find . -type f) > all.log
# 3. Hunt the obvious indicators before building any timeline
grep -aiE 'flag\{|base64 |curl |wget |powershell|/etc/passwd|union select' all.log
# 4. Frequency analysis - the rarest source IP or user agent is usually the answer
awk '{print $1}' all.log | sort | uniq -c | sort -n | head -20
```
Fallback: feed the directory to `log2timeline.py --storage-file case.plaso .` and sort with `psort.py`, and check for rotated or truncated files with gaps in their timestamps.

## You were given: an EVTX bundle
```bash
# 1. Which logs exist and which are non-empty
ls -lS *.evtx && for f in *.evtx; do echo "$f $(evtx_dump -o jsonl "$f" | wc -l)"; done
# 2. Sigma-based hunt across the whole directory in one command
chainsaw hunt . -s ./sigma --mapping ./mappings/sigma-event-logs-all.yml --csv -o out
# 3. Normalised timeline with detections flagged
hayabusa csv-timeline -d . -o timeline.csv
# 4. Pull the high-value event IDs directly when you already know the question
EvtxECmd.exe -d . --inc 4624,4625,4688,4697,7045,1102,4104 --csv out
```
Fallback: `evtx_dump -o jsonl Security.evtx | jq -r '.Event.EventData.CommandLine'`, and remember 1102/104 mean the log was cleared, so pivot to Prefetch, SRUM and the MFT instead.

## You were given: an email (.eml/.msg/.pst)
```bash
# 1. Headers in order - Received chain, SPF/DKIM results and the real origin IP
formail -X '' < mail.eml | head -60
# 2. Decode and save every MIME part including attachments
munpack -f mail.eml || python3 -c "import email,sys;[open(p.get_filename() or 'part.bin','wb').write(p.get_payload(decode=True) or b'') for p in email.message_from_file(open('mail.eml')).walk() if p.get_payload(decode=True)]"
# 3. MSG files are OLE2 containers, so use the OLE tooling
msgconvert mail.msg && oledump.py mail.msg
# 4. Explode a PST/OST into per-message files you can grep
readpst -D -o out/ archive.pst && grep -ril 'flag{' out/
```
Fallback: base64-decode every part by hand (`grep -A999 'base64' mail.eml | base64 -d`), check `X-Originating-IP` and `Thread-Index`, and scan attachments as their own file type.

## You were given: a registry hive
```bash
# 1. Confirm it is a hive and whether dirty transaction logs must be replayed first
file NTUSER.DAT && ls -l NTUSER.DAT.LOG*
# 2. Replay the logs so you are not parsing a stale hive
rla.exe -d . --out clean/
# 3. Run the full plugin profile for that hive type
rip.pl -r ./clean/NTUSER.DAT -f ntuser > ntuser.txt
# 4. Free-text search across every key and value for your indicator
RECmd.exe -f ./clean/NTUSER.DAT --sd 'flag' --csv out
```
Fallback: `reglookup -H hive | grep -i <term>` for deleted-key remnants, and carve unallocated hive space with `regipy` or `strings -el hive`.

## You were given: a Docker image or container export
```bash
# 1. A saved image is a tar of layers plus a manifest
tar -tf image.tar | head -20 && mkdir img && tar -xf image.tar -C img
# 2. Layer history often contains the secret that a later layer deleted
jq -r '.[0].history[].created_by' img/*.json 2>/dev/null || cat img/manifest.json
# 3. Unpack every layer in order into one filesystem view
for l in img/*/layer.tar; do tar -xf "$l" -C rootfs/ 2>/dev/null; done
# 4. Search the merged rootfs and every individual layer for credentials
grep -rilE 'flag\{|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}' rootfs/ img/
```
Fallback: use `dive image.tar` or `docker save` plus `whiteout` files (`.wh.*`) to find deleted paths, and check `/root/.bash_history` and image ENV for leftovers.

## You were given: a git repository or .git directory
```bash
# 1. Full history including branches, tags and dangling commits
git log --all --oneline --graph --decorate | head -50
# 2. Secrets are almost always in a deleted file from an old commit
git log --all --diff-filter=D --name-only | head -50
# 3. Search the entire history, not just the working tree
git grep -iIE 'flag\{|password|api[_-]?key' $(git rev-list --all) | head -40
# 4. Unreachable objects survive a rebase or a force push
git fsck --lost-found --unreachable && git cat-file -p <oid>
```
Fallback: if only `.git` was given, run `git checkout -- .` to materialise the tree, or `git-dumper` for a remote one; inspect `.git/packed-refs`, `logs/HEAD` reflog and `ORIG_HEAD`.

## You were given: a filesystem directory dump (KAPE/triage collection)
```bash
# 1. Map the collection layout and confirm which artefact classes are present
find . -maxdepth 4 -type d | head -40
# 2. Run the whole Eric Zimmerman parser set over the collection
kape.exe --msource . --mdest parsed --module !EZParser --mflush
# 3. Or build one super timeline with plaso if you are on Linux
log2timeline.py --storage-file case.plaso . && psort.py -o dynamic -w super.csv case.plaso
# 4. Start from execution evidence: Prefetch, Amcache, ShimCache, BAM
PECmd.exe -d ./Windows/Prefetch -q --csv parsed --csvf pf.csv
```
Fallback: grep the whole collection for your indicator in both encodings (`grep -ari` plus `strings -el`), and check `$MFT`/`$J` if the collector included them.

## You were given: a mobile backup (Android adb or iOS)
```bash
# 1. Android adb backups are a 24-byte header plus a zlib stream, not a plain tar
dd if=backup.ab bs=24 skip=1 | zlib-flate -uncompress > backup.tar && tar -tf backup.tar
# 2. iOS backups use hashed filenames indexed by a SQLite manifest
sqlite3 Manifest.db 'select fileID, domain, relativePath from Files limit 40;'
# 3. Rebuild readable paths from an iOS backup automatically
idevicebackup2 unback . 2>/dev/null || plistutil -i Info.plist
# 4. The payload is almost always app SQLite databases and plists
find . -name '*.sqlite*' -o -name '*.db' -o -name '*.plist' | head -40
```
Fallback: convert binary plists with `plistutil -i f.plist`, check `WhatsApp/msgstore.db` style app stores, and look in `apps/*/sp/` for shared preferences XML.

## You were given: a virtual machine image (.vmdk/.ova/.vbox/.qcow2)
```bash
# 1. An OVA is just a tar: unpack it to get the OVF descriptor and the disks
tar -xvf vm.ova && cat *.ovf | head -40
# 2. Identify the disk format and whether it is split, sparse or a snapshot chain
qemu-img info vm.vmdk
# 3. Convert to raw so every Sleuthkit and carving tool works normally
qemu-img convert -O raw vm.vmdk vm.raw && mmls vm.raw
# 4. Do not skip the memory and snapshot files - they are a free RAM dump
ls -l *.vmem *.vmsn *.vmss *.sav
```
Fallback: mount without converting using `guestmount -a vm.qcow2 -i --ro /mnt/vm`, and check snapshot deltas (`*-00000N.vmdk`) which may hold the pre-cleanup state.

## You were given: a firmware blob
```bash
# 1. Signature scan across the whole image reveals headers, filesystems and keys
binwalk firmware.bin
# 2. Entropy map separates the compressed rootfs from the plain bootloader
binwalk -E firmware.bin
# 3. Recursive extraction unpacks squashfs, jffs2, cramfs and nested archives
binwalk -Me firmware.bin
# 4. Search the extracted rootfs for credentials, keys and startup scripts
grep -riE 'password|BEGIN .*PRIVATE KEY|telnetd|/etc/shadow' _firmware.bin.extracted/
```
Fallback: if binwalk finds nothing, check for a non-zero base offset or XOR/byte-swapped image (`binwalk --raw` after `dd conv=swab`), and try `ubireader_extract_images` or `unblob firmware.bin`.

## Universal first four commands
```bash
# 1. What is it, really
file -k target && xxd -l 64 target
# 2. Flag-shaped strings in ASCII and UTF-16, the single highest-yield command
strings -a target | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'; strings -el target | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
# 3. Anything embedded at any offset
binwalk -Me target
# 4. Every metadata tag including unknown and duplicated ones
exiftool -a -u -g1 target
```

## Flag-shaped greps
```bash
# Plain ASCII, the standard CTF flag format
grep -aoE 'flag\{[^}]+\}' target
# Any prefix, case-insensitive, bounded length so you do not match whole files
grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}' target
# UTF-16LE, which is how Windows and .NET store strings
strings -el target | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
# UTF-16BE, for Java and some network protocols
strings -eb target | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
# Base64 of the literal prefix, all three alignments of "flag{"
grep -aoE 'Zmxh[Zz]|ZseW|mbGFn|ZmxhZ3' target
# Hex encoding of "flag{" in both cases
grep -aoiE '666c61677b[0-9a-f]+7d' target
# ROT13 of the prefix, the classic "sync" variant
grep -aoiE 'synt\{[^}]+\}' target
# Decode every base64-looking run and re-grep the result
grep -aoE '[A-Za-z0-9+/]{20,}={0,2}' target | while read -r b; do echo "$b" | base64 -d 2>/dev/null; done | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
```

## When you are stuck
```text
1.  Did you re-run `file -k` and `binwalk` on every extracted child file, recursively?
2.  Did you search UTF-16LE and UTF-16BE, not just ASCII?
3.  Did you check the bytes AFTER the format's footer (IEND, %%EOF, 0x3B, EOCD)?
4.  Did you check slack and unallocated space, not just allocated files?
5.  Is the header corrupted on purpose? Compare bytes 0..15 against the signature table.
6.  Are there timestamps that are impossible, identical, or out of order?
7.  Did you diff against a clean original of the same file if one was provided?
8.  Did you look in the -wal, -shm, .LOG1, .LOG2 and journal sidecar files?
9.  Did you convert every timestamp to the same timezone before building the timeline?
10. Is the answer metadata rather than content - author, GPS, printer, template path?
11. Did you try the challenge name, author name and empty string as a stego passphrase?
12. Did you re-read the challenge description for the format hint you skimmed past?
```
