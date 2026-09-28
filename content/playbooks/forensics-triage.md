---
title: "Playbook - Forensics Triage: pcap, Memory, Disk, Documents"
category: forensics
subcategory: triage
type: playbook
tags: [forensics-triage, where-to-start, stuck, pcap, wireshark, tshark, memory-dump, volatility3, disk-image, autopsy, sleuthkit, maldoc, pdf, office-macro, carving, timeline, mft, registry, evtx, usb-traffic]
summary: "Four branches by artifact type: pcap, memory image, disk image, or a document. Each ends in a concrete extraction command."
when_to_use:
  - "You were given a .pcap/.pcapng and need to find what was exfiltrated"
  - "You were given a memory dump (.raw/.mem/.vmem/.dmp)"
  - "You were given a disk image (.dd/.e01/.img/.vmdk)"
  - "You were given an office document, PDF, or email and suspect it is malicious"
related: [unknown-file, wireshark-tshark, volatility3, binwalk, exiftool, stego-triage]
---

## TL;DR - identify the artifact

```sh
file evidence.*
```
| `file` says | Branch |
|---|---|
| `pcap capture file` / `pcapng` | [Section 1](#section-1--pcap) |
| `data` + several GB + you were told "memory" | [Section 2](#section-2--memory-dump) |
| `DOS/MBR boot sector`, `EWF/Expert Witness`, `QEMU QCOW`, `VMDK` | [Section 3](#section-3--disk-image) |
| `PDF document`, `Microsoft Word/Excel`, `Composite Document File`, `RFC 822 mail` | [Section 4](#section-4--documents-and-email) |
| An image/audio file | `ctfbrain search stego-triage` |
| Windows event logs (`.evtx`), registry hives (`SYSTEM`,`NTUSER.DAT`) | [Section 3.4](#34-windows-artefacts) |
| Something else | `ctfbrain search unknown-file` |

---

## Section 1 - pcap

### 1.1 The 60-second sweep (run all of these)

```sh
PCAP=capture.pcap

# What protocols are in here, and in what volume? This alone often names the challenge.
tshark -r "$PCAP" -q -z io,phs

# Who talked to whom, how much.
tshark -r "$PCAP" -q -z conv,tcp | head -30
tshark -r "$PCAP" -q -z conv,udp | head -30

# Every URL requested.
tshark -r "$PCAP" -Y http.request -T fields -e http.host -e http.request.uri | sort -u

# Every DNS name queried (exfil hides here).
tshark -r "$PCAP" -Y dns.flags.response==0 -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -40

# Any plaintext credentials.
tshark -r "$PCAP" -Y 'http.authorization or ftp.request.command=="PASS" or telnet or pop or imap' -T fields -e frame.number -e _ws.col.Info

# Pull every transferred file out automatically.
tshark -r "$PCAP" --export-objects http,out_http/
tshark -r "$PCAP" --export-objects smb,out_smb/
tshark -r "$PCAP" --export-objects tftp,out_tftp/
tshark -r "$PCAP" --export-objects imf,out_mail/
foremost -i "$PCAP" -o out_carved/

# Brute-force string search across the payloads.
strings -a "$PCAP" | grep -aiE 'flag\{|ctf\{|password|BEGIN (RSA|OPENSSH)|eyJ'
```

### 1.2 Branch by dominant protocol

| Dominant protocol | What the challenge is | Command |
|---|---|---|
| HTTP (plain) | a file transfer, a webshell session, or credentials | Wireshark -> Follow HTTP Stream; `--export-objects http` |
| HTTPS/TLS | you need the key. Look for a `sslkeylog.txt`/`.log` in the handout, or an RSA private key | `tshark -r f -o tls.keylog_file:keys.log -Y http2` ; `ctfbrain search tls-decryption` |
| DNS (many long subdomains) | DNS exfiltration: the data is in the labels | decode below |
| ICMP (large or varying payloads) | ICMP tunnelling: data in the payload | `tshark -r f -Y icmp -T fields -e data.data` |
| FTP / FTP-DATA | credentials in FTP, file in FTP-DATA | Follow TCP Stream on the data port |
| SMB / SMB2 | file transfer, hash capture (NTLMv2) | `--export-objects smb`; `ctfbrain search ntlm-relay` |
| Telnet | the whole session is plaintext | Follow TCP Stream |
| USB (URB) | keystrokes or mass storage | section 1.4 |
| TCP on a weird port, binary | a custom protocol or a reverse shell | Follow Stream, then reverse the protocol |
| Modbus / S7 / DNP3 | ICS challenge | `tshark -Y modbus` |
| IEEE 802.11 with EAPOL | WPA handshake -> crack it | `aircrack-ng -w rockyou.txt f.pcap` |
| Bluetooth / Zigbee | a wireless capture | `ctfbrain search wireless-forensics` |
| QUIC / HTTP3 | encrypted; needs keys the same way TLS does | look for a keylog file in the handout |
| Lots of RST/SYN to many ports | a port scan; the payload is elsewhere in the capture | `tshark -r f -Y 'tcp.flags.syn==1 and tcp.flags.ack==1'` |

### 1.3 DNS exfiltration decoder

```python
#!/usr/bin/env python3
"""Reassemble data hidden in DNS query labels."""
import base64, binascii, subprocess, sys

pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
out = subprocess.run(
    ["tshark", "-r", pcap, "-Y", "dns.flags.response==0",
     "-T", "fields", "-e", "dns.qry.name"],
    capture_output=True, text=True).stdout

labels, seen = [], set()
for line in out.splitlines():
    if line in seen:
        continue
    seen.add(line)
    labels.append(line.split(".")[0])

blob = "".join(labels)
print("raw:", blob[:200])
for name, fn in (("hex", binascii.unhexlify),
                 ("b32", lambda s: base64.b32decode(s.upper() + "=" * (-len(s) % 8))),
                 ("b64", lambda s: base64.b64decode(s + "=" * (-len(s) % 4)))):
    try:
        print(name, fn(blob)[:400])
    except Exception as e:
        print(name, "failed:", e)
```

### 1.4 USB traffic

```sh
# Keyboard: the HID usage codes are in the 8-byte capture data, byte 2 is the keycode
tshark -r usb.pcap -Y 'usb.capdata and usb.transfer_type==0x01' -T fields -e usb.capdata > keys.txt
```
```python
#!/usr/bin/env python3
"""Decode USB HID keyboard capdata (from tshark -e usb.capdata) into text."""
HID = {
    4:"a",5:"b",6:"c",7:"d",8:"e",9:"f",10:"g",11:"h",12:"i",13:"j",14:"k",15:"l",
    16:"m",17:"n",18:"o",19:"p",20:"q",21:"r",22:"s",23:"t",24:"u",25:"v",26:"w",
    27:"x",28:"y",29:"z",30:"1",31:"2",32:"3",33:"4",34:"5",35:"6",36:"7",37:"8",
    38:"9",39:"0",40:"\n",41:"[ESC]",42:"[BS]",43:"\t",44:" ",45:"-",46:"=",47:"[",
    48:"]",49:"\\",51:";",52:"'",53:"`",54:",",55:".",56:"/",
}
SHIFT = {"1":"!","2":"@","3":"#","4":"$","5":"%","6":"^","7":"&","8":"*","9":"(",
         "0":")","-":"_","=":"+","[":"{","]":"}","\\":"|",";":":","'":"\"",
         "`":"~",",":"<",".":">","/":"?"}

out = []
for line in open("keys.txt"):
    line = line.strip().replace(":", "")
    if len(line) < 6:
        continue
    b = bytes.fromhex(line)
    mod, code = b[0], b[2]
    if code == 0:
        continue
    ch = HID.get(code, "")
    if mod & 0x22:  # left or right shift
        ch = SHIFT.get(ch, ch.upper())
    out.append(ch)
print("".join(out))
```
Mouse traffic: plot the relative X/Y deltas cumulatively and the flag is drawn. USB mass storage: `--export-objects` will not work; carve with `binwalk`/`foremost` on the reassembled SCSI payloads.

### 1.5 Reassembling a stream by hand
```sh
# list streams, then dump one
tshark -r f.pcap -T fields -e tcp.stream | sort -un | tail -1
tshark -r f.pcap -q -z follow,tcp,raw,0 > stream0.hex
# in Wireshark: right-click -> Follow -> TCP Stream, set 'Show data as: Raw', Save As
```

---

## Section 2 - Memory dump

```sh
DUMP=mem.raw
# 1. Volatility 3 needs no profile. Confirm the OS.
vol3 -f "$DUMP" windows.info        # or linux.banner / mac.*
# 2. Processes: look for the odd one out (misspelled, wrong parent, unusual path)
vol3 -f "$DUMP" windows.pslist
vol3 -f "$DUMP" windows.pstree
vol3 -f "$DUMP" windows.psscan      # includes terminated/hidden
# 3. Network
vol3 -f "$DUMP" windows.netscan
# 4. Command lines - very often the flag or the answer is literally here
vol3 -f "$DUMP" windows.cmdline
# 5. Console history
vol3 -f "$DUMP" windows.consoles
# 6. Files present in memory
vol3 -f "$DUMP" windows.filescan | grep -iE 'flag|\.txt|\.png|desktop'
# 7. Dump one
vol3 -f "$DUMP" -o out/ windows.dumpfiles --virtaddr 0xXXXXXXXX
# 8. The blunt instrument that solves 30% of memory challenges
strings -a -e l "$DUMP" | grep -aiE 'flag\{|ctf\{' ; strings -a "$DUMP" | grep -aiE 'flag\{|ctf\{'
```

| Question asked | Plugin |
|---|---|
| What was the user doing? | `windows.cmdline`, `windows.consoles`, `windows.envars` |
| What malware ran? | `windows.malfind`, `windows.pstree`, `windows.dlllist`, `windows.ldrmodules` |
| What was on the clipboard? | `windows.clipboard` (vol2: `clipboard`) |
| What did they type? | `windows.consoles`, or carve the conhost process |
| Passwords / hashes | `windows.hashdump`, `windows.lsadump`, `windows.cachedump`; mimikatz output in memory |
| Registry values | `windows.registry.hivelist`, `windows.registry.printkey --key '...'` |
| What was on screen? | `windows.screenshot` (vol2 `screenshot`) |
| Injected code | `windows.malfind`, then dump and reverse the region |
| A browser session | carve the process memory and grep for URLs/cookies |
| Network connections | `windows.netscan`, `windows.netstat` |
| Truecrypt/Bitlocker key | `windows.truecryptmaster`, or `bulk_extractor` |
| Linux dump | `banners.Banners` first, then `linux.pslist`, `linux.bash`, `linux.proc.Maps` |

Getting a process's memory to reverse:
```sh
vol3 -f mem.raw -o out/ windows.memmap --pid 1234 --dump
vol3 -f mem.raw -o out/ windows.pslist --pid 1234 --dump   # the PE itself
```
Then `strings out/*.dmp | grep flag`, or carve with `binwalk -e`.

`bulk_extractor -o be/ mem.raw` extracts emails, URLs, credit cards, AES keys, and zip/jpeg fragments in one pass - run it in the background while you do the rest.

`ctfbrain search volatility3`

---

## Section 3 - Disk image

### 3.1 Identify and mount
```sh
IMG=disk.dd
# partition table
mmls "$IMG"
fdisk -l "$IMG"
# filesystem info for a partition starting at sector 2048
fsstat -o 2048 "$IMG"
# mount read-only (Linux)
sudo mount -o ro,loop,offset=$((2048*512)) "$IMG" /mnt/evidence
# E01 -> raw
ewfmount disk.E01 /mnt/ewf && ls /mnt/ewf
# VMDK/QCOW2 -> raw
qemu-img convert -O raw disk.vmdk disk.raw
```

### 3.2 Sleuthkit without mounting
```sh
fls -r -o 2048 "$IMG" | head -100              # recursive file list, * = deleted
fls -r -o 2048 "$IMG" | grep -i '^-/-\|\*'     # deleted entries
icat -o 2048 "$IMG" <inode> > recovered.bin    # extract by inode
tsk_recover -e -o 2048 "$IMG" out/             # extract everything, including deleted
```

### 3.3 Carving and searching
```sh
foremost -i "$IMG" -o carved/
photorec "$IMG"                                # interactive, best recovery rate
binwalk -e "$IMG"
bulk_extractor -o be/ "$IMG"
strings -a "$IMG" | grep -aiE 'flag\{|ctf\{|password'
# search unallocated space only
blkls -o 2048 "$IMG" > unalloc.raw && strings -a unalloc.raw | grep -i flag
```

### 3.4 Windows artefacts

| Artefact | Path in the image | Parser |
|---|---|---|
| Registry hives | `/Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY}` | `RegRipper (rip.pl)`, `python-registry`, `reglookup` |
| User hive | `/Users/<u>/NTUSER.DAT` | RegRipper; RunMRU, TypedPaths, RecentDocs, UserAssist |
| Event logs | `/Windows/System32/winevt/Logs/*.evtx` | `evtx_dump`, `python-evtx`, `chainsaw`, `hayabusa` |
| Prefetch | `/Windows/Prefetch/*.pf` | `PECmd`, `prefetch-parser` - proves execution |
| MFT | `$MFT` at the FS root | `analyzeMFT.py`, `MFTECmd` - full timeline |
| USN journal | `$Extend/$UsnJrnl:$J` | `MFTECmd -f` |
| Recycle bin | `/$Recycle.Bin/<SID>/$I*` | `rifiuti2` |
| Browser history | `/Users/<u>/AppData/**/History` (SQLite) | `sqlite3`, `hindsight` |
| LNK files | `/Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/` | `LECmd`, `pylnk` |
| Amcache | `/Windows/appcompat/Programs/Amcache.hve` | RegRipper |
| Scheduled tasks | `/Windows/System32/Tasks/` | read the XML |
| Hibernation/pagefile | `hiberfil.sys`, `pagefile.sys` | `hibr2bin`, `strings` |
| SAM hashes | SAM + SYSTEM | `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` |

Linux equivalents: `/var/log/auth.log`, `/var/log/wtmp` (`utmpdump`), `~/.bash_history`, `/etc/shadow`, `/etc/crontab`, `/var/spool/cron`, `/home/*/.ssh/`, `~/.viminfo`, `~/.local/share/recently-used.xbel`. See `ctfbrain search linux-useful-paths`.

### 3.5 Build a timeline
```sh
log2timeline.py --storage-file plaso.db "$IMG"
psort.py -o l2tcsv -w timeline.csv plaso.db
# or, MFT-only and much faster:
mactime -b bodyfile.txt -d > timeline.csv
```

---

## Section 4 - Documents and email

### 4.1 Office
```sh
# modern (.docx/.xlsx/.pptx) are ZIPs
unzip -o doc.docx -d doc_x/ && grep -rniE 'http|flag|script|cmd|powershell' doc_x/
# macros and embedded objects in either format
olevba -a doc.doc          # macro source + IOC summary
oleid doc.doc              # quick risk indicators
oledump.py doc.doc         # stream listing; then: oledump.py -s 8 -v doc.doc
msoffcrypto-tool -p '' enc.docx dec.docx   # remove a known/blank password
# DDE, external relationships, remote templates
grep -rn 'Target=' doc_x/word/_rels/
```
Look for: `AutoOpen`, `Document_Open`, `Shell`, `WScript`, `powershell -enc <base64>`, `CreateObject("MSXML2.XMLHTTP")`, a template injection URL in `settings.xml.rels`.

### 4.2 PDF
```sh
pdfinfo f.pdf
pdf-parser.py -a f.pdf              # object statistics
pdfid.py f.pdf                      # /JS /JavaScript /OpenAction /Launch /EmbeddedFile counts
pdf-parser.py -s JavaScript -f f.pdf
peepdf -i f.pdf                     # interactive analysis
pdfdetach -list f.pdf && pdfdetach -saveall f.pdf
pdftotext -layout f.pdf -            # hidden text behind images still extracts
qpdf --qdf --object-streams=disable f.pdf out.pdf && strings out.pdf | less
mutool draw -o page%d.png f.pdf     # render to see what is visible
exiftool f.pdf
binwalk -e f.pdf                    # appended files
```
Common tricks: text covered by a white/black rectangle (`pdftotext` reveals it), an attachment, metadata, a hidden layer (OCG), a font-based substitution cipher, a JavaScript payload.

### 4.3 Email
```sh
# .eml / .msg
python3 -c "
import email, sys
m = email.message_from_file(open(sys.argv[1]))
for k in ('From','To','Subject','Date','Received','Return-Path','Message-ID','X-Originating-IP'):
    for v in m.get_all(k) or []:
        print(k+':', v)
for part in m.walk():
    fn = part.get_filename()
    if fn:
        print('ATTACHMENT', fn, part.get_content_type())
        open(fn, 'wb').write(part.get_payload(decode=True))" mail.eml
msgconvert mail.msg                 # .msg -> .eml
```
Check: `Received:` chain for the true origin, SPF/DKIM results, `X-Originating-IP`, base64 attachments, and URLs in the HTML part.

---

## Section 5 - Universal fallbacks

```sh
# these solve a surprising share of forensics challenges regardless of type
strings -a -n 6 evidence | grep -aiE 'flag\{|ctf\{|key\{'
strings -a -e l evidence | grep -aiE 'flag\{'          # UTF-16LE (Windows)
binwalk -e evidence
foremost -i evidence -o out/
bulk_extractor -o be/ evidence
exiftool -a -u -G1 evidence
grep -aoE '[A-Za-z0-9+/]{40,}={0,2}' evidence | while read b; do echo "$b" | base64 -d 2>/dev/null | grep -ai flag; done
```

Still nothing: `ctfbrain search stuck`
