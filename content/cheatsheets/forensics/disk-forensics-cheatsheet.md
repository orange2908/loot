---
title: "Disk Forensics Cheatsheet - Sleuthkit, Mounting, Hashing, Carving"
category: forensics
subcategory: disk
type: cheatsheet
tags: [sleuthkit, tsk, mmls, fsstat, fls, icat, istat, tsk-recover, ewfmount, qemu-nbd, losetup, dislocker, bulk-extractor, foremost, mactime, autopsy, disk-image, e01, ntfs, dfir]
summary: "Identify, verify, mount, walk and carve a disk image: offset arithmetic, every Sleuthkit tool with real flags, container formats, BitLocker/LUKS, and carving."
tools: [sleuthkit, libewf, qemu-img, dislocker, cryptsetup, bulk-extractor, foremost, scalpel, photorec, testdisk, autopsy, plaso, ntfs-3g]
related: [disk-image-triage, disk-file-carving, disk-ntfs-mft, disk-hidden-data, disk-windows-registry, disk-linux-forensics]
---

Golden rule: never mount the evidence read-write and never work on the original. Hash first,
work on a copy, mount `ro,loop,noexec,nodev` or use Sleuthkit which never mounts at all.

## Image format identification

| Format | Magic / signature | Offset |
|---|---|---|
| raw / dd | none; MBR `55 AA` or GPT `EFI PART` | 0x1FE / 0x200 |
| EWF / E01 | `45 56 46 09 0D 0A FF 00` (`EVF\x09\r\n\xff\x00`) | 0 |
| Lx01 logical evidence | `4C 56 46 09 0D 0A FF 00` (`LVF...`) | 0 |
| Ex01 / EnCase7 | `45 56 46 32 0D 0A 81 00` (`EVF2`) | 0 |
| AFF (legacy) | `41 46 46 00` (`AFF\x00`) | 0 |
| AFF4 | `50 4B 03 04` (it is a ZIP container) | 0 |
| VMDK sparse | `4B 44 4D 56` (`KDMV`) | 0 |
| VMDK descriptor | `# Disk DescriptorFile` (plain text) | 0 |
| VDI | `<<< Oracle VM VirtualBox Disk Image >>>` | 0 |
| VHD | `conectix` | last 512 bytes |
| VHDX | `vhdxfile` | 0 |
| QCOW2 | `51 46 49 FB` (`QFI\xfb`) | 0 |
| NTFS volume | `NTFS    ` | 3 |
| FAT32 volume | `FAT32   ` | 82 |
| ext2/3/4 | `53 EF` superblock magic | 0x438 |
| APFS container | `NXSB` | 32 |
| HFS+ | `H+` (`HX` for HFSX) | 1024 |
| LUKS | `4C 55 4B 53 BA BE` (`LUKS\xba\xbe`) | 0 |
| BitLocker | `-FVE-FS-` | 3 |

```sh
# first question always: what is this file, and is it a container or a raw image
file -s image.dd && ls -lh image.dd
# read the first 64 bytes as hex+ascii to match against the table above
xxd -l 64 image.dd
# check the last 512 bytes for a VHD footer, which lives at the end not the start
tail -c 512 disk.vhd | xxd | head -3
# libewf tells you segment count, acquisition tool and stored hashes for an E01
ewfinfo evidence.E01
```

## Hashing and verification

```sh
# hash the image before touching it; keep this value in your notes
sha256sum image.dd | tee image.dd.sha256
# md5deep/hashdeep recursively hashes a directory tree into an audit file
hashdeep -r -c md5,sha256 /mnt/evidence > hashes.txt
# later, audit the same tree against that file and report added/changed/removed
hashdeep -r -a -k hashes.txt /mnt/evidence
# verify an E01 against the hashes libewf stored inside the container itself
ewfverify evidence.E01
# acquire a device into E01 with compression, chunked segments and both hashes
ewfacquire -t /evidence/case001 -f encase6 -c deflate:fast -S 2GiB -d sha1 /dev/sdb
# raw acquisition that survives bad sectors: pad errors with zeros, keep going
dd if=/dev/sdb of=image.dd bs=4M conv=noerror,sync status=progress
# ddrescue is strictly better than dd on failing media; the map file allows resume
ddrescue -d -r3 /dev/sdb image.dd rescue.map
# second ddrescue pass that only retries the bad areas recorded in the map
ddrescue -d -R -r5 /dev/sdb image.dd rescue.map
# confirm your working copy matches the original bit for bit
cmp image.dd working.dd && echo IDENTICAL
```

## Converting formats

```sh
# E01 to raw, the conversion that makes every other tool work
ewfexport -t image -f raw evidence.E01
# raw back into E01 (useful when a tool only accepts EWF)
ewfacquire -t evidence -f encase6 image.dd
# qemu-img converts between qcow2, vmdk, vdi, vhdx and raw in one command
qemu-img convert -p -O raw disk.qcow2 disk.raw
# inspect a virtual disk's format, virtual size and backing file chain first
qemu-img info disk.vmdk
# VMDK split into many extents: point qemu-img at the descriptor, not an extent
qemu-img convert -p -O raw vm.vmdk vm.raw
# VirtualBox's own converter, also handles VDI to raw
VBoxManage clonehd disk.vdi disk.raw --format RAW
```

## Partition and volume layout

```sh
# mmls is the first Sleuthkit command: partition table with START SECTORS you need
mmls image.dd
# force the partition scheme when autodetect fails (dos, gpt, mac, bsd, sun)
mmls -t gpt image.dd
# fdisk on the file shows the same table plus the sector size explicitly
fdisk -l image.dd
# gdisk shows GPT partition GUIDs and finds a damaged primary header
gdisk -l image.dd
# parted prints sizes in bytes, which removes all sector-size ambiguity
parted image.dd unit B print
# blkid identifies filesystem type and UUID of a partition device or image
blkid -p image.dd
# back up and restore the GPT when the partition table itself is damaged
sgdisk --backup=gpt.bin image.dd && sgdisk --load-backup=gpt.bin image.dd
# find filesystem boot sectors when the partition table is gone entirely
sigfind -t ntfs image.dd
```

## Offset arithmetic (worked example)

```sh
# 1) mmls prints slot, start, end, length, description - note Units are 512-byte sectors
mmls image.dd
#    Units are in 512-byte sectors
#    Slot  Start       End         Length      Description
#    002:  000000128   000206847   000206720   NTFS / exFAT (0x07)
#    003:  000206848   000976773    000769926  NTFS / exFAT (0x07)
# 2) byte offset = start sector * sector size; here 206848 * 512
echo $((206848 * 512))
#    105906176
# 3) every Sleuthkit tool takes that partition by SECTOR with -o
fsstat -o 206848 image.dd
# 4) mount takes the same partition by BYTE offset
mount -o ro,loop,offset=105906176,noexec,nodev image.dd /mnt/e
# 5) if the units line says 4096-byte sectors, multiply by 4096 instead
echo $((206848 * 4096))
# 6) losetup -P does the arithmetic for you and creates /dev/loop0p1, p2, ...
losetup -r -f -P --show image.dd
```

## Mounting read-only

```sh
# raw image, single filesystem with no partition table (a dd of one partition)
mount -o ro,loop,noexec,nodev image.dd /mnt/e
# raw image with a partition table: byte offset computed above
mount -o ro,loop,offset=105906176,noexec,nodev image.dd /mnt/e
# -r read-only, -f next free device, -P scan the partition table, --show print the name
losetup -r -f -P --show image.dd
# then mount the partition device the kernel created
mount -o ro,noexec,nodev /dev/loop0p2 /mnt/e
# always detach the loop device when finished or the next case inherits it
umount /mnt/e && losetup -d /dev/loop0
# kpartx is the device-mapper alternative when losetup -P is unavailable
kpartx -a -r -v image.dd && ls /dev/mapper/loop0p*
```

## Mounting container formats

```sh
# ewfmount exposes an E01 as a single raw file at /mnt/ewf/ewf1
mkdir -p /mnt/ewf && ewfmount evidence.E01 /mnt/ewf
# then treat that file exactly like a raw image
mmls /mnt/ewf/ewf1 && mount -o ro,loop,offset=105906176 /mnt/ewf/ewf1 /mnt/e
# affuse does the same for AFF containers
affuse evidence.aff /mnt/aff && ls /mnt/aff
# xmount converts on the fly and can present an image as a VDI/VMDK for booting
xmount --in ewf --out vmdk evidence.E01 /mnt/xmount
# qemu-nbd attaches a qcow2/vmdk/vhdx as a block device without converting it
modprobe nbd max_part=16 && qemu-nbd --read-only --connect=/dev/nbd0 disk.qcow2
# make the kernel read that device's partition table, then mount a partition
partx -av /dev/nbd0 && mount -o ro /dev/nbd0p2 /mnt/e
# disconnect the nbd device when done, or it stays locked
umount /mnt/e; qemu-nbd --disconnect /dev/nbd0
# guestmount mounts any libguestfs-supported image without root and without loop devices
guestmount -a disk.qcow2 -i --ro /mnt/e
```

## Encrypted volumes

```sh
# BitLocker: probe the volume and print which unlock methods it accepts
dislocker-metadata -V /dev/loop0p2
# unlock with a recovery key and expose a decrypted dislocker-file
dislocker -r -V /dev/loop0p2 -p123456-123456-123456-123456-123456-123456-123456-123456 -- /mnt/dis
# unlock with the user password instead of a recovery key
dislocker -r -V /dev/loop0p2 -u -- /mnt/dis
# then mount the decrypted virtual file as NTFS
mount -o ro,loop /mnt/dis/dislocker-file /mnt/e
# LUKS: dump the header to confirm cipher, key slots and PBKDF parameters
cryptsetup luksDump /dev/loop0p2
# open a LUKS container read-only and mount the mapped device
cryptsetup --readonly luksOpen /dev/loop0p2 case_luks && mount -o ro /dev/mapper/case_luks /mnt/e
# VeraCrypt/TrueCrypt volumes through cryptsetup, including the hidden volume
cryptsetup --veracrypt --type tcrypt --readonly open container.tc case_vc
# crack the LUKS passphrase offline: extract the header and feed hashcat -m 14600
cryptsetup luksHeaderBackup /dev/loop0p2 --header-backup-file luks.img
```

## LVM and RAID

```sh
# scan for physical volumes after attaching the loop device
pvscan && vgscan
# list the volume groups and logical volumes the image contains
vgdisplay && lvdisplay
# activate the volume group read-only so /dev/mapper nodes appear
vgchange -a y --readonly forensic_vg
# mount the logical volume you want
mount -o ro /dev/forensic_vg/root /mnt/e
# deactivate cleanly when finished
vgchange -a n forensic_vg
# assemble a software RAID set from several images (read-only)
mdadm --assemble --readonly /dev/md0 /dev/loop0 /dev/loop1
# examine one member's RAID superblock to learn level, chunk size and disk order
mdadm --examine /dev/loop0
```

## NTFS, APFS and HFS+

```sh
# ntfs-3g read-only with the Windows metadata files visible ($MFT, $LogFile, $Secure)
mount -t ntfs-3g -o ro,show_sys_files,streams_interface=windows image.dd /mnt/e
# streams_interface=windows makes alternate data streams readable as file:stream
cat '/mnt/e/report.txt:hidden'
# list every alternate data stream under a mounted NTFS volume
getfattr -Rn ntfs.streams /mnt/e 2>/dev/null | grep -B1 ':\$DATA'
# APFS on Linux via apfs-fuse, -r selects the volume index inside the container
apfs-fuse -o ro -v 0 apfs_part.dd /mnt/e
# APFS or HFS+ on macOS: attach without mounting, then mount one volume read-only
hdiutil attach -readonly -nomount image.dmg && diskutil mount readOnly /dev/disk4s2
# HFS+ on Linux
mount -t hfsplus -o ro,loop,offset=1048576 image.dd /mnt/e
```

## Filesystem metadata (Sleuthkit)

```sh
# fsstat: filesystem type, block size, cluster count, $MFT location, journal location
fsstat -o 206848 image.dd
# istat: everything about one inode/MFT entry, including every MACB timestamp and run list
istat -o 206848 image.dd 12345
# ifind maps a file path back to its inode number
ifind -o 206848 -n '/Users/bob/notes.txt' image.dd
# ifind -d maps a data unit (cluster) back to the inode that owns it
ifind -o 206848 -d 98765 image.dd
# ffind maps an inode back to every filename that points at it (hard links included)
ffind -o 206848 image.dd 12345
# blkstat reports whether a given block is allocated and its metadata
blkstat -o 206848 image.dd 98765
# blkcalc converts a unit address in the unallocated blkls output back to an image address
blkcalc -o 206848 -u 4242 image.dd
# jls lists journal entries (ext3/4 journal or NTFS $LogFile)
jls -o 206848 image.dd
# jcat prints one journal block, which can hold a pre-deletion copy of metadata
jcat -o 206848 image.dd 8 > jblock.bin
# usnjls parses the NTFS $UsnJrnl change journal: every create/delete/rename
usnjls -o 206848 image.dd
```

## Listing and extracting files

```sh
# fls -r recursive, -p full paths, -d deleted only: the fastest way to find a deleted flag
fls -o 206848 -r -p -d image.dd
# -u shows undeleted (allocated) entries only; drop both to see everything
fls -o 206848 -r -p -u image.dd | grep -i flag
# -m emits body-file format for mactime, with a path prefix for the mount point
fls -o 206848 -r -m /C image.dd > bodyfile.txt
# -l long listing with the timestamps inline
fls -o 206848 -l image.dd 12345
# icat writes a file's content to stdout by inode, including deleted ones
icat -o 206848 image.dd 12345 > recovered.bin
# icat -r attempts recovery of a deleted file whose runs are partly overwritten
icat -o 206848 -r image.dd 12345 > recovered.bin
# icat an NTFS alternate data stream by attribute id (inode-attrtype-attrid)
icat -o 206848 image.dd 12345-128-5 > ads.bin
# tsk_recover -e extracts EVERY file (allocated and deleted) to a directory
tsk_recover -e -o 206848 image.dd ./recovered
# -a extracts allocated files only, which is much faster on a big image
tsk_recover -a -o 206848 image.dd ./allocated
# sorter categorises every file by type and flags extension mismatches
sorter -f ntfs -o 206848 -d ./sorted image.dd
```

## Deleted data, unallocated space and carving

```sh
# blkls extracts unallocated blocks only: the raw material for carving
blkls -o 206848 image.dd > unallocated.dd
# -s extracts slack space only, where fragments of old files survive
blkls -o 206848 -s image.dd > slack.dd
# -a extracts allocated blocks only (the inverse of the default)
blkls -o 206848 -a image.dd > allocated.dd
# sigfind locates a hex signature across the image and prints its sector numbers
sigfind -b 512 504b0304 image.dd
# foremost carves by header/footer; -t limits types, -o output dir, -i input
foremost -t jpg,pdf,zip,doc -i unallocated.dd -o ./carved
# scalpel is faster and driven entirely by scalpel.conf; -b keeps the carved headers
scalpel -c /etc/scalpel/scalpel.conf -o ./carved_scalpel unallocated.dd
# photorec is the best generic carver for photos and office docs, /log keeps an audit log
photorec /log /d ./photorec_out image.dd
# testdisk repairs the partition table itself and can undelete whole filesystems
testdisk /log image.dd
# ext3/ext4 deleted file recovery straight from the journal
extundelete image.dd --restore-all
# ext4magic uses the journal to recover files deleted after a given time
ext4magic image.dd -a $(date -d '2 days ago' +%s) -r -d ./ext4_recovered
```

## bulk_extractor

```sh
# run every scanner; finds emails, URLs, credit cards, keys, exif, zip, base64 in one pass
bulk_extractor -o be_out image.dd
# enable a scanner that is off by default (wordlist, xor, hiberfile, rar, sqlite)
bulk_extractor -e wordlist -e xor -e hiberfile -o be_out image.dd
# disable the noisy scanners to make a big image finish this century
bulk_extractor -x accts -x exif -x json -o be_out image.dd
# restrict to one scanner when you know what you want (here just network artefacts)
bulk_extractor -E net -o be_net image.dd
# the feature files are plain TSV: offset, feature, context
head -20 be_out/email.txt && wc -l be_out/*.txt
# the histogram files rank features by frequency, which surfaces the important ones
sort -rn -k1 be_out/email_histogram.txt | head -20
# carved zips and packets land in their own outputs, ready for further analysis
ls be_out/zip/ be_out/packets.pcap 2>/dev/null
# grep every feature file at once for a flag
grep -rhaoiE '[a-z0-9_]+\{[^}]{4,80}\}' be_out/ | sort -u
```

## Autopsy CLI notes

```sh
# Autopsy 4 is a GUI, but its ingest can be driven headless on Windows builds
autopsy --nosplash --runFromCommandLine --caseDir=C:\cases\case1 --dataSource=D:\image.E01
# on Linux, the same ingest modules are the Sleuthkit tools above plus these two
tsk_loaddb -d case.db image.dd
# query the resulting SQLite database directly instead of using the GUI
sqlite3 case.db "select name, size, meta_addr from tsk_files where name like '%flag%';"
```

## Registry, EVTX and user artefacts from a mounted image

```sh
# the five registry hives worth copying out of a mounted Windows image
cp /mnt/e/Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY} /mnt/e/Windows/System32/config/DEFAULT ./hives/
# per-user hives: NTUSER.DAT and UsrClass.dat (the latter holds shellbags)
cp /mnt/e/Users/*/NTUSER.DAT /mnt/e/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat ./hives/
# extract them straight from an unmounted image with Sleuthkit instead
icat -o 206848 image.dd "$(ifind -o 206848 -n '/Windows/System32/config/SYSTEM' image.dd)" > SYSTEM
# all event logs live in one directory; Security, System and PowerShell/Operational matter most
cp /mnt/e/Windows/System32/winevt/Logs/*.evtx ./evtx/
# the execution artefacts: prefetch, amcache, srum
cp /mnt/e/Windows/Prefetch/*.pf ./prefetch/ && cp /mnt/e/Windows/AppCompat/Programs/Amcache.hve ./
# the $MFT itself, for a full filesystem timeline
icat -o 206848 image.dd 0 > '$MFT'
# browser history databases, which are SQLite and greppable as-is
find /mnt/e/Users -name 'places.sqlite' -o -name 'History' -o -name 'WebCacheV01.dat'
```

## Timelines

```sh
# body file from the filesystem metadata, with the mount point as the path prefix
fls -o 206848 -r -m /C image.dd > bodyfile.txt
# add the registry and other non-filesystem artefacts into the same body file
tsk_gettimes -o 206848 image.dd >> bodyfile.txt
# mactime renders a body file as a chronological CSV timeline
mactime -b bodyfile.txt -d -z UTC > timeline.csv
# restrict the timeline to a date range, which is what makes it readable
mactime -b bodyfile.txt -d -z UTC 2024-05-01..2024-05-03 > window.csv
# plaso/log2timeline does a full super-timeline over the image itself
log2timeline.py --storage_file case.plaso image.dd
# psort turns the plaso store into a filtered CSV
psort.py -o l2tcsv -w timeline.csv case.plaso "date > '2024-05-01 00:00:00'"
```

## Common one-liners

```sh
# every SUID/SGID binary on a mounted Linux image - privilege escalation evidence
find /mnt/e -xdev -type f -perm /6000 -printf '%M %u %g %p\n' 2>/dev/null
# files modified in the 24 hours before the incident, newest first
find /mnt/e -xdev -type f -newermt '2024-05-01' ! -newermt '2024-05-02' -printf '%T@ %p\n' | sort -rn
# hash every regular file on the image into a manifest
find /mnt/e -xdev -type f -exec sha256sum {} + > manifest.sha256
# diff two acquisitions of the same host by comparing manifests
diff <(sort -k2 before.sha256) <(sort -k2 after.sha256) | grep '^[<>]'
# every file whose content type disagrees with its extension
find /mnt/e -xdev -type f -exec file --mime-type {} + | grep -Ei '\.(txt|jpg|png):.*(executable|zip)'
# flag-shaped strings across the whole raw image, ASCII and UTF-16LE
strings -a image.dd | grep -aoE 'flag\{[^}]+\}'; strings -el image.dd | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'
# the largest files on the image, which is where hidden containers live
find /mnt/e -xdev -type f -printf '%s %p\n' | sort -rn | head -20
# grep the unallocated space directly without carving it into files first
grep -abo 'flag{' unallocated.dd | head
# find every archive and check it for password protection in one pass
find /mnt/e -xdev -iname '*.zip' -exec 7z l -slt {} \; | grep -E 'Path =|Encrypted = \+'
```

## References

- The Sleuthkit tool reference (`mmls`, `fsstat`, `fls`, `icat`, `istat`, `blkls`, `mactime` man pages)
- `libewf` tools: `ewfinfo`, `ewfverify`, `ewfexport`, `ewfacquire`, `ewfmount`
- `bulk_extractor` scanner documentation and feature-file format
- `plaso` / `log2timeline` documentation; `dislocker`, `cryptsetup`, `apfs-fuse` man pages
