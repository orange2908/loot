---
title: "Usb (Forensics)"
category: "forensics"
subcategory: "disk"
type: "technique"
tags: ["my-notes", "personal", "testdisk", "mft", "sleuthkit", "forensics"]
summary: "-> https://www.cgsecurity.org/wiki/TestDiskDownload"
source:
  name: "Personal notes"
origin_path: "Forensics/USB.md"
---

-> https://www.cgsecurity.org/wiki/TestDisk_Download
```bash
~/ctf/rootme/forensics/deleted-file 1m 51s
❯ /home/serioton/Downloads/testdisk-7.3-WIP/testdisk_static usb.image
```
### recover deleted files
```bash
~/ctf/hackropole/forensics/103_spx » icat -o 0 USB_a_analyser 66 > secret.xz
~/ctf/hackropole/forensics/103_spx » sha256sum secret.xz
0fb08681c2f8db4d3c127c4c721018416cc9f9b369d5f5f9cf420b89ee5dfe4e  secret.xz
```
-> icat from sleuthkit
## Mount USB
```bash
~/ctf/hackropole/forensics/103_spx » file USB_a_analyser
USB_a_analyser: DOS/MBR boot sector, code offset 0x52+2, OEM-ID "NTFS    ", sectors/cluster 8, Media descriptor 0xf8, sectors/track 62, heads 8, dos < 4.0 BootSector (0x80), FAT (1Y bit by descriptor); NTFS, sectors/track 62, sectors 507903, $MFT start cluster 4, $MFTMirror start cluster 31743, bytes/RecordSegment 2^(-1*246), clusters/index block 1, serial number 06d84ef355f47cf91
```

```bash
~/tools/forensics » sudo mkdir /mnt/usb_recovery
~/tools/forensics » sudo mount -o loop,ro USB_a_analyser /mnt/usb_recovery
```

---

*From your own notes: `Forensics/USB.md`*
