---
title: "Work With E01 Files (Forensics)"
category: "forensics"
subcategory: "disk"
type: "technique"
tags: ["my-notes", "personal", "sleuthkit", "work", "e01", "files", "forensics"]
summary: "Personal note: Work With E01 Files (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Work With E01 Files.md"
---

```
$ mkdir phy1
$ mkdir log1
$ sudo ewfmount kubuntu-MUS22.E01 ./phy1
$ sudo file ./phy1/ewf1
./phy1/ewf1: DOS/MBR boot sector
```

```
$ sudo apt install sleuthkit
$ sudo mmls ./phy1/ewf1
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (\#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001050623   0001048576   Win95 FAT32 (0x0b)
003:  -------   0001050624   0001052671   0000002048   Unallocated
004:  Meta      0001052670   0250068991   0249016322   DOS Extended (0x05)
005:  Meta      0001052670   0001052670   0000000001   Extended Table (\#1)
006:  001:000   0001052672   0250068991   0249016320   Linux (0x83)
007:  -------   0250068992   0250069679   0000000688   Unallocated
```

```
$ echo 1052672 \* 512 | bc
538968064
```

```
$ sudo mount -o ro,loop,offset=538968064 ./phy1/ewf1 ./log1
$ cd log1/
/log1$ ls
bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  swapfile  tmp  var
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   sys       usr
```

```
$ sudo chroot ./log1
root@Inara:/#
```

```
$ sudo umount ./log1
$ sudo umount ./phy1
```

### Reference

> **Info** Linux Forensics on Linux - Cyber5W CTF Walkthrough
> Cyber5W released a Mini Linux DFIR CTF based on the Magnet Summit 2022 live CTF. It is doable if you are new to Linux investigations. A few questions are on the more intermediate end. If you don’t get to investigate Linux very often, this one is highly recommended! The CTF will be up until Jan 01, 2023, so you have plenty of time to work through it.  
> [https://dfir.science/2022/05/Linux-Forensics-on-Linux-Cyber5W-CTF-Walkthrough](https://dfir.science/2022/05/Linux-Forensics-on-Linux-Cyber5W-CTF-Walkthrough)

---

*From your own notes: `Forensics/Work With E01 Files.md`*
