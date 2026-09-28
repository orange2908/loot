---
title: "VHD file - VHDX (Forensics)"
category: "forensics"
subcategory: "disk"
type: "technique"
tags: ["my-notes", "personal", "mft", "sleuthkit", "vhd", "file", "vhdx", "forensics"]
summary: "Personal note: VHD file - VHDX (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/VHD file - VHDX.md"
---

# Corrupted VHD file
```bash
~/ctf/isitdtu ❯ fdisk -lu Deleted.vhd
Disk Deleted.vhd: 100 MiB, 104858112 bytes, 204801 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x5cfdbd58

Device       Boot Start    End Sectors Size Id Type
Deleted.vhd1        128 198783  198656  97M  7 HPFS/NTFS/exFAT
```

```bash
~/ctf/isitdtu ❯ dd if=Deleted.vhd bs=512 skip=128 count=1 of=boot_sector.bin
1+0 records in
1+0 records out
512 bytes copied, 0.000100754 s, 5.1 MB/s
```

```bash
~/ctf/isitdtu ❯ xxd -s 3 -l 8 boot_sector.bin
00000003: 4e54 4600 2020 2020                      NTF.
```

```bash
~/ctf/isitdtu ❯ sudo blkls -o 128 Deleted.vhd > unallocated_data.bin
```

```bash
~/ctf/isitdtu ❯ sudo fls -r -o 128 Deleted.vhd
```
# Fix file
```bash
~/ctf/isitdtu ❯ dd if=Deleted.vhd of=NTFS_Partition.img bs=512 skip=128 count=198656
```

```bash
~/ctf/isitdtu ❯ sudo ntfsfix NTFS_Partition.img
Mounting volume... NTFS signature is missing.
FAILED
Attempting to correct errors... NTFS signature is missing.
FAILED
Failed to startup volume: Invalid argument
NTFS signature is missing.
Trying the alternate boot sector
The alternate bootsector is usable
Rewriting the bootsector
The boot sector has been rewritten

Processing $MFT and $MFTMirr...
Reading $MFT... OK
Reading $MFTMirr... OK
Comparing $MFTMirr to $MFT... OK
Processing of $MFT and $MFTMirr completed successfully.
Setting required flags on partition... OK
Going to empty the journal ($LogFile)... OK
Checking the alternate boot sector... OK
NTFS volume version is 3.1.
NTFS partition NTFS_Partition.img was processed successfully.
```

---

# Mount VHDX file
```bash
sudo apt update
sudo apt install libguestfs-tools -y


sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 "2025-02-25T004054_Restorer.vhdx"
sudo fdisk -l /dev/nbd0
sudo mount /dev/nbd0p1 /mnt/lol
```

```bash
sudo umount /mnt
sudo qemu-nbd --disconnect /dev/nbd0
sudo rmmod nbd
```

---

*From your own notes: `Forensics/VHD file - VHDX.md`*
