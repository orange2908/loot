---
title: "BitLocker encrypted drive (Forensics)"
category: "forensics"
type: "technique"
tags: ["my-notes", "personal", "bitlocker", "encrypted", "drive", "forensics"]
summary: "Personal note: BitLocker encrypted drive (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/BitLocker encrypted drive.md"
---

#bitlocker

```
~/ctf/flagyard/Locked-Secrets/triage image/E/Windows/System32/config
❯ secretsdump.py -sam SAM -security SECURITY -system SYSTEM local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x902c4190206df1f2694c3709a6bac5cb
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:af1f01380d776724659a3902859dfa95:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:d17b486ea716ee4d6d817147064c9a69af502f3e71e3ed185b166b224263ca45628beb9adeba83a27b8890a955141c454cb593bc625fbc224f3e75b70aa5521a0db1dc25594c0df3eef26b9751129b11415807146a5ab53f37e75b82cbce69c973a44fef88ce55b6b0f913cf24ccc30563652a0011586a1c567b1b14e6a757bcdc068427d3f5a892e3e3787e6869daa69752d484ee7f42235a6b9784f9b5b6004a3a139bc38fb797c336d23120c321bfe948b0b0656b0f20e10845b879cc280c46edc459c03f3e9637074748bdefcec1afeaf7b3ebe3d22d3e51744f8c402ab39f953cf75c6ce1653a13aa42f2f5b90f
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:11cb791057ee2741212308b9b35c38ca
[*] DefaultPassword
(Unknown User):Passw0rd123!@Meme
[*] DPAPI_SYSTEM
dpapi_machinekey:0x2e2a6ffa945588e56ca3ea9a16897007aa5bf821
dpapi_userkey:0xbb33cadecfbe029d3eedf4e8bf17d63dbd002221
[*] NL$KM
 0000   C1 A1 C7 0C F5 7A 19 C8  83 33 C6 C2 15 8B 80 86   .....z...3......
 0010   5B C5 AD 0E 64 EB B9 61  96 63 99 DF 11 DC 76 7A   [...d..a.c....vz
 0020   D5 DC 00 07 81 1C FB AB  FA BD 9B 6B DE 6C 22 A4   ...........k.l".
 0030   73 EF 9F E0 7C 6C 0E 2F  64 BF 3A 4E 27 91 5D A1   s...|l./d.:N'.].
NL$KM:c1a1c70cf57a19c88333c6c2158b80865bc5ad0e64ebb961966399df11dc767ad5dc0007811cfbabfabd9b6bde6c22a473ef9fe07c6c0e2f64bf3a4e27915da1
[*] Cleaning up...
```

```
Passw0rd123!@Meme
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# mkdir rawimage
root@ubuntu /h/s/c/f/L/bitlocker drive# ewfmount bitlocker_drive.E01 ./rawimage/
ewfmount 20140807
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# mkdir mountpoint
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# file ./rawimage/ewf1
./rawimage/ewf1: DOS/MBR boot sector MS-MBR Windows 7 english at offset 0x163 "Invalid partition table" at offset 0x17b "Error loading operating system" at offset 0x19a "Missing operating system", disk signature 0x174e82b; partition 1 : ID=0x7, start-CHS (0x0,2,3), end-CHS (0x8,172,36), startsector 128, 139264 sectors
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# sudo blkid ./rawimage/ewf1
./rawimage/ewf1: PTUUID="0174e82b" PTTYPE="dos"
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# fdisk -l ./rawimage/ewf1
Disk ./rawimage/ewf1: 71 MiB, 74448896 bytes, 145408 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x0174e82b

Device            Boot Start    End Sectors Size Id Type
./rawimage/ewf1p1        128 139391  139264  68M  7 HPFS/NTFS/exFAT
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# dd if=./rawimage/ewf1 of=./partition1.img bs=512 skip=128 count=139264
139264+0 records in
139264+0 records out
71303168 bytes (71 MB, 68 MiB) copied, 0.704122 s, 101 MB/s
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# mkdir ./dislocker
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# dislocker -V ./partition1.img -u'Passw0rd123!@Meme' -- ./dislocker/
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# ls dislocker/
dislocker-file
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# mkdir ./bitlocker
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# mount -o loop ./dislocker/dislocker-file ./bitlocker
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# ls bitlocker
'System Volume Information'/  'the flag.txt'*
root@ubuntu /h/s/c/f/L/bitlocker drive# cat bitlocker/the\ flag.txt
FlagY{a8b4c9a8d9e0f5b9a77b89a7b1a5b9f8}            
```

```
FlagY{a8b4c9a8d9e0f5b9a77b89a7b1a5b9f8}
```

```
root@ubuntu /h/s/c/f/L/bitlocker drive# umount /home/serioton/ctf/flagyard/Locked-Secrets/bitlocker\ drive/bitlocker
root@ubuntu /h/s/c/f/L/bitlocker drive# umount /home/serioton/ctf/flagyard/Locked-Secrets/bitlocker\ drive/dislocker
```

---

*From your own notes: `Forensics/BitLocker encrypted drive.md`*
