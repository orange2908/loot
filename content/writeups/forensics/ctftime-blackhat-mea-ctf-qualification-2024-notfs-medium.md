---
title: "NotFS Medium - BlackHat MEA CTF Qualification 2024"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "file-carving", "testdisk", "png-chunks", "notfs", "medium", "disk", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "The challenge attached a (.img) Disk Image called \"Chall.img\", we can use the strings tool to check the contents and it seems like it is a file system."
source:
  name: "CTFtime writeup #39454"
  url: "https://ctftime.org/writeup/39454"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "NotFS Medium"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** NotFS Medium
- **Author team:** JordanShell
- **CTFtime:** <https://ctftime.org/writeup/39454>

---
### NotFS (Medium— 180pts)

\-----  
![](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*w3pXqlqHUBtIru6z2JL6sA.png>)

\-----  
The challenge attached a (.img) Disk Image called "Chall.img", we can use the `strings` tool to check the contents and it seems like it is a file system.

\-----

Firstly during the analysis I tried opening the (img) using **autopsy** to extract data from the (img) file and it were able to carve 6 WEBP images, that were AI generated images of CTF competetions.  
And as the challenge description sugested to make "necessay adjustments to solve the challenge" i started using **TestDisk** on the linux terminal to recover lost partitions.  
  
\-----  
After opening the img on TestDesk it showed that :   
```  
  
TestDisk 7.1, Data Recovery Utility, July 2019   
Christophe GRENIER <[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)>   
<https://www.cgsecurity.org>   
  
  
Disk Chall.img - 17 GB / 16 GiB   
  
Please select the partition table type, press Enter when done.   
[Intel ] Intel/PC partition   
[EFI GPT] EFI GPT partition map (Mac i386, some x86_64...)   
[Humax ] Humax partition table   
[Mac ] Apple partition map (legacy)   
[None ] Non partitioned media   
[Sun ] Sun Solaris partition   
[XBox ] XBox partition   
[Return ] Return to disk selection   
  
  
  
Hint: Intel partition table type has been detected.   
Note: Do NOT select 'None' for media with only a single partition. It's very   
rare for a disk to be 'Non-partitioned'.

```  
  
As you can see it mentioned that ** Intel partition table type has been detected** so we proceed with that info and further use the **Analyse** option from the list :  
  
```  
TestDisk 7.1, Data Recovery Utility, July 2019   
Christophe GRENIER <[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)>   
<https://www.cgsecurity.org>   
  
  
Disk Chall.img - 17 GB / 16 GiB   
CHS 2089 255 63 - sector size=512   
  
>[ Analyse ] Analyse current partition structure and search for lost partitions   
[ Advanced ] Filesystem Utils   
[ Geometry ] Change disk geometry   
[ Options ] Modify options   
[ MBR Code ] Write TestDisk MBR code to first sector   
[ Delete ] Delete all data in the partition table   
[ Quit ] Return to disk selection   
  
  
  
  
  
Note: Correct disk geometry is required for a successful recovery. 'Analyse'   
process may give some warnings if it thinks the logical geometry is mismatched.

```  
Then we can use the option to do a **[Quick Search]** to locate a partition that shows us:

```  
Disk Chall.img - 17 GB / 16 GiB - CHS 2089 255 63   
Partition Start End Size in sectors   
>D HPFS - NTFS 0 32 33 63 253 62 1026048   
D Linux 0 32 33 2088 137 33 33550336

```  
We can after press **P: list files** after selecting the **HPFS - NTFS** partition and that shows us a list of these files:

```  
TestDisk 7.1, Data Recovery Utility, July 2019   
Christophe GRENIER <[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)>   
<https://www.cgsecurity.org>   
HPFS - NTFS 0 32 33 63 253 62 1026048   
Directory /   
  
>dr-xr-xr-x 0 0 0 8-Aug-2024 21:30 .   
dr-xr-xr-x 0 0 0 8-Aug-2024 21:30 ..   
-r--r--r-- 0 0 359206 8-Aug-2024 21:28 DALL·E 2024-08-08 07.03.54 - A surreal landscape with floating   
-r--r--r-- 0 0 548748 8-Aug-2024 21:28 DALL·E 2024-08-08 07.04.40 - A futuristic cityscape at night wi  
-r--r--r-- 0 0 456490 8-Aug-2024 21:28 DALL·E 2024-08-08 07.04.49 - An intense Capture The Flag (CTF)   
-r--r--r-- 0 0 481196 8-Aug-2024 21:28 DALL·E 2024-08-08 07.05.19 - A CTF (Capture The Flag) cybersecu  
-r--r--r-- 0 0 580774 8-Aug-2024 21:28 DALL·E 2024-08-08 07.06.03 - A digital forensics CTF (Capture T  
-r--r--r-- 0 0 2784359 8-Aug-2024 21:28 DALL·E 2024-08-08 07.08.12 - A bustling scene at Black Hat MEA   
-r--r--r-- 0 0 473262 8-Aug-2024 21:28 DALL·E 2024-08-08 07.08.12 - A bustling scene at Black Hat MEA   
-r--r--r-- 0 0 30 8-Aug-2024 21:29 hmmmREadHa  
```  
  
Here you can see that we found the same WEBP images and two other files one (TXT) and one (PNG) ,press **a** to select all files and **C** to extract them to where you want to find if they have any relevant information...

\-----

And as mentioned before we found a (PNG) image that we can't open because there's a problem with the file format, so we can open it using **hexeditor** to check for the file signature which shows this :  
```  
File: file2png ASCII Offset: 0x00000004 / 0x002A7C66 (%00) M  
00000000 00 00 00 00 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 ............IHDR  
00000010 00 00 04 00 00 00 04 00 08 06 00 00 00 7F 1D 2B ...............+  
00000020 83 00 00 00 01 73 52 47 42 00 AE CE 1C E9 00 00 .....sRGB.......  
00000030 00 04 67 41 4D 41 00 00 B1 8F 0B FC 61 05 00 00 ..gAMA......a...  
00000040 00 09 70 48 59 73 00 00 0B 11 00 00 0B 11 01 7F ..pHYs..........  
00000050 64 5F 91 00 00 FF A5 49 44 41 54 78 5E A4 FD 67 d_.....IDATx^..g  
00000060 94 5D E7 B5 1D 88 32 21 A3 50 A8 9C 73 CE 39 57 .]....2!.P..s.9W  
00000070 9D 3A 95 4F 9D CA 39 E7 42 55 A1 50 C8 39 E7 0C .:.O..9.BU.P.9..

```

to open the image you'll have to use the correct file signature for a PNG image, you can find a List of file signatures on wikipedia and search for the PNG signature to see that its `89 50 4E 47 0D 0A 1A 0A` 

\-----

And after editing that on the hexeditor we can finally open the image which contains the flag:  
![](<https://miro.medium.com/v2/resize:fit:828/format:webp/1*ZxJg5F-Sxm9s83vJfKvbyw.png>)
