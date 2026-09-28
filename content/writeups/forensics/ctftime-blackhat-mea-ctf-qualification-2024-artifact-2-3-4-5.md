---
title: "Artifact - BlackHat MEA CTF Qualification 2024"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "sleuthkit", "privesc", "artifact", "disk", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Get unlimited access to the best of Medium for less than $1/week."
source:
  name: "CTFtime writeup #39406"
  url: "https://ctftime.org/writeup/39406"
original_source: "https://medium.com/@ahmadmassas342/blackhat-mea-qualification-ctf-forensics-095746b4764b"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Artifact"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Artifact
- **Author team:** JordanShell
- **CTFtime:** <https://ctftime.org/writeup/39406>
- **Original writeup:** <https://medium.com/@ahmadmassas342/blackhat-mea-qualification-ctf-forensics-095746b4764b>

---
Search  
Write

Ahmad Massad  
Get unlimited access to the best of Medium for less than $1/week.  
Become a member

BlackHat MEA Qualification CTF-Forensics  
Ahmad Massad  
Ahmad Massad

5 min read  
·  
Just now

Artifiact

The challenge gives us a zip file after extracting the files from it we got a registry file

Okay now we need to use RegistryExplorer.exe from ZimmermanTools

1:open the hive

So the challenge was talking about impersonation tools that had been executed

so let’s think a little if someone needs to execute a tool he will use cmd.exe or powershell.exe

now we need to see where the PowerShell was executed on the system

Ctrl + F and search for the powershell.exe

Okay we can see that the powershell.exe was executed and appcompatcache can tell us that

After opening the hive we will see that some suspicious Executables

Like :DeadPotato-NET4.exe

After searching for this file in Google we got

Windows Privilege Escalation — Token Impersonation(SeImpersonatePrivilege)  
Introduction  
[usersince99.medium.com](https://usersince99.medium.com)

BHFlagY{DeadPotato-NET4.exe_09/08/2024_22:42:13}

NotFS

The description for this challenge try to say to us: hey investigators that the file may contain or represent a file system, and you need to analyze and possibly reconstruct or repair it to extract relevant information.

okay now before diving into the challenge we know that the file had some issues we need to fix, we always do that.

okay after downloading the zip file we will get a a disk image

DOS-style Master Boot Record (MBR) partitioning scheme

Let us start solving this now

1: Discovery  
1: First we will use “mmls” to display the partition layout of a volume system (partition tables). From SleuthKit.

mmls Chall.img

Allocated Partition: The disk has one allocated partition (Slot 002) formatted as NTFS or exFAT, covering sectors 39168 to 1063168.  
Allocated Partition: This disk section is in use and formatted to store files.  
NTFS/exFAT: The partition uses one of these file systems, which determines how files are organized and accessed.  
Sectors 39168 to 1063168: This is the range of the disk that the partition occupies.  
2: Mount:  
dd if=Chall.img of=ch_1 bs=512 skip=0 count=1024001 

We are copying a specific portion of a disk image to a new file

This portion is for NTFS where is Allocated Partition and its store files.

sudo mkdir -p /mnt/disk 

Now let's mount the Partition to this dir

sudo mount ch_1 /mnt/disk

Error:)

but Why?

the issue was related to the use of loop devices and possibly mounting the disk image file

One minute what are loop devices?

In Unix-like operating systems, a loop device, vnd, or lofi is a pseudo-device that makes a computer file accessible as a block device. Before use, a loop device must be connected to an extant file in the file system.

hmm

now let's fix that, we always do

now we need to forget about the ch_1 because that will not work why? because we need to mount the whole image

Okay Let's start:

1: Understanding the Process: Mounting a Disk Image

When working with disk images, it’s crucial to properly mount them to access and analyze their contents. Here’s a detailed explanation of the steps taken to mount the disk image file Chall.img:

Attempting to Set Up the Loop Device  
sudo losetup /dev/loop1 /home/kali/Desktop/Chall.img

Purpose: This command attempts to associate the disk image file Chall.img with the loop device /dev/loop1. Loop devices allow you to mount files as if they were actual disks.

2\. Checking Current Loop Device Associations

losetup -a

3\. Mounting the Disk Image with Offset

sudo mount -o loop,offset=$((0x100000)) /dev/loop1 /mnt/disk  
Purpose: This command mounts the disk image file directly to a mount point (/mnt/disk) using the loop device /dev/loop1, with an offset specified. The offset=$((0x100000)) option is used to skip over any preliminary data (e.g., partition table) and reach the start of the actual filesystem.  
4\. Verifying the Mounted Filesystem

ls /mnt/disk

All the files have the same extension .webp, only one file has the .png extension

'DALL·E 2024-08-08 07.08.12 - A bustling scene at Black Hat MEA (Middle East & Africa) cybersecurity event. The image includes a large exhibition hall filled with booths from vario.png'  
5\. Analysing the file

mv /mnt/disk/DALL·E\ 2024-08-08\ 07.08.12\ -\ A\ bustling\ scene\ at\ Black\ Hat\ MEA\ \\(Middle\ East\ \&\ Africa\\)\ cybersecurity\ event.\ The\ image\ includes\ a\ large\ exhibition\ hall\ filled\ with\ booths\ from\ vario.png /home/kali/Desktop

Something Wrong:)

Let's see the header of the PNG file

I used: <https://hexed.it/>

now we know why it's not opening:)

Magic Numpers :)

We need to add the Magic Numper header for the png

List of file signatures - Wikipedia  
needs additional citations for verification .improve this article by (Learn how and when to remove this message )…  
[en.wikipedia.org](https://en.wikipedia.org)

89 50 4E 47 0D 0A 1A 0A  
Add the Magic Numbers using <https://hexed.it/>

Export the file

open DALL·E\ 2024-08-08\ 07.08.12\ -\ A\ bustling\ scene\ at\ Black\ Hat\ MEA\ \\(Middle\ East\ \&\ Africa\\)\ cybersecurity\ event.\ The\ image\ includes\ a\ large\ exhibition\ hall\ filled\ with\ booths\ from\ vario\\(1\\).png

Thx For reading.

P0peye always catches bad actors:)

Ahmad Massad  
Written by Ahmad Massad  
10 Followers  
Digital Forensics Analyst

Edit profile  
More from Ahmad Massad  
Aliens CTF -DFIR  
Ahmad Massad  
Ahmad Massad

Aliens CTF -DFIR  
Challenge Name: 7 Oct  
6d ago  
26

HTB-Sherlocks |Recollection  
Ahmad Massad  
Ahmad Massad

HTB-Sherlocks |Recollection  
Sherlock Scenario  
Feb 13  
13  
3

Ramadaniat-CTF DFIR  
Ahmad Massad  
Ahmad Massad

Ramadaniat-CTF DFIR  
Operation Data Leak0  
Apr 6

See all from Ahmad Massad  
Recommended from Medium  
How To Secure Facebook Account  
Sophia Taylor  
Sophia Taylor

How To Secure Facebook Account  
I’m going to show you how to make your Facebook account more secure for that you have to follow my instructions very carefully.

3d ago  
403  
10

Israel-Palestine conflict will end soon — but for a shocking reason  
The Other Millennial  
The Other Millennial

Israel-Palestine conflict will end soon — but for a shocking reason  
No conflict is perpetual. This too must come to an end. But not because of a brotherly embrace by the warring factions inspired by…

Jul 31  
2.9K  
126

Lists

Staff Picks  
723 stories  
·  
1265 saves

Stories to Help You Level-Up at Work  
19 stories  
·  
775 saves

Self-Improvement 101  
20 stories  
·  
2654 saves

Productivity 101  
20 stories  
·  
2280 saves  
Automated Network Traffic Analysis and Monitoring Script for Compromised Hosts  
Aardvark Infinity  
Aardvark Infinity

in

Aardvark Infinity

Automated Network Traffic Analysis and Monitoring Script for Compromised Hosts  
Name: [automated_network_analysis.sh](http://automated_network_analysis.sh)

Aug 13  
57

Detect hidden surveillance cameras with your phone  
Vasileiadis A. (CyberKid)  
Vasileiadis A. (CyberKid)

Detect hidden surveillance cameras with your phone  
A family recently it had a big surprise on their Airbnb: a hidden camera disguised as a smoke detector in the living room, monitoring their…  
Aug 5  
366  
4

The Mother Of All Real Estate Bubbles Is Probably Coming  
Tony Yiu  
Tony Yiu

in

Alpha Beta Blog

The Mother Of All Real Estate Bubbles Is Probably Coming  
Interest rates are coming down which means home prices are going up

Aug 25  
1K  
32

Why the Upcoming Web3 and Crypto Mega Bull Run Will Catch Everyone off Guard  
Abhimanyu Bhargava  
Abhimanyu Bhargava

in

DataDrivenInvestor

Why the Upcoming Web3 and Crypto Mega Bull Run Will Catch Everyone off Guard  
A multi-year global recession is coming, but until then, this is what will happen

Aug 26  
490  
11

See more recommendations  
Help

Status

About

Careers

Press

Blog

Privacy

Terms

Text to speech

Teams

<https://medium.com/@ahmadmassas342/blackhat-mea-qualification-ctf-forensics-095746b4764b>
