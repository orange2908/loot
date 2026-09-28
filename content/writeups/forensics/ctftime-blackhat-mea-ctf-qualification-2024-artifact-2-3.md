---
title: "Artifact - BlackHat MEA CTF Qualification 2024"
category: "forensics"
subcategory: "windows"
type: "writeup"
tags: ["forensics", "forensic", "registry", "privesc", "artifact", "windows", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Challenge : Artifact (Easy)"
source:
  name: "CTFtime writeup #39463"
  url: "https://ctftime.org/writeup/39463"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Artifact"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Artifact
- **Author team:** APT-X
- **CTFtime tags:** forensic
- **CTFtime:** <https://ctftime.org/writeup/39463>

---
Challenge : Artifact (Easy)

Solution: 

1\. The attached file is named “execution”.   
2\. The file type is identified as: MS Windows Registry File  
3\. After searching online and reviewing writeups, I discovered that one way to analyze this registry file is by using the "RegRipper tool" to extract the necessary information.   
4\. I searched all the .exe files and caught my attention for "Deadpotato" name which is a Windows Privilege Escalation utility, part of the well-known “Potato” family of exploits. These exploits are famous for their sophisticated methods of escalating privileges on Windows systems.   
5\. After aligning the information with the required flag format, the challenge was solved!

**Flag:** BHFlagY{DeadPotato-NET4.exe_09/08/2024_22:42:13}
