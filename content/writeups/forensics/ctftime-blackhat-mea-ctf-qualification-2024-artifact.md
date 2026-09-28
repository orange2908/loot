---
title: "Artifact - BlackHat MEA CTF Qualification 2024"
category: "forensics"
subcategory: "windows"
type: "writeup"
tags: ["forensics", "artifact", "registry", "windows", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "In this challenge, the primary artifact provided was a Registry Hive file."
source:
  name: "CTFtime writeup #39695"
  url: "https://ctftime.org/writeup/39695"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Artifact"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Artifact
- **Author team:** APT-X
- **CTFtime tags:** artifact
- **CTFtime:** <https://ctftime.org/writeup/39695>

---
In this challenge, the primary artifact provided was a Registry Hive file. To begin my analysis, I employed RegRipper, a widely-used tool for extracting and analyzing key information from Windows registry files.

After RegRipper completed its scan, I focused on identifying executable files, particularly searching for any potentially suspicious entries. During this search, I discovered a significant entry: DeadPotato-NET4.exe, located within the registry path:

ControlSet001\Control\Session Manager\AppCompatCache.

The AppCompatCache registry key logs details about executable files that have been run on the system, including their execution timestamps. The file DeadPotato-NET4.exe was executed on 09/08/2024 at 22:42:13, which provided the necessary timestamp for the challenge.

The flag for this challenge was:

BHFlagY{DeadPotato-NET4.exe_09/08/2024_22:42:13}

This challenge emphasizes the significance of registry forensics in detecting and investigating suspicious activities on a system. By utilizing tools like RegRipper, it is possible to efficiently extract crucial evidence from registry hives to aid in forensic investigations.
