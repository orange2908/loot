---
title: "Artifact - BlackHat MEA CTF Qualification 2024"
category: "forensics"
subcategory: "windows"
type: "writeup"
tags: ["registry", "forensics", "artifact", "windows", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "The challenge gave a Registry Hive renamed to the name \"execution\" (you could tell that its the SYSTEM hive), that you can open using Registry Explorer from the list of Eric Zimmerman tools:"
source:
  name: "CTFtime writeup #39451"
  url: "https://ctftime.org/writeup/39451"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Artifact"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Artifact
- **Author team:** JordanShell
- **CTFtime tags:** registry, forensics
- **CTFtime:** <https://ctftime.org/writeup/39451>

---
Artifact (Easy — 90pts)  
\-----

\-----

![](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*m2dcJGvPJHkG5doPYSgtGw.png>)

\-----

The challenge gave a Registry Hive renamed to the name "execution" (you could tell that its the SYSTEM hive), that you can open using Registry Explorer from the list of Eric Zimmerman tools:

\-----

![](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*smqlwE7rhvSZM-B55dvyVg.png>)

\-----

And because the question asked about " the executable" related to the impersonation tools we can check the relevant registries like "AppCompatCache" under:   
```  
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache   
```  
There you would find these entries in the beggining :  
```  
Cache Entry Position Program Name Modified Time  
0 C:\Users\Labib\Desktop\AmcacheParser\8bKpGWGh.exe 2024-08-09 23:05:18  
1 C:\Users\Labib\Desktop\AmcacheParser\DeadPotato-NET4.exe 2024-08-09 22:42:13  
2 C:\Users\Labib\Desktop\AmcacheParser\AmcacheParser.exe 2023-05-21 18:49:06  
3 SIGN.MEDIA=2715636E DeadPotato-NET4.exe 2024-08-09 22:42:13  
4 SIGN.MEDIA=BD586BEC DeadPotato-NET4.exe 2024-08-09 22:42:13  
5 C:\Users\Labib\Desktop\DeadPotato-NET4.exe 2024-08-09 22:42:13  
```  
from there you can search the internet for DeadPotato to find that its a windows priv escalation tool "leveraging the SeImpersonate right to obtain SYSTEM privileges."

\----  
therefore the flag would be:  
> BHFlagY{DeadPotato-NET4.exe_09/08/2024_22:42:13}
