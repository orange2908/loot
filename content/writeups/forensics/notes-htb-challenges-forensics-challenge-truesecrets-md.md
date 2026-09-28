---
title: "Challenge- TrueSecrets (Forensics)"
category: "forensics"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "cbc", "volatility", "cyberchef", "forensics", "htb-challenges"]
summary: "there is a script that encrypts using DES with CBC mode"
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Forensics/Challenge- TrueSecrets.md"
---

### Dump the backup_development.zip using

```
vol.py --plugins=~/Desktop/volatility/volatility/plugins -f TrueSecrets.raw --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=. -Q 0x000000000bbf6158
```
### found development.tc file
it is a `truecrypt` file
### decrypt using
```
mkdir extract
```

```
sudo truecrypt -t -k "" --protect-hidden=no development.tc extract
```
### Get password using this command in volatility
```
vol.py --plugins=~/Desktop/volatility/volatility/plugins -f TrueSecrets.raw --profile=Win7SP1x86_23418 truecryptsummary
```
### output
```
Password             X2Hk2XbEJqWYsh8VdbSYg6WpG9g7 at offset 0x89ebf064
Process              TrueCrypt.exe at 0x91892030 pid 2128
Service              truecrypt state SERVICE_RUNNING
Kernel Module        truecrypt.sys at 0x89e8b000 - 0x89ec2000
Symbolic Link        D: -> \Device\TrueCryptVolumeD mounted 2022-12-14 21:33:00 UTC+0000
Symbolic Link        Volume{d22d7a9d-7b72-11ed-b81d-0800273bf313} -> \Device\TrueCryptVolumeD mounted 2022-12-14 21:10:21 UTC+0000
Symbolic Link        D: -> \Device\TrueCryptVolumeD mounted 2022-12-14 21:33:00 UTC+0000
Driver               \Driver\truecrypt at 0xbe6b780 range 0x89e8b000 - 0x89ec1b80
Device               TrueCryptVolumeD at 0x8391b9b0 type FILE_DEVICE_DISK
Container            Path: \??\C:\Users\IEUser\Documents\development.tc
Device               TrueCrypt at 0x83e6b600 type FILE_DEVICE_UNKNOWN
```

```
password : X2Hk2XbEJqWYsh8VdbSYg6WpG9g7 
```
### decrypt and get the `malware_agent` folder
there is a script that encrypts using DES with CBC mode
```
AgentServer.cs
```
with the following parameters
```
key = AKaPdSgV
iv = QeThWmYq
```
The encrypted strings found in 3 files , the one that has the flag is
```
de008160-66e4-4d51-8264-21cbc27661fc.log.enc
```
### Encrypted flag
```
+iTzBxkIgVWgWm/oyP/Uf6+qW+A+kMTQkouTEammirkz2efek8yfrP5l+mtFS+bWA7TCjJDK2nLAdTKssL7CrHnVW8fMvc6mJR4Ismbs/d/fMDXQeiGXCA==
```
### Decrypt in CyberChef using
### Output
```
Cmd: type c:\users\greg\documents\flag.txt
HTB{570r1ng_53cr37_1n_m3m0ry_15_n07_g00d}
```

---
### References

```
https://truecrypt.sourceforge.net/
```

```
https://volatility-labs.blogspot.com/2014/01/truecrypt-master-key-extraction-and.html
```

```
https://blog.stalkr.net/2010/09/csaw-ctf-forensics-write-up.html
```

```
https://www.digitalocean.com/community/tutorials/how-to-install-truecrypt-cli-on-linux
```

```
https://techyrick.com/droopy-ctf-walkthrough-full-tutorial/\#brute-force-attack-on-truecrypt-volume-truecrack
```

---
### Achievements 🎉

> **Info** Owned TrueSecrets from Hack The Box!
> I have just owned challenge TrueSecrets from Hack The Box  
> [https://www.hackthebox.com/achievement/challenge/768975/446](https://www.hackthebox.com/achievement/challenge/768975/446)  

```
Alhamdulillah 
```

```
first time solving a challenge in HTB within TOP 13
```

---

*From your own notes: `HTB Challenges/Forensics/Challenge- TrueSecrets.md`*
