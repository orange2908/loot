---
title: "Hoarded Flag - 1337UP LIVE CTF"
category: "forensics"
subcategory: "memory"
type: "writeup"
tags: ["forensics", "volatility3", "volatility", "memory-forensics", "hoarded", "memory", "1337up-live-ctf", "ctf-writeup"]
summary: "It's a memory dump, so we can analyse with volatility"
source:
  name: "CTFtime writeup #39675"
  url: "https://ctftime.org/writeup/39675"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/forensics/hoarded_flag/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "Hoarded Flag"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** Hoarded Flag
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39675>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/forensics/hoarded_flag/>

---
It's a memory dump, so we can analyse with [volatility](<https://github.com/volatilityfoundation/volatility3>)

Iterate through each of the plugins, looking for useful info. One of those plugins checks the `cmdline` and reveals some interesting command.

```bash  
python [vol.py](http://vol.py) -f memory_dump.raw windows.cmdscan

** 1032 conhost.exe 0x23442febbf0 _COMMAND_HISTORY.CommandBucket_Command_1 0x2344310e0e0 7z a -pScaredToDeathScaredToLook1312 -mhe flag.7z flag.zip  
```

So, `7z` was used to encrypt a flag using the password `ScaredToDeathScaredToLook1312`

Search for these files with the `filescan` plugin.

```bash  
python [vol.py](http://vol.py) -f memory_dump.raw windows.filescan | grep flag

0xb20dbd74d5f0.0\Users\cat\Desktop\flag.zip  
0xb20dbd74e720 \Users\cat\Desktop\flag.7z  
```

Download one of those (password for both is the same)

```bash  
python [vol.py](http://vol.py) -f memory_dump.raw windows.dumpfiles.DumpFiles --virtaddr 0xb20dbd74e720  
```

Finally, extract the flag: `7z x flag.zip`

Flag: `INTIGRITI{7h3_m3m0ry_h0ld5_7h3_53cr375}`
