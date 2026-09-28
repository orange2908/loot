---
title: "Notoriously Tricky Login Mess (Part 1) - SwampCTF 2024"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "notoriously", "tricky", "login", "mess", "network", "swampctf", "swampctf-2024", "2024", "ctf-writeup"]
summary: "Flag format: swampCTF{username}"
source:
  name: "CTFtime writeup #39025"
  url: "https://ctftime.org/writeup/39025"
original_source: "https://margheritaviola.com/2024/04/08/swampctf-2024-forensics-notoriously-tricky-login-mess-part-1-writeup/"
ctf:
  name: "SwampCTF 2024"
  year: 2024
  challenge: "Notoriously Tricky Login Mess (Part 1)"
---

## Metadata

- **CTF:** SwampCTF 2024
- **Task:** Notoriously Tricky Login Mess (Part 1)
- **Author team:** creeper
- **CTFtime tags:** forensics
- **CTFtime:** <https://ctftime.org/writeup/39025>
- **Original writeup:** <https://margheritaviola.com/2024/04/08/swampctf-2024-forensics-notoriously-tricky-login-mess-part-1-writeup/>

---
> We found out a user account has been compromised on our network. We took a packet capture of the time that we believe the remote login happened. Can you find out what the username of the compromised account is?  
Flag format: swampCTF{username}

If we examine the .pcap file in network miner, we can access Credential information.  
![](<https://margheritaviola.com/wp-content/uploads/2024/04/2024-04-06-15_49_12-Linux-VMware-Workstation.png>)

We see that the username is adamkadaban.  
```  
swampCTF{adamkadaban}  
```
