---
title: "Decrypt SMB3 Traffic (Forensics)"
category: "forensics"
subcategory: "network"
type: "technique"
tags: ["my-notes", "personal", "pcap", "decrypt", "smb3", "traffic", "forensics"]
summary: "Personal note: Decrypt SMB3 Traffic (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Decrypt SMB3 Traffic.md"
---

### What we need

```
user= "" 
domain= ""
password_hash = ""
NTProofStr = ""
EncryptedSessionKey = ""

ResponseKeyNT = HMAC_MD5(password_hash, (user.upper()+domain.upper()).encode('utf16-le'))
KeyExchangeKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
RandomSessionKey = RC4(KeyExchangeKey,EncryptedSessionKey)
```

### Get password from lsass.dmp using mimikatz

```
sekurlsa::minidump lsass.dmp
```

```
sekurlsa::logonPasswords
```

### Get the NTLM Hash

```
sekurlsa::logonPasswords
```

### Script

> **Info** Random Session Key calculator based off of data from a packet capture
> Random Session Key calculator based off of data from a packet capture You can't perform that action at this time. You signed in with another tab or window. You signed out in another tab or window. Reload to refresh your session. Reload to refresh your session.  
> [https://gist.github.com/khr0x40sh/747de1195bbe19f752e5f02dc22fce01](https://gist.github.com/khr0x40sh/747de1195bbe19f752e5f02dc22fce01)  

### How to run

```
python calc.hash.py -u athomson -d CORP -n d047ccdffaeafb22f222e15e719a34d4 -k 032c9ca4f6908be613b240062936e2d2 -p test
```

### Reference

```
https://domdom.tistory.com/465
```

```
https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2
```

```
https://social.msdn.microsoft.com/Forums/en-US/689077f5-207e-495c-aece-01e345ebb80c/ntlmv2-session-key?forum=os_fileservices
```

---

*From your own notes: `Forensics/Decrypt SMB3 Traffic.md`*
