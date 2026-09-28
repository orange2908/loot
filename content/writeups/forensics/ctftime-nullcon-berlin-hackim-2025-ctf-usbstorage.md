---
title: "usbstorage - Nullcon Berlin HackIM 2025 CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "usbstorage", "network", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We are given a packet capture (.pcapng) that records USB storage activity."
source:
  name: "CTFtime writeup #40404"
  url: "https://ctftime.org/writeup/40404"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "usbstorage"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** usbstorage
- **Author team:** numatrixx
- **CTFtime:** <https://ctftime.org/writeup/40404>

---
# USB Storage Forensics Writeup

## Challenge Description  
We are given a packet capture (`.pcapng`) that records USB storage activity.   
The story: a file was copied from a USB drive to a laptop and then deleted, but the friend could still see what was copied by analyzing the USB traffic.

The goal: recover the secret file or flag from the USB capture.

\---

## Step 1: Inspect the PCAPNG  
We start by looking for human-readable strings inside the capture:  
```bash  
strings usbstorage.pcapng | less  
```  
Among normal system artifacts (CPU info, kernel version, etc.), we found something very interesting:

```  
flag.tar.gz  
```

This indicated that a file named **flag.tar.gz** was transferred via USB.

\---

## Step 2: Search for File Signatures  
USB captures often contain the raw data being transferred. To locate embedded files, we search for known file signatures (magic bytes).   
For GZIP archives, the magic bytes are:

```  
1F 8B 08  
```

We scan the raw PCAP data and extract chunks starting from these bytes.

\---

## Step 3: Extract Embedded File  
By carving from the GZIP header, we recovered an archive:

```  
extracted_0.tar.gz  
```

When inspecting the contents of this tarball:

```bash  
tar -tzf extracted_0.tar.gz  
```

We saw:  
```  
flag.gz  
```

\---

## Step 4: Decompress the Inner File  
We extract and decompress:

```bash  
tar -xzf extracted_0.tar.gz  
gunzip flag.gz  
cat flag  
```

This revealed the flag.

\---

## Final Flag  
```  
ENO{USB_STORAGE_SHOW_ME_THE_FLAG_PLS}  
```

\---

## Lessons Learned  
\- USB captures can leak **full file contents**, not just filenames.   
\- Even if a file is deleted later, if the transfer was captured, forensic tools can reconstruct it.   
\- Always treat USB captures as sensitive—metadata and raw payloads may expose secrets.
