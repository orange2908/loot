---
title: "The Real Admin - KnightCTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "real", "admin", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "Use the following display filter to exclude packets with the IP address 192.168.1.9 and focus on HTTP packets:"
source:
  name: "CTFtime writeup #39813"
  url: "https://ctftime.org/writeup/39813"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "The Real Admin"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** The Real Admin
- **Author team:** NCA@Nepal
- **CTFtime:** <https://ctftime.org/writeup/39813>

---
## Step 1: Apply Display Filter  
Use the following display filter to exclude packets with the IP address `192.168.1.9` and focus on HTTP packets:  
```  
!(ip.addr == 192.168.1.9) && http  
```

## Step 2: Search for "admin" in the Packet Data  
1\. Press CTRL + F (or Command + F on macOS) to open the search bar.  
2\. In the search bar:  
3\. - **Find**: Enter the string admin.  
\- **Search In**: Select Packet Details (or Packet Bytes for deeper matches).  
\- Click **Find** to locate packets containing the string admin.

## Expected Outcome & Flag  
1\. This process will filter out HTTP packets that do not belong to `192.168.1.9`.  
2\. Searching for admin will highlight packets containing the string `admin`.  
3\. If `192.168.1.3` appears in the packet data, it is likely the actual IP address of the admin.

## Flag  
`KCTF{ip_of_admin}` == `KCTF{192.168.1.3}`
