---
title: "USBNet - Nullcon Goa HackIM 2025 CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "cyberchef", "usbnet", "network", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "How good are your USB skills?"
source:
  name: "CTFtime writeup #39990"
  url: "https://ctftime.org/writeup/39990"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "USBNet"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** USBNet
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39990>

---
# usbnet

## Description  
How good are your USB skills? Show me by recovering the flag!

Author: @gehaxelt

## Solution  
\- We received a PCAP file and, after opening it in Wireshark, realized that almost all the packets belonged to the USB protocol.

\- I started analyzing the capture data of all URB_BULK IN packets since they usually contain transferred user activity data. After scrolling through the packets, I noticed that packet 170 had some PNG magic headers in its capture data.

\- Leftover Capture Data of Packet 170:  
```  
4e434d480c003800f3011000000000004e434d30100000002000d30100000000000ec69553510ac8930bdbd00800450001c57ab840004006ed03c0a82801c0a828250539a9004127595260d618f38018007f27ea00000101080a2adeb753481735eb89504e470d0a1a0a0000000d494844520000006f0000006f0103000000d80b0c2300000006504c5445000000ffffffa5d99fdd0000000274524e53ffffc8b5dfc7000000097048597300000b1200000b1201d2dd7efc0000012349444154388dd5d43b8e84300c0660230a77cb0522e51ae97225b8008f0bc095d2718d917281d0a588f8d7cc6877b40d4e33c546a1f890421c6387f067d0ff6022ea99865088acca03a5e7326433a182c15c0bd9f45cc5dec5b99a13e2964b15718534d23bc81bca7987ddc8fc3dfe0d659cde8cfe9dd81b264f53c696b1be3e75cbd3b5896d9223bb1a9a2e9b6ea79175268a472823c7d343a53cb2b0c9ed11ac4a59b2fa32042c3b7472e9f6385f2fad4aec56e6caedeca0f2c844f4e87ea252283f1d66c898192a114c93a983f97a665221e212248d65f43a131be276bb62834a19071e43b089754ac54a05ae2c456b555ebd00e90529ad0a4aff66c924357b15a5fc928f0beae8a80bd75e3ae5cea198a88c4ee7b37f5bc0ce04959fbb723fc56fd3d60e31e00c8f5e0000000049454e44ae426082  
```

\- Extracted PNG Hex:  
```  
89504e470d0a1a0a0000000d494844520000006f0000006f0103000000d80b0c2300000006504c5445000000ffffffa5d99fdd0000000274524e53ffffc8b5dfc7000000097048597300000b1200000b1201d2dd7efc0000012349444154388dd5d43b8e84300c0660230a77cb0522e51ae97225b8008f0bc095d2718d917281d0a588f8d7cc6877b40d4e33c546a1f890421c6387f067d0ff6022ea99865088acca03a5e7326433a182c15c0bd9f45cc5dec5b99a13e2964b15718534d23bc81bca7987ddc8fc3dfe0d659cde8cfe9dd81b264f53c696b1be3e75cbd3b5896d9223bb1a9a2e9b6ea79175268a472823c7d343a53cb2b0c9ed11ac4a59b2fa32042c3b7472e9f6385f2fad4aec56e6caedeca0f2c844f4e87ea252283f1d66c898192a114c93a983f97a665221e212248d65f43a131be276bb62834a19071e43b089754ac54a05ae2c456b555ebd00e90529ad0a4aff66c924357b15a5fc928f0beae8a80bd75e3ae5cea198a88c4ee7b37f5bc0ce04959fbb723fc56fd3d60e31e00c8f5e0000000049454e44ae426082  
```

\- I then used CyberChef to decode the data and successfully retrieved the flag.

## Flag

`ENO{USB_ETHERNET_ADAPTER_ARE_COOL_N!C3}`
