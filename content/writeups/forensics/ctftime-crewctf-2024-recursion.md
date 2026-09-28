---
title: "Recursion - CrewCTF 2024"
category: "forensics"
subcategory: "usb"
type: "writeup"
tags: ["usb", "forensics", "crewctf2024", "usb-hid", "recursion", "crewctf", "crewctf-2024", "2024", "ctf-writeup"]
summary: "Link to my original write-up: <https://medium.com/@chaoskist/crewctf-2024-recursion-50-points-forensics-challenge-be67bd58f2fe>"
source:
  name: "CTFtime writeup #39364"
  url: "https://ctftime.org/writeup/39364"
ctf:
  name: "CrewCTF 2024"
  year: 2024
  challenge: "Recursion"
---

## Metadata

- **CTF:** CrewCTF 2024
- **Task:** Recursion
- **Author team:** ByTheW4y
- **CTFtime tags:** usb, forensics, crewctf2024
- **CTFtime:** <https://ctftime.org/writeup/39364>

---
# CrewCTF 2024 - Recursion (50 points) - Forensics Challenge  
Link to my original write-up: <https://medium.com/@chaoskist/crewctf-2024-recursion-50-points-forensics-challenge-be67bd58f2fe>

We got a `usb.pcapng` indicating that we will be deal with USB traffic to get a flag but whats about "Recursion"? we will find out soon

![1](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*oDKVfuxn_vPG3xXDjy5wbw.png>)

I’ve read some write-up about USB traffic challenge and those challenges are about getting keystroke from USB traffic but when I opened provided pcapng file, I noticed that this challenge is about file transferring and we need to export a file out from `USB_BULK out/in` packet which we will can see that this packet has the largest packet length and its also indicates that this file is gzip file from “Left Capture Data”

![2](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*7V2PVIjO2dnoiKCCpbDPQw.png>)

We can test it with Detect It Easy to see if we really got gzip file which we can see that we got the right one here

![3](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*RqRhWCewc6zRzCZwNC3vBQ.png>)

If you’re using Windows, just use 7z to extract everything then we will have this `layer4.pcapng` file indicating we need to get through more 4 layers before getting a flag hence the challenge name.

![4](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*5Opp-ZcwBF2ztKLu-le4Rg.png>)

And in this file, we will find 7z file was transferred so just export it out

Keep continue doing this from layer4 to layer1 and lastly we will have pcapng file being transferred 

![5](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*lKlvfxieMnEOA_QDDlEIUA.png>)

And from that pcapng file, we will have a flag of this challenge
