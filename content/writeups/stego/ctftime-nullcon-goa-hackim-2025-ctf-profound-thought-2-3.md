---
title: "Profound thought - Nullcon Goa HackIM 2025 CTF"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "lsb", "zsteg", "profound", "thought", "image", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "imagedata .. text: \"286-0.\\t\\n\\t\""
source:
  name: "CTFtime writeup #39932"
  url: "https://ctftime.org/writeup/39932"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Profound thought"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Profound thought
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39932>

---
```  
zsteg l5b245c11.png  
imagedata .. text: "286-0.\t\n\t"  
b1,r,lsb,xy .. text: "rzsZA>FCNR^_]\""  
b1,r,msb,xy .. file: OpenPGP Public Key  
b1,g,msb,xy .. file: OpenPGP Secret Key  
b1,rgb,lsb,xy .. text: "ENO{57394n09r4phy_15_w4y_c00l3r_7h4n_p0rn06r4phy} ENO{57394n09r4phy_15_w4y_c00l3r_7h4n_p0rn06r4phy} ENO{57394n09r4phy_15_w4y_c00l3r_7h4n_p0rn06r4phy} ENO{57394n09r4phy_15_w4y_c00l3r_7h4n_p0rn06r4phy} ENO{57394n09r4phy_15_w4y_c00l3r_7h4n_p0rn06r4phy} ENO{57"  
b2,r,msb,xy .. file: OpenPGP Secret Key  
b2,bgr,msb,xy .. file: OpenPGP Public Key  
b3,r,msb,xy .. file: RLE image data, 16888 x 4242, lower left corner: 8321, lower right corner: 65025, clear first, 16 color channels, 224 bits per pixel, 183 color map channels  
b4,r,lsb,xy .. text: "wYtE$ER\\#$DUEFuREEf2E%5"  
b4,g,lsb,xy .. text: "#\"5DQ232UT2"  
```
