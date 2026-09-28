---
title: "WE_ARE_VALORANT - VishwaCTF 2024"
category: "forensics"
subcategory: "image"
type: "writeup"
tags: ["forensics", "steghide", "valorant", "image", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "The key to this challenge lies in the word Signature."
source:
  name: "CTFtime writeup #39514"
  url: "https://ctftime.org/writeup/39514"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/We%20are%20Valorant.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "WE_ARE_VALORANT"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** WE_ARE_VALORANT
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39514>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/We%20are%20Valorant.pdf>

---
### Solution:

The key to this challenge lies in the word Signature. Here's the step-by-step solution:

* File Signature Modification:  
The phrase "Signature move" hints that the file signature of the given .jpg image has been altered. The standard file signature for a JPEG image is FF D8 FF E0, but in this case, the signature has been changed to FF F8 D0 E0.

You can restore the signature by using a hex editor like hexedit in Linux, or use any online hex editor tool.  
After editing the signature back to FF D8 FF E0, the image file becomes accessible.  
* Command for hexedit:

```  
bash

hexedit image.jpg  
```  
* Text Extraction Using Steganography:  
Once the image is accessible, the next step is to extract hidden data from the image. You can use steghide or any online tool to extract the hidden text file from the image.

The tool will prompt you for a passphrase.  
* Passphrase from the Video/Gif:  
The passphrase is hidden within the attached video/gif file. Watch the video carefully, frame by frame, as there's a brief moment where a text appears. The text visible in one of the frames is: Tenz.

Use the passphrase Tenz to unlock the hidden text from the image.  
* Retrieve the Flag:  
After entering the passphrase, the hidden text file is revealed. It contains the flag in plain text format.

`Flag: VishwaCTF{you_are_invited_to_the_biggest_valorant_event}`
