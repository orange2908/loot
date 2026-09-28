---
title: "PROFESSORS INHERITANCE - VishwaCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "professors", "inheritance", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Q1: Find the next number in the series:"
source:
  name: "CTFtime writeup #39515"
  url: "https://ctftime.org/writeup/39515"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/Professor&#39;s%20Inheritance.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "PROFESSORS INHERITANCE"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** PROFESSORS INHERITANCE
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39515>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/Professor&#39;s%20Inheritance.pdf>

---
### Solution:

Q1: Find the next number in the series:  
Series: 5, 12, 23, 50, 141, 488, 1859, 7326, ?  
Answer: 29177

Step 1:

Decode the given audio file using Deep Sound 2.0, with the answer to the series question (29177) as the password.  
You will find an image named "maths_embed.png" encrypted inside the audio file.  
Step 2:

Decrypt the image using Stegosuite GUI.  
Inside, you'll find the following question:  
"The letters of the word 'VISHWA' are permuted in all possible ways and arranged as in a dictionary. What is the rank of the word 'VISHWA'?"

Answer: VISHWA-545

Example: If the answer to the question was 127, the password for the next file would be VISHWA-127.

For this challenge, the password for the next step is VISHWA-545.

Step 3:

Decrypt the file "[encryptedcode.txt.nc](http://encryptedcode.txt.nc)" using the following command:  
bash

mcrypt -d [encryptedcode.txt.nc](http://encryptedcode.txt.nc)  
Use the passphrase VISHWA-545.

Step 4:

After decryption, you will find an obfuscated JavaScript (JS) function.  
Use an online deobfuscator like Deobfuscate to deobfuscate the JS code.  
Run the hexArray function in VS Code or any other compiler to get the flag.
