---
title: "Bad Compression - VishwaCTF 2024"
category: "rev"
subcategory: "python"
type: "writeup"
tags: ["rev", "reverse-engineering", "python-bytecode", "pyinstaller", "bad", "compression", "python", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Extract the contents of the PyInstaller-generated executable file."
source:
  name: "CTFtime writeup #39513"
  url: "https://ctftime.org/writeup/39513"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Bad%20Compression.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "Bad Compression"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** Bad Compression
- **Author team:** CyberCellVIIT
- **CTFtime tags:** reverse_engineering
- **CTFtime:** <https://ctftime.org/writeup/39513>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Bad%20Compression.pdf>

---
Step 1:  
Extract the contents of the PyInstaller-generated executable file. The source code for ‘pyinstxtractor’ has been pasted inside the [ex.py](http://ex.py) file.

Step 2:  
Decompile the .pyc file using pycdas since pycdc won't work with the latest Python versions.

Step 3:  
Use AI to reconstruct the source code part by part. Do not feed the entire text at once, as AI may approximate the code to the standard version, which won't help with the challenge.

Step 4:  
After generating the entire code, you will notice that the compression algorithm is based on Huffman encoding. The differences compared to the standard Huffman code are outlined in the diary.

Step 5:  
The algorithm encrypts characters based on their frequency of occurrence in the string provided in the diary. Input this frequency data into the source code to obtain the prefix codes used for each character.

Step 6:  
Write a script to decrypt the given file using the extracted prefix codes.
