---
title: "MYSTERIOUS OLD CASE - VishwaCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "mysterious", "case", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "The audio is reversed and embedded within music clips."
source:
  name: "CTFtime writeup #39516"
  url: "https://ctftime.org/writeup/39516"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/Mysterious%20Old%20Case.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "MYSTERIOUS OLD CASE"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** MYSTERIOUS OLD CASE
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39516>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Steganography/Mysterious%20Old%20Case.pdf>

---
### Solution:  
The audio is reversed and embedded within music clips. After reversing the audio, the following information is revealed:  
"I am Dan Cooper, it is 24/11/1971. Now I have left from Seattle and headed towards Reno. I have got all my demands fulfilled. I have made some changes in the flight log and uploaded it to a remote server. The file is encrypted; the hint for decryption is the airliner that I am flying in. Most importantly, the secret key is split and hidden at every element of the Fibonacci series starting from 2."  
The challenge references the mysterious case of Dan Cooper (DB Cooper), which occurred in 1971, so the text provides hints for solving the puzzle. After analyzing the metadata of the audio file, more clues are uncovered:  
* The zip file is 100 MB, not 7 GB.  
* DB Cooper.  
* 727/305.  
* •1971.   
* The password for the zip file is all lowercase with no spaces.  
A Google Drive link is provided, which leads to the flight_log.zip file, as mentioned in the text. The zip file is password-protected, and the hints for decryption are given in both the text and the metadata. The password is "northwestorientairlines" (the airliner Dan Cooper flew in, all lowercase with no spaces).  
After extracting the zip file, you find 1000 flight logs. Based on the information in the metadata and the real flight DB Cooper was on, the flight log to look for is flight 305. All other logs are dated 2024, except for flight 305, which is dated 1971 and references the Boeing 727.  
Opening flight log 305 reveals a pattern where the flag is encoded using the Fibonacci sequence, starting from 2.  
`Flag: VishwaCTF{1_W!LL_3E_B@CK}`
