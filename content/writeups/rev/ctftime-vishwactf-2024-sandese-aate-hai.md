---
title: "SANDESE AATE HAI - VishwaCTF 2024"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "ghidra", "sandese", "aate", "hai", "static-analysis", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "In this challenge, we are given an encrypted txt file in the form of a 2D square array."
source:
  name: "CTFtime writeup #39511"
  url: "https://ctftime.org/writeup/39511"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Sandese%20Aate%20Hai.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "SANDESE AATE HAI"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** SANDESE AATE HAI
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39511>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Sandese%20Aate%20Hai.pdf>

---
### Solution:  
In this challenge, we are given an encrypted txt file in the form of a 2D square array. We are also given a program by which the encryption happened. We have to understand the code and reverse it to decrypt the encrypted file to get the original txt and possibly our flag.

When you open the code in Ghidra, you will find a lot of if-else statements. These were the if-else statements used to encrypt the file. Upon understanding the code, we realize that this code depends on whether the given element is prime or divisible by 2, 3, or 5. This is a form of Markov chain which decides its next state depending on the divisibility of current elements. Once we reverse the code, we get the decrypted 2D matrix in spiral form and, fortunately, our flag.

```  
Flag:  
VishwaCTF{4nd23y_4nd23y3v1ch_m42k0v}  
```
