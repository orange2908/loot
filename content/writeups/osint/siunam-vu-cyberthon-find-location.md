---
title: "Find location - VU-Cyberthon 2023"
category: "osint"
subcategory: "metadata"
type: "writeup"
tags: ["osint", "exiftool", "find", "location", "metadata", "open-source-intelligence"]
summary: "In this challenge, we there's an image file:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/VU-Cyberthon-2023/OSINT/Find-location/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/OSINT/Find-location/README.md"
ctf:
  name: "VU-Cyberthon"
  year: 2023
  challenge: "Find location"
---

## Source

- **CTF:** VU-Cyberthon 2023
- **Challenge:** Find location
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/VU-Cyberthon-2023/OSINT/Find-location/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/VU-Cyberthon-2023/OSINT/Find-location/README.md>

---
# Find location

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225152333.png)

## Find the flag

**In this challenge, we there's an image file:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225152422.png)

**Let's download it:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/OSINT/Find-location)-[2023.02.25|15:23:52(HKT)]
└> wget https://vuknf.file.core.windows.net/vucyberthon2023/Location.jpeg\?sv\=2021-10-04\&st\=2023-02-20T12%3A21%3A10Z\&se\=2024-02-21T12%3A21%3A00Z\&sr\=f\&sp\=r\&sig\=8wpC74vfb64zxWKobYWFM48WN9FtIzbW0rhvgSXTCfI%3D
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/OSINT/Find-location)-[2023.02.25|15:24:30(HKT)]
└> mv Location.jpeg\?sv=2021-10-04\&st=2023-02-20T12:21:10Z\&se=2024-02-21T12:21:00Z\&sr=f\&sp=r\&sig=8wpC74vfb64zxWKobYWFM48WN9FtIzbW0rhvgSXTCfI= Location.jpeg
```

**Now, we can use `exiftool` to view it's metadata:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/OSINT/Find-location)-[2023.02.25|15:24:42(HKT)]
└> exiftool Location.jpeg 
[...]
X Resolution                    : 1
Y Resolution                    : 1
XMP Toolkit                     : FILE
Location                        : VU{d5bc0961009b25633293206cde4ca1e0}
```

We found the flag!

- **Flag: `VU{d5bc0961009b25633293206cde4ca1e0}`**

# Conclusion

What we've learned:

1. Viewing Image Metadata
