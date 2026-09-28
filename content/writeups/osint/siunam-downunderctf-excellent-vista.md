---
title: "Excellent-Vista! - DownUnderCTF 2023"
category: "osint"
subcategory: "metadata"
type: "writeup"
tags: ["osint", "exiftool", "exif", "excellent-vista", "metadata", "open-source-intelligence"]
summary: "What a nice spot to stop,lookout and watch time go by, EXAMINE the image and discover where this was taken."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/DownUnderCTF-2023/osint/Excellent-Vista%21/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/DownUnderCTF-2023/osint/Excellent-Vista%21/README.md"
ctf:
  name: "DownUnderCTF"
  year: 2023
  challenge: "Excellent-Vista!"
---

## Source

- **CTF:** DownUnderCTF 2023
- **Challenge:** Excellent-Vista!
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/DownUnderCTF-2023/osint/Excellent-Vista%21/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/DownUnderCTF-2023/osint/Excellent-Vista%21/README.md>

---
# Excellent Vista!

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find The Flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 768 solves / 100 points
- Author: Yo_Yo_Bro
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

What a nice spot to stop,lookout and watch time go by, EXAMINE the image and discover where this was taken.

NOTE: Flag is case-insensitive and requires placing inside `DUCTF{}` wrapper! e.g `DUCTF{Osint_Lookout}`

Author: Yo_Yo_Bro

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/DownUnderCTF-2023/images/Pasted%20image%2020230904225853.png)

## Find The Flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/osint/Excellent-Vista!/ExcellentVista.jpg):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/osint/Excellent-Vista!)-[2023.09.04|22:59:51(HKT)]
└> file ExcellentVista.jpg                                    
ExcellentVista.jpg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=7, xresolution=2158, yresolution=2166, resolutionunit=2, GPS-Data], baseline, precision 8, 4032x3024, components 3
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/DownUnderCTF-2023/images/Pasted%20image%2020230904230033.png)

**In an image file, it's important that extracting the metadata of the file, as it might leaked some sensitive information, like GPS position:**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/osint/Excellent-Vista!)-[2023.09.04|23:00:32(HKT)]
└> exiftool ExcellentVista.jpg         
[...]
GPS Version ID                  : 2.3.0.0
GPS Latitude Ref                : South
GPS Longitude Ref               : East
GPS Altitude Ref                : Above Sea Level
GPS Speed Ref                   : km/h
GPS Speed                       : 0
GPS Img Direction Ref           : True North
GPS Img Direction               : 122.5013812
GPS Dest Bearing Ref            : True North
GPS Dest Bearing                : 122.5013812
GPS Horizontal Positioning Error: 6.055886243 m
[...]
GPS Altitude                    : 70.5 m Above Sea Level
GPS Latitude                    : 29 deg 30' 34.33" S
GPS Longitude                   : 153 deg 21' 34.46" E
GPS Position                    : 29 deg 30' 34.33" S, 153 deg 21' 34.46" E
```

Nice! We found the GPS position where the image was taken!

**Let's convert that into Google Map format via ChatGPT:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/DownUnderCTF-2023/images/Pasted%20image%2020230904231153.png)

- GPS position format: `-29.5095361, 153.3595722`

**Then query with that GPS position in Google Map:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/DownUnderCTF-2023/images/Pasted%20image%2020230904232237.png)

Found it!

- **Flag: `DUCTF{Durrangan_Lookout}`**

## Conclusion

What we've learned:

1. Extracting image's metadata via `exiftool`
