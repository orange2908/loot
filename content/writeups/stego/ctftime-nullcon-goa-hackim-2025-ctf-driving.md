---
title: "driving - Nullcon Goa HackIM 2025 CTF"
category: "stego"
subcategory: "metadata"
type: "writeup"
tags: ["stego", "exiftool", "driving", "metadata", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We are given a strange video (.mp4) of a “banana driving a Car xD”."
source:
  name: "CTFtime writeup #39996"
  url: "https://ctftime.org/writeup/39996"
original_source: "https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "driving"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** driving
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39996>
- **Original writeup:** <https://w1r3w01f.github.io/2025/02/02/Nullcon-2025/>

---
# driving

## Description  
We are given a strange video (.mp4) of a “banana driving a Car xD”.

## Solution

\- On extracting the frames of the video using the frames per second rates of 30 fps we get 387 frames.

```  
ffmpeg -i driving.mp4 -vf "fps=30" frame_%04d.png  
```

\- Also the Artist in the video’s metadata looks like a hint for the challenge.

```  
$ exiftool driving.mp4  
ExifTool Version Number : 12.40  
File Name : driving.mp4  
Directory : .  
File Size : 2.2 MiB  
File Modification Date/Time : 2025:02:01 14:06:53+05:30  
File Access Date/Time : 2025:02:02 18:56:35+05:30  
File Inode Change Date/Time : 2025:02:01 14:06:57+05:30  
File Permissions : -rwxrwxrwx  
File Type : MP4  
File Type Extension : mp4  
MIME Type : video/mp4  
Major Brand : MP4 v2 [ISO 14496-14]  
Minor Version : 0.0.0  
Compatible Brands : mp42, mp41  
Movie Header Version : 0  
Create Date : 2025:01:12 15:35:52  
Modify Date : 2025:01:12 15:35:52  
Time Scale : 90000  
Duration : 12.93 s  
Preferred Rate : 1  
Preferred Volume : 100.00%  
Preview Time : 0 s  
Preview Duration : 0 s  
Poster Time : 0 s  
Selection Time : 0 s  
Selection Duration : 0 s  
Current Time : 0 s  
Next Track ID : 3  
Track Header Version : 0  
Track Create Date : 2025:01:12 15:35:52  
Track Modify Date : 2025:01:12 15:35:52  
Track ID : 1  
Track Duration : 12.90 s  
Track Layer : 0  
Track Volume : 0.00%  
Image Width : 640  
Image Height : 480  
Graphics Mode : srcCopy  
Op Color : 0 0 0  
Compressor ID : hvc1  
Source Image Width : 640  
Source Image Height : 480  
X Resolution : 72  
Y Resolution : 72  
Compressor Name : HEVC Coding  
Bit Depth : 24  
Video Frame Rate : 30  
Matrix Structure : 1 0 0 0 1 0 0 0 1  
Media Header Version : 0  
Media Create Date : 2025:01:12 15:35:52  
Media Modify Date : 2025:01:12 15:35:52  
Media Time Scale : 44100  
Media Duration : 12.93 s  
Media Language Code : eng  
Balance : 0  
Handler Description : Alias Data Handler  
Audio Format : mp4a  
Audio Channels : 2  
Audio Bits Per Sample : 16  
Audio Sample Rate : 44100  
Handler Type : Metadata  
XMP Toolkit : Image::ExifTool 13.00  
Artist : 2+(10*n) for all n>=10  
Media Data Size : 2271847  
Media Data Offset : 12469  
Image Size : 640x480  
Megapixels : 0.307  
Avg Bitrate : 1.41 Mbps  
Rotation : 0  
```

\- Now on a simple inspection of the frames, one thing that catches our eye is the presence of `}` in the frame number 383 (indexing from 1).  
\- Then by the Artist hint on inspecting frames on intervals of 10 i.e the following frames, `[103,113,123,133,143,153,163,173,183,193,203,213,223,233,243,253,263,273,283,293,303,313,323,333,343,353,363,373,383]`   
\- we find that each of those frames contain one character of the flag in the following order, `Left Top → Right Top → Right Bottom → Left Bottom → Left Top…` , which leads us to our flag.

## Flag  
`ENO{Y0U_4R3_DR1V1N6_M3_CR4ZY}`
