---
title: "Scattered in the fog - TSG CTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "scattered", "fog", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "1\\. Randomly select three points and use them to determine a plane."
source:
  name: "CTFtime writeup #39751"
  url: "https://ctftime.org/writeup/39751"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "Scattered in the fog"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** Scattered in the fog
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39751>

---
## Problem-solving approach:

1\. Randomly select three points and use them to determine a plane.  
2\. Check how many scattered points lie on this plane. If a substantial number of points are found to lie on the same plane, it can be considered as identifying a "scattered point plane."  
3\. Using this plane, calculate the rotation matrix to analyze the transformation relationship among the scattered points.  
4\. Based on the obtained rotation matrix, reverse-engineer the original positions of the scattered points and count the number of points on each plane.  
5\. Leverage the one-to-one correspondence between the number of scattered points and the pixel count of letters (since the pixel count for most letters is unique) to map the point count to the corresponding letters.  
6\. Finally, decode the correct flag based on the reconstructed content and the principles of readability.
