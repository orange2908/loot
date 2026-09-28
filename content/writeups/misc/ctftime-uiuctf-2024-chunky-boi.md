---
title: "Chunky Boi - UIUCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "chunky", "boi", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "Searched the photo to find any clues of the airport or the planes."
source:
  name: "CTFtime writeup #39289"
  url: "https://ctftime.org/writeup/39289"
original_source: "https://github.com/juke-33/Write-ups/tree/main/UIUCTF%202024/OSINT/Chunky%20Boi"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "Chunky Boi"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** Chunky Boi
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39289>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/UIUCTF%202024/OSINT/Chunky%20Boi>

---
Searched the photo to find any clues of the airport or the planes.

Found that these planes with the blue face are from the [Alaska Airlines](<https://www.alaskaair.com/>).

While searching for the background buildings i found [this](<https://www.youtube.com/watch?v=J2WYaQ07aVY>) video that gives the location of the airport.

So put the airport on maps and found the exact spot of the plane and the coordinates.

Tried to find any information about the plane and every result was a Boeing C-17.

Finally, the exact plane type was [Boeing C-17 Globemaster III](<https://en.wikipedia.org/wiki/Boeing_C-17_Globemaster_III>).

Flag: `uiuctf{Boeing C-17 Globemaster III, 47.462, -122.303}`
