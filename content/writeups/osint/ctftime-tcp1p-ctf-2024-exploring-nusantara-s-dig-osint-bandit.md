---
title: "[OSINT] Bandit - TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
category: "osint"
type: "writeup"
tags: ["osint", "bandit", "tcp1p-ctf-2024-exploring-nusan", "tcp1p-ctf-2024-exploring-nusantara", "2024", "ctf-writeup"]
summary: "An Jieyab as informant took a photo of a vehicle, can you find the location?"
source:
  name: "CTFtime writeup #39563"
  url: "https://ctftime.org/writeup/39563"
original_source: "https://github.com/juke-33/Write-ups/tree/main/TCP1P%20CTF%202024/OSINT/Bandit"
ctf:
  name: "TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
  year: 2024
  challenge: "[OSINT] Bandit"
---

## Metadata

- **CTF:** TCP1P CTF 2024: Exploring Nusantara's Digital Realm
- **Task:** [OSINT] Bandit
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39563>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/TCP1P%20CTF%202024/OSINT/Bandit>

---
## Challenge

Bandit

An Jieyab as informant took a photo of a vehicle, can you find the location?

The flag is name the location and date example TCP1P{Town, Coutry. Month Year}

Example : TCP1P{Yogyakarta, Indonesia. June 2010}

## Solution

We uploaded the photo on Google Lens to get any useful information about it.

Found out it was a plate in Indonesia, so searched for this specific plate and got [this](<https://platesmania.com/id/nomer24795105>) site.

Flag: `TCP1P{Malang, Indonesia. October 2019}`
