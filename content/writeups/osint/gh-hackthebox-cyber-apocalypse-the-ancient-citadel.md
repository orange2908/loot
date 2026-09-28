---
title: "The Ancient Citadel - cyber apocalypse 2025"
category: "osint"
subcategory: "osint"
type: "writeup"
tags: ["osint", "ancient", "citadel", "open-source-intelligence", "the-ancient-citadel", "cyber-apocalypse"]
difficulty: "medium"
summary: "osint writeup for \"The Ancient Citadel\" from cyber apocalypse - techniques: ancient, citadel, open-source-intelligence, the-ancient-citadel, cyber-apocalypse."
source:
  name: "hackthebox/cyber-apocalypse-2025"
  url: "https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/OSINT/The%20Ancient%20Citadel/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2025
  challenge: "The Ancient Citadel"
---

## Source

- **CTF:** cyber apocalypse 2025
- **Challenge:** The Ancient Citadel
- **Repository:** [hackthebox/cyber-apocalypse-2025](https://github.com/hackthebox/cyber-apocalypse-2025)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/OSINT/The%20Ancient%20Citadel/README.md>

---
# The Ancient Citadel

**Date:** 18 of March 2025
**Prepared By:** Joaquin Iglesias  
**Challenge Author(s):** Joaquin Iglesias  
**Difficulty:** Medium  
**Classification:** Official  

## Synopsis
Deep in her sanctum beneath Eldoria's streets, Nyla arranges seven crystalline orbs in a perfect circle. Each contains a different vision of stone battlements and weathered walls—possible matches for the mysterious fortress the Queen seeks in the southern kingdoms of Chile. The image in her central crystal pulses with ancient power, showing a majestic citadel hidden among the distant Chilean mountains. Her fingers dance across each comparison crystal, her enchanted sight noting subtle architectural differences between the visions. The runes along her sleeves glow more intensely with each elimination until only one crystal remains illuminated. As she focuses her magical threads on this final vision, precise location runes appear in glowing script around the orb. Nyla smiles in satisfaction as the fortress reveals not just its position, but its true name and history. A more challenging mystery solved by Eldoria's premier information seeker, who knows that even the most distant fortifications cannot hide their secrets from one who compares the patterns of stone and shadow.
## Description
You’ve been provided with an image of a majestic fortress in Latin America. The task is simple: reverse-search the image to begin your search for clues. Once you start searching, you’ll be directed to several castles, and you must check each one for any similarity to the structure in the image. The closer you get, the clearer the path will become.

## Steps to Solve:
1. **Reverse-search** the provided image using **Google Images**.
2. **Compare** the search results with the castle in the photo. Keep looking until you find a match.
3. **Verify** the location of the identified castle and pinpoint the **full address**.
4. **Submit** the full address as the flag.

## Assets Provided:
✔ High-resolution image of the fortress  

## Flag Format:
```
HTB{street number,postal code city, region}
```
