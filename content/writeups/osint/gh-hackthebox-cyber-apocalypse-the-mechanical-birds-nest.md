---
title: "The Mechanical Birds Nest - cyber apocalypse 2025"
category: "osint"
subcategory: "lattice"
type: "writeup"
tags: ["osint", "lattice", "mechanical", "birds", "nest", "open-source-intelligence"]
difficulty: "easy"
summary: "osint writeup for \"The Mechanical Birds Nest\" from cyber apocalypse - techniques: lattice, mechanical, birds, nest, open-source-intelligence."
source:
  name: "hackthebox/cyber-apocalypse-2025"
  url: "https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/OSINT/The%20%20Mechanical%20Birds%20Nest/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2025
  challenge: "The Mechanical Birds Nest"
---

## Source

- **CTF:** cyber apocalypse 2025
- **Challenge:** The Mechanical Birds Nest
- **Repository:** [hackthebox/cyber-apocalypse-2025](https://github.com/hackthebox/cyber-apocalypse-2025)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2025/blob/843bdcc55112c5b68b05b5fe706fbbb1dad9b551/OSINT/The%20%20Mechanical%20Birds%20Nest/README.md>

---
# The Mechanical Bird's Nest

**Date:** 18 of March 2025
**Prepared By:** Joaquin Iglesias  
**Challenge Author(s):** Joaquin Iglesias  
**Difficulty:** Easy  
**Classification:** Official  

## Synopsis
In the highest tower of Eldoria's archives, Nyla manipulates a crystal scrying glass, focusing on a forbidden fortress in the desert kingdoms. The Queen's agents have discovered a strange mechanical bird within the fortress walls—an unusual flying machine whose exact position could reveal strategic secrets. Nyla's fingers trace precise measurement runes across the crystal's surface as the aerial image sharpens. Her magical lattice grid overlays the vision, calculating exact distances and positions. The blue runes along her sleeves pulse rhythmically as coordinates appear in glowing script. Another hidden truth uncovered by the realm's premier information seeker, who knows that even the most distant secrets cannot hide from one who sees with magical precision.

## Challenge Description
A high-resolution satellite scan of Area 51 has captured an unidentified helicopter within a secure perimeter. Your objective is to locate this aircraft using publicly available satellite imagery and determine its precise latitude and longitude. By cross-referencing the image with Google Maps, you can identify the helicopter’s position and extract its coordinates.  

## Steps to Solve
1. Open **Google Maps** or **Google Earth** and navigate to Area 51, Nevada.  
2. Switch to **satellite view** and carefully scan the facility for a helicopter.  
3. Identify key landmarks and compare them with the provided image.  
4. Pinpoint the helicopter’s location and extract its precise coordinates:  
   - **Latitude:** 37°14'49.5" N  
   - **Longitude:** 115°48'44.3" W  
5. Submit the flag in the required format.  

## Flag Format
```
HTB{latitude_longitude}
```
