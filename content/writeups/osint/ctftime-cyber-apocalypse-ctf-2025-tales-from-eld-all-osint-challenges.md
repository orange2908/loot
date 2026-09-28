---
title: "All OSINT challenges - Cyber Apocalypse CTF 2025: Tales from Eldoria"
category: "osint"
subcategory: "lattice"
type: "writeup"
tags: ["osint", "lattice", "geolocation", "challenges", "cyber-apocalypse-ctf-2025-tale", "cyber-apocalypse-ctf-2025-tales-fr", "2025", "ctf-writeup"]
summary: "In the highest tower of Eldoria's archives, Nyla manipulates a crystal scrying glass, focusing on a forbidden fortress in the desert kingdoms."
source:
  name: "CTFtime writeup #40125"
  url: "https://ctftime.org/writeup/40125"
ctf:
  name: "Cyber Apocalypse CTF 2025: Tales from Eldoria"
  year: 2025
  challenge: "All OSINT challenges"
---

## Metadata

- **CTF:** Cyber Apocalypse CTF 2025: Tales from Eldoria
- **Task:** All OSINT challenges
- **Author team:** N0C715
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/40125>

---
# **The Mechanical Bird’s Nest**

## **Challenge Description:**  
In the highest tower of Eldoria's archives, Nyla manipulates a crystal scrying glass, focusing on a forbidden fortress in the desert kingdoms. The Queen's agents have discovered a strange mechanical bird within the fortress walls—an unusual flying machine whose exact position could reveal strategic secrets. Nyla's fingers trace precise measurement runes across the crystal's surface as the aerial image sharpens. Her magical lattice grid overlays the vision, calculating exact distances and positions. The blue runes along her sleeves pulse rhythmically as coordinates appear in glowing script. Another hidden truth uncovered by the realm's premier information seeker, who knows that even the most distant secrets cannot hide from one who sees with magical precision.

The goal is to retrieve the exact latitude and longitude in the format:

> `HTB{[XX.XXX_-XXX.XXX](http://XX.XXX_-XXX.XXX)}`

\---

## **Step 1: Gathering Intelligence**

![](<https://i.ibb.co/5X6jBM8L/birdnest.png>)

The first step involved analyzing the provided satellite image to identify recognizable features and landmarks. The image displayed:

1\. A helipad marking on the runway   
2\. A unique dirt road leading to a group of buildings   
3\. Aircraft-shaped objects similar to the mechanical bird 

To find out more, the photo was uploaded to **Google Lens** for a reverse image search. The search indicated that the place is located in **Area 51**, which is a famous military base in **Nevada, USA.**

\---

## **Step 2: Pinpointing the Coordinates**

Knowing that the location was within **Area 51**, the next step was to manually search the base using **Google Maps**. The following visual markers from the image were used for reference:

1\. The helipad sign on the runway   
2\. The clear road formation around the structures   
3\. The location of the mechanical bird on the airstrip 

Carefully looking through the map, the point was located, which equates to the coordinates:

```  
✅ 37.247092, -115.812317  
```  
![](<https://i.ibb.co/F40TG1Ry/Screenshot-2025-03-29-223055.png>)  
\---

## **Step 3: Extracting and Submitting the Flag**

With the coordinates confirmed, the flag was presented in the correct format based on the challenge rules:

```  
✅ Flag: HTB{37.247_-115.812}  
```

Providing this flag successfully solved the challenge.

\---

## **Conclusion:**

This challenge required a combination of **image analysis**, **reverse image search**, and **manual geolocation** techniques. The key takeaway is that leveraging both automated tools like **Google Lens** and manual map analysis provides a robust approach to identifying and verifying precise locations. **Patience** and **attention to visual details** were essential in pinpointing the mechanical bird's position accurately.

```  
Flag: HTB{37.247_-115.812}  
```

\---

# **Team Name: NØCTIS**
