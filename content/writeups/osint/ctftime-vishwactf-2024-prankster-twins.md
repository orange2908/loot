---
title: "PRANKSTER TWINS - VishwaCTF 2024"
category: "osint"
subcategory: "archives"
type: "writeup"
tags: ["osint", "wayback", "prankster", "twins", "archives", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "The given audio contains a dialogue from a Harry Potter film, which indicates the question is based on the Harry Potter universe."
source:
  name: "CTFtime writeup #39524"
  url: "https://ctftime.org/writeup/39524"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Open%20Source%20Intelligence%20(OSINT)/Prankster%20Twins.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "PRANKSTER TWINS"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** PRANKSTER TWINS
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39524>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Open%20Source%20Intelligence%20(OSINT)/Prankster%20Twins.pdf>

---
### Solution:   
The given audio contains a dialogue from a *Harry Potter* film, which indicates the question is based on the *Harry Potter* universe. The description mentions the ‘previous owners’ of the item—Fred and George Weasley—who are also known as the prankster twins.

The description (and the hint provided) directs the solver to visit the Harry Potter Fandom Wiki page. On visiting the website, the solver searches “Fredandgeorge” in the search option and selects the “People” tab.

On scrolling down, an account with the name Fredandgeorge0478 is found.

About page of the account:   
The flag is divided into two parts. The first part can be found from the hints given on this page: the first-time password to the Headmaster’s Office (Dumbledore).

A given link leads to a text post containing a riddle and a hyperlink saying “Your Flag.” The riddle suggests using the Wayback Machine, and the hyperlink leads to a dead-end.

On visiting the post history, another hyperlink, “Remnants of Banner,” is found, leading to a page that has been deleted. Copy the link address from the hyperlink and input it into the Wayback Machine archive.

The second half of the flag can be found by noting the first letter of each line.

```  
Flag:   
VishwaCTF{LemonDrops_RAVENCLAW}  
```
