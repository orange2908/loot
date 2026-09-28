---
title: "TRY HACK ME - VishwaCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "try", "hack", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "The description says one of the member of the team member of CyberCell VIIT is"
source:
  name: "CTFtime writeup #39527"
  url: "https://ctftime.org/writeup/39527"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Open%20Source%20Intelligence%20(OSINT)/Try%20Hack%20Me.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "TRY HACK ME"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** TRY HACK ME
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39527>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Open%20Source%20Intelligence%20(OSINT)/Try%20Hack%20Me.pdf>

---
### Solution :   
The description says one of the member of the team member of CyberCell VIIT is   
very active on Try Hack Me and ranks in top 3% of the global leaderboard and we need to   
check for his Try Hack Me profile.  
* We can find all the members of the team on official website <https://vishwactf.com/> in the   
Our Heroes tab  
We can see 6 members in Core Committee, 39 members in tech team and 17 members in the   
non-tech team. Also each members social account is also been provided.  
* Analysing each member’s account we can find Ankush Kaudi’s linkedin mentions he is in top  
3% of the global rankings in Try Hack Me.  
So we have the team member, we just need to find his Try Hack Me profile. We can see if we   
search for any person’s profile, we can’t access the profile easily. But if we observe the search  
url for Try Hack Me, it works as follows :  
<https://tryhackme.com/p/>[username]  
* It has been mentioned in description that username and real name are the same. So   
searching for the same we can see the profile.  
<https://tryhackme.com/p/ankushkaudi>  
* Hence, we can find the flag  
` Flag : VishwaCTF{Pr0f1l3_1dent1fi3d_v0uch3r5_cr3d1t3d_5ucc355fully}`
