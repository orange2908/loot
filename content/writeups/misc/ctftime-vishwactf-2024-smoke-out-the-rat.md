---
title: "SMOKE OUT THE RAT - VishwaCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "base64", "smoke", "out", "rat", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Step 1 : Find the traitor using the phone number given."
source:
  name: "CTFtime writeup #39519"
  url: "https://ctftime.org/writeup/39519"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Digital%20Forensics/Smoke%20out%20the%20rat.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "SMOKE OUT THE RAT"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** SMOKE OUT THE RAT
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39519>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Digital%20Forensics/Smoke%20out%20the%20rat.pdf>

---
### Solution:

Step 1 : Find the traitor using the phone number given. You get the first name as ‘Matthew’.

Note : Analyse the database log carefully , look for things which describe the database like tables , columns and other to get an basic Idea about what the database is all about , it will benefit you getting the flag .

Step 2 : Now as you are asked about the timestamp , you need to convert the binary into readable format . The which helps you achieving this ‘mysqlbinlog’ utility .

Step 3 : Now open the decrypted text file , and get the remaining part of the flag . The description hints that , outsider added in the database created fake transactions and ultimately dropped the entire database . Find the ‘drop’ statement and search nearby …

Step 4 : Scrolling a bit you can see an update made in the employees table , note the timestamp , and converting the binlog using Base64 helps you get the name of the outsider added .  
```  
FLAG :- VishwaCTF{Matthew_Darwin_15:31:29}  
```
