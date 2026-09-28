---
title: "SAVE-THE-CITY - VishwaCTF 2024"
category: "misc"
subcategory: "shells"
type: "writeup"
tags: ["misc", "nmap", "reverse-shell", "save-the-city", "shells", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "1\\. Identifying the Vulnerability:"
source:
  name: "CTFtime writeup #39507"
  url: "https://ctftime.org/writeup/39507"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/Save%20the%20city.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "SAVE-THE-CITY"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** SAVE-THE-CITY
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39507>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/Save%20the%20city.pdf>

---
Solution:  
1\. Identifying the Vulnerability:

From the provided hint, we learn that the application is using LibSSH 0.8.1, which is vulnerable.  
A quick Google search reveals this vulnerability.  
2\. nmap Scan:

Running an nmap scan on the target IP address exposes the open ports and services.  
3\. Exploiting the Vulnerability:

Using the Exploit DB’s Python script for the LibSSH 0.8.1 vulnerability, we can gain a reverse shell.  
Download the Paramiko exploit from this link.  
4\. The command to execute the exploit is:  
`python3 [exploit.py](http://exploit.py) -T <ip_address> -P 22 -C '<linux_command>'`

5\. Locating the Bomb:

After accessing the system, the location of the bomb can be found in `/location.txt`.
