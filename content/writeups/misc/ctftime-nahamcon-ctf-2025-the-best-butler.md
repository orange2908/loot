---
title: "The Best Butler - NahamCon CTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "best", "butler", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "We get a jenkins dashboard in this challenge."
source:
  name: "CTFtime writeup #40278"
  url: "https://ctftime.org/writeup/40278"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/devops/TheBestButler"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "The Best Butler"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** The Best Butler
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40278>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/devops/TheBestButler>

---
> Solved by thewhiteh4t

We get a `jenkins` dashboard in this challenge. Jenkins is a very popular open source automation server used in DevOps infrastructure.

**Fingerprinting**

Jenkins version `2.332.2` is visible in the footer. We can easily find vulnerabilities for this version :

[Multiple vulnerabilities in Jenkins and Jenkins LTS](<https://www.cybersecurity-help.cz/vdb/SB2024012513>)

Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

Working exploit PoC : [CVE-2024-23897](<https://github.com/godylockz/CVE-2024-23897/blob/main/jenkins_fileread.py>)

We can simply run the python file and provide the challenge URL as argument to leak sensitive data from the endpoint : 

![](<https://i.imgur.com/72LjOp1.png>)

**Key Learning and Takeaways**

\- Fingerprinting : It's the first step in finding known weaknesses. Always look for version numbers on any service you encounter, more fingerprinting means easier pwning later.  
\- Proof-of-Concepts (PoCs) are Your Best Friend : Other people like you and me, some of us love making PoCs for exploits, and it helps a lot in work and as well as in CTFs. This also highlights how quickly an attacker can leverage publicly known vulnerabilities once they've identified the software version.  
\- TLDR : Keep all software up to date everywhere and specially in a DevOps environment!
