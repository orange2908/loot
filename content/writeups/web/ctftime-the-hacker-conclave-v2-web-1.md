---
title: "WEB 1 - The Hacker Conclave v2"
category: "web"
type: "writeup"
tags: ["web", "wordlists", "the-hacker-conclave", "the-hacker-conclave-v2", "ctf-writeup"]
summary: "As the task says going if we go direcotry to directory in the browers we aren't going to get the flag."
source:
  name: "CTFtime writeup #39692"
  url: "https://ctftime.org/writeup/39692"
ctf:
  name: "The Hacker Conclave v2"
  challenge: "WEB 1"
---

## Metadata

- **CTF:** The Hacker Conclave v2
- **Task:** WEB 1
- **Author team:** Sqli Enjoyer
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39692>

---
# Real author: cherpietro  
# Avoiding redirects 

As the task says going if we go direcotry to directory in the browers we aren't going to get the flag. Using the curl command will give you false flags, probably of the redirection. (Side note, Crepyy_killer78 here. Maybe using the -L of curl could do the trick but no sure.).

So lets use wget and get the file for each directory.

# Script  
```  
#! /bin/bash  
cat wordlist | while read dir; do  
wget http://130.206.158.146:42005/$dir  
done;  
```

And 1 of the files is the actuall flag.
