---
title: "wabash - b01lers CTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "bash", "wabash", "b01lers-ctf", "b01lers-ctf-2024", "2024", "ctf-writeup"]
summary: "We are thrown into a shell that adds the prefix 'wa' to each command line parameter."
source:
  name: "CTFtime writeup #39147"
  url: "https://ctftime.org/writeup/39147"
ctf:
  name: "b01lers CTF 2024"
  year: 2024
  challenge: "wabash"
---

## Metadata

- **CTF:** b01lers CTF 2024
- **Task:** wabash
- **Author team:** nohackspace
- **CTFtime tags:** bash
- **CTFtime:** <https://ctftime.org/writeup/39147>

---
We are thrown into a shell that adds the prefix 'wa' to each command line parameter.

```  
_ _   
__ __ __ __ _ | |__ __ _ ___ | |_   
\ V V // _` | | '_ \ / _` | (_-< | ' \   
\\_/\\_/ \\__,_| |_.__/ \\__,_| /__/_ |_||_|   
_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|   
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

$ `bash`;  
sh: 1: wabash: not found  
$ ls  
sh: 1: wals: not found  
```

we can use the command '(wa)it' to escape this condition  
```  
$ it&&ls   
run  
```  
We can use the "[internal/input field separator](<https://en.wikipedia.org/wiki/Input_Field_Separators>)" variable IFS to print our flag.txt content.  
```  
$ it&&cat${IFS}/flag.txt  
bctf{wabash:_command_not_found521065b339eb59a71c06a0dec824cd55}
